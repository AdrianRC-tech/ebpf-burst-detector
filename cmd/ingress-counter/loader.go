package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const bpfPinDir = "/sys/fs/bpf/burst-detector"

type attachment struct {
	objs    bpfObjects
	links   map[uint32]link.Link // ifindex → netkit primary link
	counter *ebpf.Map            // read-only alias into objs.NodeIngrBytes; never Close this field directly
}

type netkitDev struct {
	Ifindex      uint32
	Name         string
	PeerIfindex  int    // peer (pod-side eth0) ifindex, relative to the pod netns; 0 if unknown
	PodNetnsPath string // path to pod's network namespace, e.g. /proc/<pid>/ns/net; empty if unknown
}

// peerNetlinkInfo holds the raw peer information extracted from a netlink
// RTM_GETLINK response for a netkit primary device.
type peerNetlinkInfo struct {
	// PeerIfindex is the peer (pod-side) ifindex from IFLA_LINK.
	// For a netkit primary whose peer lives in a different netns this value is
	// the ifindex as seen from inside the pod netns.
	PeerIfindex uint32
	// NetnsID is the IFLA_LINK_NETNSID value from the kernel response.
	// -1 means "peer is in the same netns as the primary" (no IFLA_LINK_NETNSID sent).
	NetnsID int32
}

// fetchPeerNetlinkInfo sends a raw RTM_GETLINK request for ifindex and extracts
// IFLA_LINK (peer ifindex) and IFLA_LINK_NETNSID from the response. It uses the
// mdlayher/netlink layer directly so that the IFLA_LINK_NETNSID attribute —
// which the jsimonetti/rtnetlink high-level decoder does not surface — can be
// read without patching the library.
//
// IFLA_LINK_NETNSID is only present when the peer lives in a different network
// namespace; if the attribute is absent, NetnsID is set to -1.
func fetchPeerNetlinkInfo(ifindex uint32) (peerNetlinkInfo, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return peerNetlinkInfo{}, fmt.Errorf("dialing netlink for peer info: %w", err)
	}
	defer conn.Close()

	// Build RTM_GETLINK request: IfInfomsg with the desired ifindex.
	const sizeofIfInfomsg = 16 // Family(1)+pad(1)+Type(2)+Index(4)+Flags(4)+Change(4)
	hdr := make([]byte, sizeofIfInfomsg)
	binary.NativeEndian.PutUint32(hdr[4:8], ifindex)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETLINK,
			Flags: netlink.Request | netlink.DumpFiltered,
		},
		Data: hdr,
	}

	msgs, err := conn.Execute(req)
	if err != nil {
		return peerNetlinkInfo{}, fmt.Errorf("RTM_GETLINK for ifindex %d: %w", ifindex, err)
	}

	info := peerNetlinkInfo{NetnsID: -1}
	for _, m := range msgs {
		if len(m.Data) < sizeofIfInfomsg {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[sizeofIfInfomsg:])
		if err != nil {
			return peerNetlinkInfo{}, fmt.Errorf("decoding netlink attrs for ifindex %d: %w", ifindex, err)
		}
		ad.ByteOrder = binary.NativeEndian
		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_LINK: // 0x5 — peer ifindex
				info.PeerIfindex = ad.Uint32()
			case unix.IFLA_LINK_NETNSID: // 0x25 — netns id where the peer lives
				info.NetnsID = ad.Int32()
			}
		}
		if err := ad.Err(); err != nil {
			return peerNetlinkInfo{}, fmt.Errorf("iterating netlink attrs for ifindex %d: %w", ifindex, err)
		}
	}
	return info, nil
}

// resolvePodNetnsPath maps a kernel netns ID (from IFLA_LINK_NETNSID) to a
// /proc/<pid>/ns/net path.
//
// The approach: walk /proc/[0-9]*/ns/net; for each candidate open the file and
// send RTM_GETNSID (with NETNSA_FD) to ask the kernel what nsid it has in the
// current (host) network namespace. Return the first path whose nsid matches
// netnsID. RTM_GETNSID is available since kernel 3.19.
func resolvePodNetnsPath(netnsID int32) (string, error) {
	// Open a NETLINK_ROUTE socket once and reuse it for all RTM_GETNSID queries.
	nlConn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", fmt.Errorf("dialing netlink for nsid resolution: %w", err)
	}
	defer nlConn.Close()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("reading /proc: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		nsPath := fmt.Sprintf("/proc/%s/ns/net", e.Name())
		gotID, err := queryNetnsID(nlConn, nsPath)
		if err != nil {
			// Not found or permission denied — skip silently.
			continue
		}
		if gotID == netnsID {
			return nsPath, nil
		}
	}
	return "", fmt.Errorf("no process found for netns id %d", netnsID)
}

// queryNetnsID opens the netns file at path and asks the kernel (via
// RTM_GETNSID / NETNSA_FD) for the nsid of that namespace as seen from the
// current (host) network namespace. Returns the nsid on success.
func queryNetnsID(nlConn *netlink.Conn, path string) (int32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	// Encode the RTM_GETNSID request body: a single nested attribute
	// NETNSA_FD containing the fd of the netns file.
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.NativeEndian
	ae.Uint32(unix.NETNSA_FD, uint32(f.Fd()))
	attrBytes, err := ae.Encode()
	if err != nil {
		return 0, fmt.Errorf("encoding NETNSA_FD: %w", err)
	}

	// RTM_GETNSID header: rtgenmsg (af_unspec = 1 byte + 3 bytes pad).
	body := append([]byte{unix.AF_UNSPEC, 0, 0, 0}, attrBytes...)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETNSID,
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: body,
	}

	msgs, err := nlConn.Execute(req)
	if err != nil {
		return 0, fmt.Errorf("RTM_GETNSID for %s: %w", path, err)
	}

	// Parse RTM_NEWNSID response: rtgenmsg (4 bytes) + netlink attributes.
	const sizeofRtgenmsg = 4
	for _, m := range msgs {
		if len(m.Data) < sizeofRtgenmsg {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[sizeofRtgenmsg:])
		if err != nil {
			return 0, fmt.Errorf("decoding RTM_NEWNSID attrs: %w", err)
		}
		ad.ByteOrder = binary.NativeEndian
		for ad.Next() {
			if ad.Type() == unix.NETNSA_NSID {
				return ad.Int32(), nil
			}
		}
		if err := ad.Err(); err != nil {
			return 0, fmt.Errorf("iterating RTM_NEWNSID attrs: %w", err)
		}
	}
	return 0, fmt.Errorf("NETNSA_NSID not found in RTM_GETNSID response for %s", path)
}

// enrichNetkitDev populates PeerIfindex and PodNetnsPath for a netkitDev.
// fetchPeer and findNetns are injected so the function can be unit-tested
// without live netlink or /proc access.
//
// If peer info cannot be resolved, enrichNetkitDev returns the original dev
// unchanged and a non-nil error; the caller decides whether to skip the device.
func enrichNetkitDev(
	dev netkitDev,
	fetchPeer func(ifindex uint32) (peerNetlinkInfo, error),
	findNetns func(netnsID int32) (string, error),
) (netkitDev, error) {
	info, err := fetchPeer(dev.Ifindex)
	if err != nil {
		return dev, fmt.Errorf("fetching peer netlink info for ifindex %d: %w", dev.Ifindex, err)
	}
	if info.PeerIfindex == 0 {
		return dev, fmt.Errorf("ifindex %d: IFLA_LINK (peer ifindex) is zero or absent", dev.Ifindex)
	}
	dev.PeerIfindex = int(info.PeerIfindex)

	if info.NetnsID < 0 {
		// Peer is in the same netns as the primary (unusual for a pod-attached
		// netkit, but handle gracefully). We cannot derive a pod netns path.
		return dev, fmt.Errorf("ifindex %d: peer is in the same netns (IFLA_LINK_NETNSID absent)", dev.Ifindex)
	}

	nsPath, err := findNetns(info.NetnsID)
	if err != nil {
		return dev, fmt.Errorf("resolving pod netns for ifindex %d (netnsid %d): %w", dev.Ifindex, info.NetnsID, err)
	}
	dev.PodNetnsPath = nsPath
	return dev, nil
}

// nsResolver is the interface used by attachOne to look up the Kubernetes
// namespace for a host-side netkit ifindex. *namespaceResolver satisfies it.
type nsResolver interface {
	namespaceFor(ifindex uint32) (string, bool)
	refreshErr() error
}

type namespaceResolver struct {
	socketPath string
	client     *http.Client
	mu         sync.Mutex
	cache      map[uint32]string // guarded by mu
	lastErr    error             // guarded by mu; set when the most recent refresh fails
}

func newNamespaceResolver(socketPath string) *namespaceResolver {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &namespaceResolver{
		socketPath: socketPath,
		client:     &http.Client{Transport: transport, Timeout: 5 * time.Second},
		cache:      make(map[uint32]string),
	}
}

// namespaceFor returns (namespace, true) for the host-side netkit ifindex.
// On cache miss it refreshes from the Cilium agent; if still not found it waits
// 200 ms and retries once — a new netkit device may appear in netlink slightly
// before Cilium registers its endpoint. refreshErr() reports whether the last
// refresh attempt failed (Cilium unavailable vs. endpoint not registered yet).
func (r *namespaceResolver) namespaceFor(ifindex uint32) (string, bool) {
	r.mu.Lock()
	ns, ok := r.cache[ifindex]
	r.mu.Unlock()
	if ok {
		return ns, true
	}
	if err := r.refresh(); err != nil {
		return "", false
	}
	r.mu.Lock()
	ns, ok = r.cache[ifindex]
	r.mu.Unlock()
	if ok {
		return ns, true
	}
	time.Sleep(200 * time.Millisecond)
	if err := r.refresh(); err != nil {
		return "", false
	}
	r.mu.Lock()
	ns, ok = r.cache[ifindex]
	r.mu.Unlock()
	return ns, ok
}

// refreshErr returns the error from the most recent refresh, or nil if the last
// refresh succeeded. Callers use this to distinguish "agent unavailable" from
// "endpoint not registered yet".
func (r *namespaceResolver) refreshErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// refresh fetches the current endpoint list from the Cilium agent and rebuilds
// the cache. A full rebuild on every miss is acceptable because refresh is
// called off the netlink receive hot path (Task 1 serializes all attach work
// through a single worker goroutine), so the O(N)-per-miss cost is bounded.
func (r *namespaceResolver) refresh() error {
	resp, err := r.client.Get("http://localhost/v1/endpoint")
	if err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("querying cilium agent: %w", err)
		err = r.lastErr
		r.mu.Unlock()
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.mu.Lock()
		r.lastErr = fmt.Errorf("reading cilium agent response: %w", err)
		err = r.lastErr
		r.mu.Unlock()
		return err
	}

	cache, parseErr := parseEndpoints(body)

	r.mu.Lock()
	defer r.mu.Unlock()
	if parseErr != nil {
		r.lastErr = parseErr
		return r.lastErr
	}
	r.cache = cache
	r.lastErr = nil
	return nil
}

// parseEndpoints decodes a Cilium /v1/endpoint JSON response body and returns
// an ifindex → namespace map. Only entries with non-zero ifindex and non-empty
// namespace are included.
func parseEndpoints(body []byte) (map[uint32]string, error) {
	var endpoints []struct {
		Status struct {
			ExternalIdentifiers struct {
				K8sNamespace string `json:"k8s-namespace"`
			} `json:"external-identifiers"`
			Networking struct {
				InterfaceIndex uint32 `json:"interface-index"`
			} `json:"networking"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &endpoints); err != nil {
		return nil, fmt.Errorf("decoding cilium endpoint list: %w", err)
	}
	cache := make(map[uint32]string, len(endpoints))
	for _, ep := range endpoints {
		idx := ep.Status.Networking.InterfaceIndex
		ns := ep.Status.ExternalIdentifiers.K8sNamespace
		if idx != 0 && ns != "" {
			cache[idx] = ns
		}
	}
	return cache, nil
}

// discoverNetkitDevices lists all netkit devices visible in the current network
// namespace via rtnetlink, and enriches each entry with the peer ifindex and
// pod netns path. Must be called from the host netns.
//
// Devices whose peer info cannot be resolved are logged at warn level and
// omitted from the returned slice so that a single un-resolvable device does
// not block attachment to the remaining devices.
func discoverNetkitDevices() ([]netkitDev, error) {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dialing rtnetlink: %w", err)
	}
	defer conn.Close()

	msgs, err := conn.Link.ListByKind("netkit")
	if err != nil {
		return nil, fmt.Errorf("listing netkit links: %w", err)
	}

	devs := make([]netkitDev, 0, len(msgs))
	for _, m := range msgs {
		var name string
		if m.Attributes != nil {
			name = m.Attributes.Name
		}
		base := netkitDev{Ifindex: uint32(m.Index), Name: name}
		enriched, err := enrichNetkitDev(base, fetchPeerNetlinkInfo, resolvePodNetnsPath)
		if err != nil {
			slog.Warn("skipping netkit device: peer/netns resolution failed",
				"ifindex", base.Ifindex, "name", base.Name, "err", err)
			continue
		}
		devs = append(devs, enriched)
	}
	return devs, nil
}

// initAttachment loads the BPF objects with map pinning and returns an
// attachment ready for per-device attachOne calls. No devices are attached yet.
func initAttachment() (*attachment, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating pin dir %s: %w", bpfPinDir, err)
	}
	var objs bpfObjects
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	}); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}
	// Guard any future error path added below this point.
	ok := false
	defer func() {
		if !ok {
			objs.Close()
		}
	}()
	att := &attachment{
		objs:    objs,
		links:   make(map[uint32]link.Link),
		counter: objs.NodeIngrBytes,
	}
	ok = true
	return att, nil
}

// decideAttach is a pure function that determines whether to attach to a device,
// given pre-gathered state. It encodes all pre-attach policy branches so they can
// be unit-tested without a real kernel. Returns (true, reason) when the caller
// should proceed with link.AttachNetkit; (false, reason) to skip.
func decideAttach(alreadyAttached bool, ns string, found bool, refreshErr error, allowedNS map[string]struct{}) (attach bool, reason string) {
	if alreadyAttached {
		return false, "already attached"
	}
	if !found || ns == "" {
		if refreshErr != nil {
			return false, fmt.Sprintf("cilium agent unavailable (%v), skipped", refreshErr)
		}
		return false, "namespace unknown, skipped"
	}
	if _, allowed := allowedNS[ns]; !allowed {
		return false, fmt.Sprintf("namespace %q not in allow-list, skipped", ns)
	}
	return true, fmt.Sprintf("attached (namespace %q)", ns)
}

// attachOne attaches the data-path program to the netkit primary of the given
// host-side ifindex if the device's namespace is in allowedNS.
// Skip-and-continue semantics: returns a reason string with nil error when the
// device is skipped; returns ("", err) only for genuine attach failures.
func (a *attachment) attachOne(ifindex uint32, resolver nsResolver, allowedNS map[string]struct{}) (string, error) {
	_, already := a.links[ifindex]
	var ns string
	var found bool
	if !already {
		ns, found = resolver.namespaceFor(ifindex) // retries internally on cache miss
	}

	attach, reason := decideAttach(already, ns, found, resolver.refreshErr(), allowedNS)
	if !attach {
		return reason, nil
	}
	l, err := link.AttachNetkit(link.NetkitOptions{
		Interface: int(ifindex),
		Program:   a.objs.IngressCounter,
		Attach:    ebpf.AttachNetkitPrimary,
	})
	if err != nil {
		return "", fmt.Errorf("attaching netkit primary on ifindex %d: %w", ifindex, err)
	}
	a.links[ifindex] = l
	return reason, nil
}

// detachOne closes the userspace fd for the given ifindex's netkit link and
// removes it from the tracking map. The kernel auto-detaches the BPF program
// when the netkit device is destroyed; this function's job is solely to close
// the fd (prevent an fd leak) and prune a.links (prevent ifindex-reuse
// staleness). link.Close() returns nil even when the device is already gone,
// so errors here indicate genuine fd-close failures rather than expected teardown.
func (a *attachment) detachOne(ifindex uint32) error {
	l, ok := a.links[ifindex]
	if !ok {
		return nil
	}
	err := l.Close()
	delete(a.links, ifindex)
	return err
}

func (a *attachment) Close() error {
	var errs []error
	for ifindex, l := range a.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing netkit link ifindex %d: %w", ifindex, err))
		}
	}
	a.links = nil
	if err := a.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing bpf objects: %w", err))
	}
	return errors.Join(errs...)
}
