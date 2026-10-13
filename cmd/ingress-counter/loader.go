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
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const bpfPinDir = "/sys/fs/bpf/burst-detector"

type attachment struct {
	objs     bpfObjects
	flowObjs flowObjects
	links    map[uint32]podLinks // ifindex → netkit primary links (counter + flow)
}

// podLinks holds the two tcx-ingress links attached on one pod's netkit peer
// device: the byte counter (ingress_counter) and the flow attribution
// counter (flow_counter), chained in that order.
type podLinks struct {
	counter link.Link
	flow    link.Link
}

type netkitDev struct {
	Ifindex      uint32
	Name         string
	PeerIfindex  uint32 // peer (pod-side eth0) ifindex, relative to the pod netns; 0 if unknown
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

// procNetnsEntry is one candidate from the /proc walk: the path to setns into
// and the netns inode string (from readlink of /proc/<pid>/ns/net).
type procNetnsEntry struct {
	Path  string
	Inode string
}

// matchNetnsByNsid returns the path of the first entry whose netns nsid equals
// target, skipping the host netns inode and de-duplicating repeated inodes so
// queryNsid runs once per distinct netns.
// queryNsid is injected (live netlink in production, a fake in tests).
func matchNetnsByNsid(
	entries []procNetnsEntry,
	hostInode string,
	target int32,
	queryNsid func(path string) (int32, error),
) (string, error) {
	seen := make(map[string]struct{})
	for _, e := range entries {
		if e.Inode == hostInode {
			continue
		}
		if _, dup := seen[e.Inode]; dup {
			continue
		}
		seen[e.Inode] = struct{}{}

		nsid, err := queryNsid(e.Path)
		if err != nil {
			continue
		}
		if nsid == target {
			return e.Path, nil
		}
	}
	return "", fmt.Errorf("no process found for netns id %d", target)
}

// resolvePodNetnsPath maps a kernel netns ID (from IFLA_LINK_NETNSID) to a
// /proc/<pid>/ns/net path.
//
// The approach: walk /proc/[0-9]*/ns/net; for each candidate open the file and
// send RTM_GETNSID (with NETNSA_FD) to ask the kernel what nsid it has in the
// current (host) network namespace. Return the first path whose nsid matches
// netnsID. RTM_GETNSID is available since kernel 3.19.
//
// The host netns is excluded and identical inodes are queried only once, so
// the number of RTM_GETNSID calls equals the number of distinct pod namespaces
// on the node rather than the number of running processes.
func resolvePodNetnsPath(netnsID int32) (string, error) {
	hostInode, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return "", fmt.Errorf("reading host netns inode: %w", err)
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return "", fmt.Errorf("reading /proc: %w", err)
	}

	var candidates []procNetnsEntry
	for _, e := range procEntries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		nsPath := fmt.Sprintf("/proc/%s/ns/net", e.Name())
		inode, err := os.Readlink(nsPath)
		if err != nil {
			continue // process exited or permission denied
		}
		candidates = append(candidates, procNetnsEntry{Path: nsPath, Inode: inode})
	}

	// Open a NETLINK_ROUTE socket once and pass it into matchNetnsByNsid via closure.
	nlConn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", fmt.Errorf("dialing netlink for nsid resolution: %w", err)
	}
	defer nlConn.Close()

	return matchNetnsByNsid(candidates, hostInode, netnsID, func(path string) (int32, error) {
		return queryNetnsID(nlConn, path)
	})
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

	// NLM_F_ACK must NOT be set: with ACK the kernel sends RTM_NEWNSID then a
	// trailing NLMSG_ERROR(0). Execute() returns after the reply and leaves the
	// ack buffered, desyncing the socket's sequence counter for the next call.
	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_GETNSID,
			Flags: netlink.Request,
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
	dev.PeerIfindex = info.PeerIfindex

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
// When tracePackets is true, the trace_packets .rodata constant is set to 1 so
// the data-path program emits per-packet records to pkt_trace_rb.
func initAttachment(tracePackets bool) (*attachment, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}
	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating pin dir %s: %w", bpfPinDir, err)
	}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading bpf collection spec: %w", err)
	}
	if tracePackets {
		vs, found := spec.Variables["trace_packets"]
		if !found {
			return nil, fmt.Errorf("variable %q not found in BPF object", "trace_packets")
		}
		if err := vs.Set(uint8(1)); err != nil {
			return nil, fmt.Errorf("setting trace_packets: %w", err)
		}
	}
	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
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

	flowSpec, err := loadFlow()
	if err != nil {
		return nil, fmt.Errorf("loading flow bpf collection spec: %w", err)
	}
	var flowObjs flowObjects
	if err := flowSpec.LoadAndAssign(&flowObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	}); err != nil {
		return nil, fmt.Errorf("loading flow bpf objects: %w", err)
	}
	defer func() {
		if !ok {
			flowObjs.Close()
		}
	}()

	att := &attachment{
		objs:     objs,
		flowObjs: flowObjs,
		links:    make(map[uint32]podLinks),
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

// attachOne attaches the data-path program via tcx-ingress on the pod-side peer
// device (inside the pod netns) for the given netkitDev, if the device's
// Kubernetes namespace is in allowedNS.
// Skip-and-continue semantics: returns a reason string with nil error when the
// device is skipped; returns ("", err) only for genuine attach failures.
func (a *attachment) attachOne(dev netkitDev, resolver nsResolver, allowedNS map[string]struct{}) (string, error) {
	_, already := a.links[dev.Ifindex]
	var ns string
	var found bool
	if !already {
		ns, found = resolver.namespaceFor(dev.Ifindex) // retries internally on cache miss
	}

	attach, reason := decideAttach(already, ns, found, resolver.refreshErr(), allowedNS)
	if !attach {
		return reason, nil
	}

	// Cross into the pod netns to attach tcx-ingress on the peer device.
	// LockOSThread must be called before any netns operation; UnlockOSThread is
	// called only after the host netns is fully restored.
	runtime.LockOSThread()

	hostNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return "", fmt.Errorf("get host netns: %w", err)
	}
	defer hostNs.Close()

	podNs, err := netns.GetFromPath(dev.PodNetnsPath)
	if err != nil {
		runtime.UnlockOSThread()
		if errors.Is(err, syscall.ENOENT) {
			slog.Debug("pod netns gone before tcx attach, skipping", "dev", dev.Name)
			return "pod netns gone, skipped", nil
		}
		return "", fmt.Errorf("open pod netns %s: %w", dev.PodNetnsPath, err)
	}
	defer podNs.Close()

	if err := netns.Set(podNs); err != nil {
		runtime.UnlockOSThread()
		return "", fmt.Errorf("enter pod netns: %w", err)
	}

	counterLink, attachErr := link.AttachTCX(link.TCXOptions{
		Interface: int(dev.PeerIfindex),
		Program:   a.objs.IngressCounter,
		Attach:    ebpf.AttachTCXIngress,
	})

	var flowLink link.Link
	if attachErr == nil {
		flowLink, attachErr = link.AttachTCX(link.TCXOptions{
			Interface: int(dev.PeerIfindex),
			Program:   a.flowObjs.FlowCounter,
			Attach:    ebpf.AttachTCXIngress,
			Anchor:    link.AfterLink(counterLink),
		})
		if attachErr != nil {
			// Both programs attach or neither does: tear down the counter
			// link we just created before falling through to error handling.
			if closeErr := counterLink.Close(); closeErr != nil {
				slog.Error("failed to close counter link after flow attach failure", "dev", dev.Name, "err", closeErr)
			}
		}
	}

	if restoreErr := netns.Set(hostNs); restoreErr != nil {
		// netns restore failed — thread is in unknown state, terminate
		slog.Error("failed to restore host netns after tcx attach, terminating", "err", restoreErr)
		os.Exit(1)
	}
	runtime.UnlockOSThread()

	if attachErr != nil {
		// Treat ENOENT/ENODEV as benign race (pod torn down between discovery and attach).
		if errors.Is(attachErr, syscall.ENOENT) || errors.Is(attachErr, syscall.ENODEV) {
			slog.Debug("pod gone before tcx attach, skipping", "dev", dev.Name)
			return "pod gone before attach, skipped", nil
		}
		return "", fmt.Errorf("attach tcx-ingress on peer %d (pod %s): %w", dev.PeerIfindex, dev.Name, attachErr)
	}

	a.links[dev.Ifindex] = podLinks{counter: counterLink, flow: flowLink} // keyed by host-side primary ifindex, unchanged
	return reason, nil
}

// detachOne closes the userspace fd for the given ifindex's netkit link and
// removes it from the tracking map. The kernel auto-detaches the BPF program
// when the netkit device is destroyed; this function's job is solely to close
// the fd (prevent an fd leak) and prune a.links (prevent ifindex-reuse
// staleness). link.Close() returns nil even when the device is already gone,
// so errors here indicate genuine fd-close failures rather than expected teardown.
func (a *attachment) detachOne(ifindex uint32) error {
	pl, ok := a.links[ifindex]
	if !ok {
		return nil
	}
	var errs []error
	if err := pl.flow.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing flow link: %w", err))
	}
	if err := pl.counter.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing counter link: %w", err))
	}
	delete(a.links, ifindex)
	return errors.Join(errs...)
}

func (a *attachment) Close() error {
	var errs []error
	for ifindex, pl := range a.links {
		if err := pl.flow.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing flow link ifindex %d: %w", ifindex, err))
		}
		if err := pl.counter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing counter link ifindex %d: %w", ifindex, err))
		}
	}
	a.links = nil
	if err := a.flowObjs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing flow bpf objects: %w", err))
	}
	if err := a.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing bpf objects: %w", err))
	}
	return errors.Join(errs...)
}
