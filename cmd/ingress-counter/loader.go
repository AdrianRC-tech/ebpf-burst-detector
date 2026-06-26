package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jsimonetti/rtnetlink/v2"
)

const bpfPinDir = "/sys/fs/bpf/burst-detector"

type attachment struct {
	objs    bpfObjects
	links   map[uint32]link.Link // ifindex → netkit primary link
	counter *ebpf.Map            // read-only alias into objs.NodeIngrBytes; never Close this field directly
}

type netkitDev struct {
	Ifindex uint32
	Name    string
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
// namespace via rtnetlink. Must be called from the host netns.
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
		devs = append(devs, netkitDev{Ifindex: uint32(m.Index), Name: name})
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
