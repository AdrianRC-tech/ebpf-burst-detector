package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// serviceResolver maps an IP address to a human-readable service identity
// (e.g. "default/memcached-rate", "host", "world"). It returns "" when the
// address cannot be resolved; callers omit the field rather than fail.
type serviceResolver interface {
	resolve(ip string) string
}

const (
	// resolverTTL bounds how stale the cached IP→service table may get;
	// pods churn, so a cached label is only trusted briefly.
	resolverTTL = 10 * time.Second
	// resolverRetryGap rate-limits refresh attempts (miss-triggered and
	// after a failure) so a down agent or a burst of unknown IPs does not
	// turn every lookup into an HTTP round-trip.
	resolverRetryGap = 2 * time.Second
)

// appLabelKeys lists the Cilium-label keys that name a workload, in
// priority order.
var appLabelKeys = []string{
	"k8s:app.kubernetes.io/name=",
	"k8s:app=",
	"k8s:io.kompose.service=",
	"k8s:k8s-app=",
}

const podNamespaceLabel = "k8s:io.kubernetes.pod.namespace="

// reservedIdentityNames maps Cilium's fixed reserved numeric identities to
// a label. Anything with id < 256 not listed here is left unresolved.
var reservedIdentityNames = map[uint32]string{
	1:  "host",
	2:  "world",
	3:  "unmanaged",
	4:  "health",
	5:  "init",
	6:  "remote-node",
	7:  "kube-apiserver",
	8:  "ingress",
	9:  "world",
	10: "world",
}

type ipEntry struct {
	prefix netip.Prefix
	label  string
}

// ciliumResolver resolves IPs through the Cilium agent API: GET /v1/ip (the
// cluster-wide ipcache, so remote pods, hosts and CIDRs are covered, not
// just local endpoints) joined with GET /v1/identity (identity → labels).
type ciliumResolver struct {
	client *http.Client
	logger *slog.Logger
	now    func() time.Time

	mu          sync.Mutex
	entries     []ipEntry
	fetchedAt   time.Time
	lastAttempt time.Time
	warned      bool
}

func newCiliumResolver(socketPath string, logger *slog.Logger) *ciliumResolver {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &ciliumResolver{
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second},
		logger: logger,
		now:    time.Now,
	}
}

func (r *ciliumResolver) resolve(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	label, ok := r.lookupLocked(addr)
	stale := r.now().Sub(r.fetchedAt) > resolverTTL
	if (stale || !ok) && r.now().Sub(r.lastAttempt) > resolverRetryGap {
		r.refreshLocked()
		label, _ = r.lookupLocked(addr)
	}
	return label
}

// lookupLocked does a longest-prefix match over the cached ipcache.
func (r *ciliumResolver) lookupLocked(addr netip.Addr) (string, bool) {
	best, bestBits := "", -1
	for _, e := range r.entries {
		if e.prefix.Contains(addr) && e.prefix.Bits() > bestBits {
			best, bestBits = e.label, e.prefix.Bits()
		}
	}
	return best, bestBits >= 0
}

func (r *ciliumResolver) refreshLocked() {
	r.lastAttempt = r.now()
	ipBody, err := r.get("/v1/ip")
	var idBody []byte
	if err == nil {
		idBody, err = r.get("/v1/identity")
	}
	var entries []ipEntry
	if err == nil {
		entries, err = parseServiceEntries(ipBody, idBody)
	}
	if err != nil {
		// Keep serving the previous (possibly empty) table; say so once.
		if !r.warned {
			r.warned = true
			r.logger.Warn("cilium service resolution unavailable; attribution records omit src_service/dst_service", "err", err)
		}
		return
	}
	r.entries = entries
	r.fetchedAt = r.now()
	r.warned = false
}

func (r *ciliumResolver) get(path string) ([]byte, error) {
	resp, err := r.client.Get("http://localhost" + path)
	if err != nil {
		return nil, fmt.Errorf("querying cilium agent %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading cilium agent %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cilium agent %s: status %d", path, resp.StatusCode)
	}
	return body, nil
}

// parseServiceEntries joins a Cilium /v1/ip body with a /v1/identity body
// into prefix→label entries. The identity list may be either the flat API
// shape ([{id, labels}]) or the key/value-wrapped shape ([{key, value:{id,
// labels}}]); both are accepted.
func parseServiceEntries(ipBody, identityBody []byte) ([]ipEntry, error) {
	var idList []struct {
		ID    uint32   `json:"id"`
		Label []string `json:"labels"`
		Value *struct {
			ID     uint32   `json:"id"`
			Labels []string `json:"labels"`
		} `json:"value"`
	}
	if err := json.Unmarshal(identityBody, &idList); err != nil {
		return nil, fmt.Errorf("decoding cilium identity list: %w", err)
	}
	labelsByID := make(map[uint32][]string, len(idList))
	for _, it := range idList {
		if it.Value != nil {
			labelsByID[it.Value.ID] = it.Value.Labels
		} else {
			labelsByID[it.ID] = it.Label
		}
	}

	var ips []struct {
		CIDR     string `json:"cidr"`
		Identity uint32 `json:"identity"`
		Metadata *struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(ipBody, &ips); err != nil {
		return nil, fmt.Errorf("decoding cilium ip list: %w", err)
	}
	entries := make([]ipEntry, 0, len(ips))
	for _, e := range ips {
		prefix, err := netip.ParsePrefix(e.CIDR)
		if err != nil {
			addr, aerr := netip.ParseAddr(e.CIDR)
			if aerr != nil {
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		var ns, name string
		if e.Metadata != nil {
			ns, name = e.Metadata.Namespace, e.Metadata.Name
		}
		label := serviceLabel(e.Identity, labelsByID[e.Identity], ns, name)
		if label == "" {
			continue
		}
		entries = append(entries, ipEntry{prefix: prefix, label: label})
	}
	return entries, nil
}

// serviceLabel picks "<namespace>/<workload>" from an identity's labels,
// falling back to the ipcache's pod metadata (namespace/pod-name). Reserved
// identities map to their fixed names ("host", "world", ...).
func serviceLabel(id uint32, labels []string, metaNS, metaName string) string {
	if name, ok := reservedIdentityNames[id]; ok {
		return name
	}
	var ns, app string
	for _, l := range labels {
		if strings.HasPrefix(l, podNamespaceLabel) {
			ns = strings.TrimPrefix(l, podNamespaceLabel)
		}
	}
	for _, key := range appLabelKeys {
		for _, l := range labels {
			if strings.HasPrefix(l, key) {
				app = strings.TrimPrefix(l, key)
				break
			}
		}
		if app != "" {
			break
		}
	}
	if ns == "" {
		ns = metaNS
	}
	if app == "" {
		app = metaName
	}
	switch {
	case app == "":
		return ""
	case ns == "":
		return app
	}
	return ns + "/" + app
}
