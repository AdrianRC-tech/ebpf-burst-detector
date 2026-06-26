package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeResolver implements nsResolver for unit testing without a real Cilium agent.
type fakeResolver struct {
	ns      string
	found   bool
	lastErr error
}

func (f *fakeResolver) namespaceFor(_ uint32) (string, bool) { return f.ns, f.found }
func (f *fakeResolver) refreshErr() error                    { return f.lastErr }

func TestDecideAttach(t *testing.T) {
	allowed := map[string]struct{}{"default": {}}

	tests := []struct {
		name            string
		alreadyAttached bool
		ns              string
		found           bool
		refreshErr      error
		wantAttach      bool
		wantContains    string
	}{
		{
			name:            "already attached",
			alreadyAttached: true,
			found:           true,
			ns:              "default",
			wantAttach:      false,
			wantContains:    "already attached",
		},
		{
			name:         "agent unavailable",
			found:        false,
			refreshErr:   errors.New("connection refused"),
			wantAttach:   false,
			wantContains: "cilium agent unavailable",
		},
		{
			name:         "endpoint not yet registered",
			found:        false,
			refreshErr:   nil,
			wantAttach:   false,
			wantContains: "namespace unknown, skipped",
		},
		{
			name:         "not in allow-list",
			found:        true,
			ns:           "kube-system",
			wantAttach:   false,
			wantContains: "not in allow-list",
		},
		{
			name:         "allowed namespace",
			found:        true,
			ns:           "default",
			wantAttach:   true,
			wantContains: `attached (namespace "default")`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attach, reason := decideAttach(tt.alreadyAttached, tt.ns, tt.found, tt.refreshErr, allowed)
			if attach != tt.wantAttach {
				t.Errorf("attach = %v, want %v (reason: %q)", attach, tt.wantAttach, reason)
			}
			if !strings.Contains(reason, tt.wantContains) {
				t.Errorf("reason = %q, want it to contain %q", reason, tt.wantContains)
			}
		})
	}
}

func TestParseEndpoints(t *testing.T) {
	// Fixture derived from real Cilium /v1/endpoint output.
	// Only interface-index and k8s-namespace are included (no PII).
	fixture := []byte(`[
		{"status":{"external-identifiers":{"k8s-namespace":"default"},"networking":{"interface-index":42}}},
		{"status":{"external-identifiers":{"k8s-namespace":"kube-system"},"networking":{"interface-index":55}}},
		{"status":{"external-identifiers":{"k8s-namespace":""},"networking":{"interface-index":99}}},
		{"status":{"external-identifiers":{"k8s-namespace":"default"},"networking":{"interface-index":0}}}
	]`)

	m, err := parseEndpoints(fixture)
	if err != nil {
		t.Fatalf("parseEndpoints: %v", err)
	}
	if ns := m[42]; ns != "default" {
		t.Errorf("m[42] = %q, want %q", ns, "default")
	}
	if ns := m[55]; ns != "kube-system" {
		t.Errorf("m[55] = %q, want %q", ns, "kube-system")
	}
	if _, ok := m[99]; ok {
		t.Error("m[99] should not exist (empty namespace filtered)")
	}
	if _, ok := m[0]; ok {
		t.Error("m[0] should not exist (zero ifindex filtered)")
	}
	if len(m) != 2 {
		t.Errorf("len(m) = %d, want 2", len(m))
	}

	// Malformed input must return an error, not panic.
	_, err = parseEndpoints([]byte("not json"))
	if err == nil {
		t.Error("parseEndpoints(malformed): expected error, got nil")
	}

	// Empty array is valid and returns an empty map.
	m, err = parseEndpoints([]byte("[]"))
	if err != nil {
		t.Fatalf("parseEndpoints(empty): %v", err)
	}
	if len(m) != 0 {
		t.Errorf("parseEndpoints(empty) len = %d, want 0", len(m))
	}
}

// TestEnrichNetkitDev tests the enrichNetkitDev helper with injected
// fetchPeer and findNetns functions so that no real netlink or /proc access
// is required.
func TestEnrichNetkitDev(t *testing.T) {
	basedev := netkitDev{Ifindex: 10, Name: "nk0"}

	// Helpers shared across test cases.
	goodFetch := func(_ uint32) (peerNetlinkInfo, error) {
		return peerNetlinkInfo{PeerIfindex: 42, NetnsID: 3}, nil
	}
	goodFindNetns := func(_ int32) (string, error) {
		return "/proc/1234/ns/net", nil
	}
	failFetch := func(_ uint32) (peerNetlinkInfo, error) {
		return peerNetlinkInfo{}, fmt.Errorf("netlink unavailable")
	}
	zeroIfindexFetch := func(_ uint32) (peerNetlinkInfo, error) {
		return peerNetlinkInfo{PeerIfindex: 0, NetnsID: 3}, nil
	}
	sameNetnsFetch := func(_ uint32) (peerNetlinkInfo, error) {
		// NetnsID == -1 means peer is in the same netns.
		return peerNetlinkInfo{PeerIfindex: 7, NetnsID: -1}, nil
	}
	failFindNetns := func(_ int32) (string, error) {
		return "", fmt.Errorf("nsid not found in /proc")
	}

	tests := []struct {
		name            string
		fetch           func(uint32) (peerNetlinkInfo, error)
		findNetns       func(int32) (string, error)
		wantErr         bool
		wantErrContains string
		wantPeerIfindex int
		wantNetnsPath   string
	}{
		{
			name:            "happy path: peer ifindex and netns path resolved",
			fetch:           goodFetch,
			findNetns:       goodFindNetns,
			wantErr:         false,
			wantPeerIfindex: 42,
			wantNetnsPath:   "/proc/1234/ns/net",
		},
		{
			name:            "fetch peer info fails",
			fetch:           failFetch,
			findNetns:       goodFindNetns,
			wantErr:         true,
			wantErrContains: "fetching peer netlink info",
		},
		{
			name:            "peer ifindex is zero (IFLA_LINK absent)",
			fetch:           zeroIfindexFetch,
			findNetns:       goodFindNetns,
			wantErr:         true,
			wantErrContains: "IFLA_LINK (peer ifindex) is zero",
		},
		{
			name:            "peer in same netns (IFLA_LINK_NETNSID absent)",
			fetch:           sameNetnsFetch,
			findNetns:       goodFindNetns,
			wantErr:         true,
			wantErrContains: "same netns",
		},
		{
			name:            "netns resolution fails",
			fetch:           goodFetch,
			findNetns:       failFindNetns,
			wantErr:         true,
			wantErrContains: "resolving pod netns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := enrichNetkitDev(basedev, tt.fetch, tt.findNetns)
			if (err != nil) != tt.wantErr {
				t.Fatalf("enrichNetkitDev() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("err = %q, want it to contain %q", err.Error(), tt.wantErrContains)
				}
				return
			}
			if got.PeerIfindex != tt.wantPeerIfindex {
				t.Errorf("PeerIfindex = %d, want %d", got.PeerIfindex, tt.wantPeerIfindex)
			}
			if got.PodNetnsPath != tt.wantNetnsPath {
				t.Errorf("PodNetnsPath = %q, want %q", got.PodNetnsPath, tt.wantNetnsPath)
			}
			// Base fields must be preserved.
			if got.Ifindex != basedev.Ifindex || got.Name != basedev.Name {
				t.Errorf("base fields mutated: got ifindex=%d name=%q, want %d %q",
					got.Ifindex, got.Name, basedev.Ifindex, basedev.Name)
			}
		})
	}
}
