package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cilium", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseServiceEntriesFromFixtures(t *testing.T) {
	entries, err := parseServiceEntries(readFixture(t, "ip.json"), readFixture(t, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &ciliumResolver{entries: entries}
	cases := map[string]string{
		"10.0.2.109": "kube-system/hubble-relay", // pod: identity labels win
		"10.0.1.139": "host",                     // reserved identity 1
		"10.0.0.7":   "world",                    // inside 10.0.0.0/24, reserved id 2
		"8.8.8.8":    "world",                    // only 0.0.0.0/0 matches
	}
	for ip, want := range cases {
		addr, _ := parseAddrForTest(ip)
		got, _ := r.lookupLocked(addr)
		if got != want {
			t.Errorf("%s -> %q, want %q", ip, got, want)
		}
	}
	// Pod whose identity is missing from the identity list falls back to
	// ipcache pod metadata.
	got, _ := r.lookupLocked(mustAddr(t, "10.0.2.28"))
	if got != "local-path-storage/local-path-provisioner-67b8995b4b-4g79z" {
		t.Errorf("metadata fallback = %q", got)
	}
}

func TestServiceLabelPriorityAndReserved(t *testing.T) {
	labels := []string{"k8s:io.kompose.service=search", "k8s:io.kubernetes.pod.namespace=default", "k8s:app=legacy"}
	if got := serviceLabel(5000, labels, "", ""); got != "default/legacy" {
		t.Errorf("got %q, want k8s:app ahead of kompose label", got)
	}
	for id, want := range map[uint32]string{1: "host", 2: "world", 6: "remote-node", 7: "kube-apiserver"} {
		if got := serviceLabel(id, nil, "", ""); got != want {
			t.Errorf("id %d -> %q, want %q", id, got, want)
		}
	}
	if got := serviceLabel(5000, nil, "", ""); got != "" {
		t.Errorf("no labels or metadata -> %q, want empty", got)
	}
}

func TestParseServiceEntriesAcceptsFlatIdentityShape(t *testing.T) {
	ip := []byte(`[{"cidr":"10.0.0.5/32","identity":42}]`)
	id := []byte(`[{"id":42,"labels":["k8s:io.kubernetes.pod.namespace=ns","k8s:app=web"]}]`)
	entries, err := parseServiceEntries(ip, id)
	if err != nil || len(entries) != 1 || entries[0].label != "ns/web" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

// ciliumTestServer serves canned Cilium JSON on a unix socket and returns a
// resolver pointed at it.
func ciliumTestServer(t *testing.T, ipBody, idBody []byte) (*ciliumResolver, *int) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "c.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ip", func(w http.ResponseWriter, _ *http.Request) { hits++; w.Write(ipBody) })
	mux.HandleFunc("/v1/identity", func(w http.ResponseWriter, _ *http.Request) { w.Write(idBody) })
	srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)
	return newCiliumResolver(sock, discardLogger()), &hits
}

func TestCiliumResolverEndToEndAndCaching(t *testing.T) {
	r, hits := ciliumTestServer(t, readFixture(t, "ip.json"), readFixture(t, "identity.json"))
	clock := time.Unix(1000, 0)
	r.now = func() time.Time { return clock }

	if got := r.resolve("10.0.2.109"); got != "kube-system/hubble-relay" {
		t.Fatalf("resolve = %q", got)
	}
	r.resolve("10.0.2.68")
	if *hits != 1 {
		t.Errorf("agent hits = %d, want 1 (cache reuse within TTL)", *hits)
	}
	clock = clock.Add(resolverTTL + time.Second)
	r.resolve("10.0.2.109")
	if *hits != 2 {
		t.Errorf("agent hits = %d, want 2 (refresh after TTL)", *hits)
	}
}

func TestCiliumResolverDownReturnsEmpty(t *testing.T) {
	r := newCiliumResolver(filepath.Join(t.TempDir(), "missing.sock"), discardLogger())
	if got := r.resolve("10.0.2.109"); got != "" {
		t.Errorf("resolve with agent down = %q, want empty", got)
	}
	if got := r.resolve("not-an-ip"); got != "" {
		t.Errorf("resolve(garbage) = %q, want empty", got)
	}
}

func parseAddrForTest(s string) (netip.Addr, error) { return netip.ParseAddr(s) }

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
