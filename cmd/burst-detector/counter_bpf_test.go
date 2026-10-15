package main

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestClearPinningRemovesAllPinning is a regression test for a load-time bug
// that made every BPF_PROG_TEST_RUN test in this file skip unconditionally,
// even under CAP_BPF/root: every map in shared_maps.h is LIBBPF_PIN_BY_NAME,
// and cilium/ebpf rejects PinByName with no MapOptions.PinPath before
// attempting any syscall (map.go's newMap, "pin by name: missing
// MapOptions.PinPath") — the tests treated that as a privilege failure and
// skipped, never actually exercising the BPF program under a privileged run.
// clearPinning gives each test fresh, unpinned maps instead.
func TestClearPinningRemovesAllPinning(t *testing.T) {
	spec, err := loadCounter()
	if err != nil {
		t.Fatalf("loadCounter: %v", err)
	}

	pinned := 0
	for _, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			pinned++
		}
	}
	if pinned == 0 {
		t.Fatal("test setup invalid: spec has no pinned maps (expected at least node_ingr_bytes); clearPinning would have nothing to prove")
	}

	clearPinning(spec)

	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Errorf("map %q still has Pinning = %v after clearPinning", name, m.Pinning)
		}
	}
}

// clearPinning strips LIBBPF_PIN_BY_NAME from every map in spec so a test
// gets fresh, unpinned maps on every load — see TestClearPinningRemovesAllPinning.
func clearPinning(spec *ebpf.CollectionSpec) {
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
}

// skipUnlessPrivileged distinguishes "need CAP_BPF/root" (skip) from a real
// bug (fail loudly), so a privileged run's genuine failures are never
// silently swallowed as a permissions issue. The explicit PinPath-message
// check is a self-check on clearPinning itself: with pinning cleared, that
// specific error can never legitimately recur, privileged or not.
func skipUnlessPrivileged(t *testing.T, action string, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "missing MapOptions.PinPath") {
		t.Fatalf("%s: %v (clearPinning should have prevented this)", action, err)
	}
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("%s failed (need CAP_BPF / root): %v", action, err)
	}
	t.Fatalf("%s: %v", action, err)
}

// TestIngressCounterIncrementsBySkbLen exercises the data-path BPF program in
// isolation via BPF_PROG_TEST_RUN. No interface attach, no TCX, no Cilium —
// just verify that running the program against a synthetic skb leaves the
// per-CPU counter advanced by exactly the packet length.
//
// Requires CAP_BPF (or root). Skipped automatically on unprivileged runs.
func TestIngressCounterIncrementsBySkbLen(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed (need CAP_BPF / root): %v", err)
	}

	spec, err := loadCounter()
	if err != nil {
		t.Fatalf("loadCounter: %v", err)
	}
	clearPinning(spec)

	var objs counterObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		skipUnlessPrivileged(t, "loading bpf objects", err)
	}
	defer objs.Close()

	// Minimal valid frame: Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes,
	// padded to 1500 bytes to mimic an MTU-sized packet.
	pkt := makeTestPacket(1500)

	ret, err := objs.IngressCounter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF_PROG_TEST_RUN not supported on this kernel: %v", err)
		}
		t.Fatalf("Program.Run: %v", err)
	}
	if ret != uint32(0xFFFFFFFF) {
		t.Fatalf("program returned %d, want TCX_NEXT (0xFFFFFFFF)", ret)
	}

	total, err := readTotal(objs.NodeIngrBytes)
	if err != nil {
		t.Fatalf("readTotal: %v", err)
	}
	if total != uint64(len(pkt)) {
		t.Fatalf("counter = %d, want %d (skb->len)", total, len(pkt))
	}
}

const (
	tcpProto = 6
	udpProto = 17
)

// rawPort converts a host-order port number into the value flow_key's
// __be16 field holds when read back as a Go uint16: the BPF program copies
// the port's network-order bytes into the field without any conversion, so
// on this little-endian host reading those same bytes back as a native
// uint16 yields the byte-swapped value. rawPort(0) is 0, matching the
// "ports unavailable" case (non-first fragments, ICMP).
func rawPort(p uint16) uint16 {
	return bits.ReverseBytes16(p)
}

// rawIPv4 converts an IPv4 address into the value flow_key's __be32 field
// holds when read back as a Go uint32, by the same raw-bytes-reinterpreted
// reasoning as rawPort.
func rawIPv4(ip [4]byte) uint32 {
	return binary.LittleEndian.Uint32(ip[:])
}

// makeIPv4Packet builds an Ethernet+IPv4+(TCP|UDP)-shaped frame for
// flow_counter tests. Only byte positions flow_counter actually reads are
// populated: ethertype, IPv4 version/IHL/frag_off/protocol/addresses, and
// the two port bytes at the transport header's first 4 bytes (valid for
// both TCP and UDP). fragOffset is in 8-byte units as carried on the wire;
// nonzero marks a non-first fragment.
func makeIPv4Packet(proto uint8, srcIP, dstIP [4]byte, srcPort, dstPort uint16, fragOffset uint16, total int) []byte {
	const minLen = 14 + 20 + 4 // Ethernet + IPv4 + 4 bytes of ports
	if total < minLen {
		total = minLen
	}
	pkt := make([]byte, total)
	pkt[12], pkt[13] = 0x08, 0x00 // ethertype = IPv4
	pkt[14] = 0x45                // version=4, ihl=5 (20 bytes)
	pkt[16] = byte((total - 14) >> 8)
	pkt[17] = byte((total - 14) & 0xff)
	binary.BigEndian.PutUint16(pkt[20:22], fragOffset&0x1FFF)
	pkt[22] = 64 // TTL
	pkt[23] = proto
	copy(pkt[26:30], srcIP[:])
	copy(pkt[30:34], dstIP[:])
	binary.BigEndian.PutUint16(pkt[34:36], srcPort)
	binary.BigEndian.PutUint16(pkt[36:38], dstPort)
	return pkt
}

// makeIPv6EthertypePacket builds a frame whose Ethernet ethertype and first
// post-Ethernet byte look like the start of a real IPv6 packet (version=6
// in the top nibble). flow_counter never branches on ethertype — it reads
// the would-be IP header's version nibble directly, and IPv4/IPv6 share the
// same bit position for that field, so this alone must trip the
// version != 4 parse-anomaly branch.
func makeIPv6EthertypePacket(total int) []byte {
	const minLen = 14 + 20
	if total < minLen {
		total = minLen
	}
	pkt := make([]byte, total)
	pkt[12], pkt[13] = 0x86, 0xdd // ethertype = IPv6
	pkt[14] = 0x60                // version=6, traffic-class high nibble=0
	return pkt
}

// sumFlowStat reads a flow_stats entry, summing bytes/skbs across CPUs and
// taking the min non-zero first_seen_ns (a BPF_NOEXIST insert only sets the
// inserting CPU's slot — see ebpf/flow_stats.bpf.c and spec correction 4).
func sumFlowStat(m *ebpf.Map, key flowFlowKey) (bytesSum, skbsSum, firstSeen uint64, err error) {
	var perCPU []flowFlowStat
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0, 0, 0, err
	}
	for _, v := range perCPU {
		bytesSum += v.Bytes
		skbsSum += v.Skbs
		if v.FirstSeenNs != 0 && (firstSeen == 0 || v.FirstSeenNs < firstSeen) {
			firstSeen = v.FirstSeenNs
		}
	}
	return bytesSum, skbsSum, firstSeen, nil
}

// sumPerCPUCounter reads one PERCPU_ARRAY slot, summed across CPUs.
func sumPerCPUCounter(m *ebpf.Map, idx uint32) (uint64, error) {
	var perCPU []uint64
	if err := m.Lookup(idx, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// runFlowCounter runs flowObjs.FlowCounter against pkt and fails the test
// unless it returns TCX_NEXT.
func runFlowCounter(t *testing.T, objs *flowObjects, pkt []byte) {
	t.Helper()
	ret, err := objs.FlowCounter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF_PROG_TEST_RUN not supported on this kernel: %v", err)
		}
		t.Fatalf("Program.Run: %v", err)
	}
	if ret != uint32(0xFFFFFFFF) {
		t.Fatalf("flow_counter returned %d, want TCX_NEXT (0xFFFFFFFF)", ret)
	}
}

func loadFlowTestObjects(t *testing.T) *flowObjects {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed (need CAP_BPF / root): %v", err)
	}

	spec, err := loadFlow()
	if err != nil {
		t.Fatalf("loadFlow: %v", err)
	}
	clearPinning(spec)

	var objs flowObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		skipUnlessPrivileged(t, "loading flow bpf objects", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &objs
}

// TestFlowCounterFlows runs flow_counter over a sequence of packets and checks
// the per-key bytes/skbs it accumulates. Every case also checks that a key's
// first_seen_ns never moves once set.
func TestFlowCounterFlows(t *testing.T) {
	client := [4]byte{192, 0, 2, 1}
	server := [4]byte{192, 0, 2, 2}
	reqKey := flowFlowKey{
		SrcIp: rawIPv4(client), DstIp: rawIPv4(server),
		SrcPort: rawPort(1234), DstPort: rawPort(80), Proto: tcpProto,
	}
	respKey := flowFlowKey{
		SrcIp: rawIPv4(server), DstIp: rawIPv4(client),
		SrcPort: rawPort(80), DstPort: rawPort(1234), Proto: tcpProto,
	}
	req := makeIPv4Packet(tcpProto, client, server, 1234, 80, 0, 1500)
	resp := makeIPv4Packet(tcpProto, server, client, 80, 1234, 0, 1500)

	type want struct{ bytes, skbs uint64 }
	tests := []struct {
		name string
		pkts [][]byte
		want map[flowFlowKey]want
	}{
		{
			// Request and its reversed response land on distinct keys, with
			// ports in network byte order.
			name: "tcp request and response are distinct keys",
			pkts: [][]byte{req, resp},
			want: map[flowFlowKey]want{
				reqKey:  {uint64(len(req)), 1},
				respKey: {uint64(len(resp)), 1},
			},
		},
		{
			// UDP shares the port layout at the transport header's first 4 bytes.
			name: "udp ports intact",
			pkts: [][]byte{makeIPv4Packet(udpProto, client, server, 5353, 53, 0, 200)},
			want: map[flowFlowKey]want{
				{SrcIp: rawIPv4(client), DstIp: rawIPv4(server), SrcPort: rawPort(5353), DstPort: rawPort(53), Proto: udpProto}: {200, 1},
			},
		},
		{
			name: "repeated key accumulates",
			pkts: [][]byte{
				makeIPv4Packet(tcpProto, client, server, 1234, 80, 0, 100),
				makeIPv4Packet(tcpProto, client, server, 1234, 80, 0, 200),
			},
			want: map[flowFlowKey]want{reqKey: {300, 2}},
		},
		{
			// A non-first fragment has no transport header at the base offset,
			// so the key's ports must be 0 even though nonzero bytes sit there.
			name: "non-first fragment zeroes ports",
			pkts: [][]byte{makeIPv4Packet(tcpProto, client, server, 9999, 9999, 32, 100)},
			want: map[flowFlowKey]want{
				{SrcIp: rawIPv4(client), DstIp: rawIPv4(server), Proto: tcpProto}: {100, 1},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			objs := loadFlowTestObjects(t)
			firstSeen := map[flowFlowKey]uint64{}
			for _, pkt := range tc.pkts {
				runFlowCounter(t, objs, pkt)
				for key := range tc.want {
					_, _, fs, err := sumFlowStat(objs.FlowStats, key)
					if err != nil {
						continue // key not inserted yet
					}
					if prev := firstSeen[key]; prev != 0 && fs != prev {
						t.Errorf("first_seen_ns changed on repeat: %d -> %d", prev, fs)
					}
					firstSeen[key] = fs
				}
			}
			for key, w := range tc.want {
				bytesSum, skbsSum, fs, err := sumFlowStat(objs.FlowStats, key)
				if err != nil {
					t.Fatalf("sumFlowStat(%+v): %v", key, err)
				}
				if bytesSum != w.bytes || skbsSum != w.skbs {
					t.Errorf("key %+v: bytes/skbs = %d/%d, want %d/%d", key, bytesSum, skbsSum, w.bytes, w.skbs)
				}
				if fs == 0 {
					t.Errorf("key %+v: first_seen_ns = 0, want nonzero", key)
				}
			}
		})
	}
}

// TestFlowCounterIPv6IsParseAnomaly: flow_counter branches on the parsed
// IP version, not on skb->protocol, so a would-be IPv6 packet must trip
// parse_anomaly (flow_anomalies[0]) and never create a flow_stats entry.
func TestFlowCounterIPv6IsParseAnomaly(t *testing.T) {
	objs := loadFlowTestObjects(t)

	runFlowCounter(t, objs, makeIPv6EthertypePacket(60))

	total, err := sumPerCPUCounter(objs.FlowAnomalies, 0)
	if err != nil {
		t.Fatalf("sumPerCPUCounter(parse_anomaly): %v", err)
	}
	if total != 1 {
		t.Errorf("parse_anomaly = %d, want 1", total)
	}

	it := objs.FlowStats.Iterate()
	var k flowFlowKey
	var v []flowFlowStat
	if it.Next(&k, &v) {
		t.Errorf("flow_stats is not empty: found key %+v", k)
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterating flow_stats: %v", err)
	}
}

// makeTestPacket builds a syntactically-plausible Ethernet+IPv4+TCP frame of
// the requested total length. Content beyond the headers is zero-padded.
// The data-path program counts skb->len, which includes the Ethernet header;
// this matches empirical observation (a 56-byte ping payload produces skb->len=98:
// 14 Ethernet + 20 IP + 8 ICMP + 56 payload).
func makeTestPacket(total int) []byte {
	const minLen = 54
	if total < minLen {
		total = minLen
	}
	pkt := make([]byte, total)
	// Ethernet header: dst, src, ethertype=IPv4 (0x0800).
	pkt[12], pkt[13] = 0x08, 0x00
	// IPv4 header: version=4, IHL=5 (20 bytes), total_len.
	pkt[14] = 0x45
	pkt[16] = byte((total - 14) >> 8)
	pkt[17] = byte((total - 14) & 0xff)
	pkt[22] = 64   // TTL
	pkt[23] = 0x06 // protocol = TCP
	// IPv4 src/dst — arbitrary RFC-5737 documentation addresses.
	pkt[26], pkt[27], pkt[28], pkt[29] = 192, 0, 2, 1
	pkt[30], pkt[31], pkt[32], pkt[33] = 192, 0, 2, 2
	// TCP header: src port=1234, dst port=80, data offset=5 (20 bytes).
	pkt[34], pkt[35] = 0x04, 0xd2
	pkt[36], pkt[37] = 0x00, 0x50
	pkt[46] = 0x50 // data offset / reserved
	return pkt
}
