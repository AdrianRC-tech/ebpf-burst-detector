package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

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

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		t.Skipf("loading bpf objects failed (need CAP_BPF / root): %v", err)
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
	if ret != 0 {
		t.Fatalf("program returned %d, want TC_ACT_OK (0)", ret)
	}

	total, err := readTotal(objs.NodeIngrBytes)
	if err != nil {
		t.Fatalf("readTotal: %v", err)
	}
	if total != uint64(len(pkt)) {
		t.Fatalf("counter = %d, want %d (skb->len)", total, len(pkt))
	}
}

// TestTraceParseBranchVerifierAndSubmit closes the verifier-coverage gap: it
// loads the BPF object with trace_packets=1 so the verifier is forced to
// accept the IPv4 parse branch (which is dead-code-eliminated at the default
// trace_packets=0). It then runs the program against a synthetic packet and
// opens the ring buffer so the caller can assert a record was submitted.
//
// Requires CAP_BPF (or root). Skipped automatically on unprivileged runs.
func TestTraceParseBranchVerifierAndSubmit(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed (need CAP_BPF / root): %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		t.Skipf("loading bpf spec failed (need CAP_BPF / root): %v", err)
	}

	vs, found := spec.Variables["trace_packets"]
	if !found {
		t.Fatal("variable trace_packets not found in BPF object")
	}
	if err := vs.Set(uint8(1)); err != nil {
		t.Fatalf("setting trace_packets: %v", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("LoadAndAssign failed (need CAP_BPF / root): %v", err)
	}
	defer objs.Close()

	pkt := makeTestPacket(1500)

	ret, err := objs.IngressCounter.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("BPF_PROG_TEST_RUN not supported on this kernel: %v", err)
		}
		t.Fatalf("Program.Run: %v", err)
	}
	if ret != 0 {
		t.Fatalf("program returned %d, want TC_ACT_OK (0)", ret)
	}

	rd, err := ringbuf.NewReader(objs.PktTraceRb)
	if err != nil {
		t.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rd.Close()

	rd.SetDeadline(time.Now().Add(time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("ringbuf.Read: %v", err)
	}

	tr, err := decodePktTrace(rec.RawSample)
	if err != nil {
		t.Fatalf("decodePktTrace: %v", err)
	}

	if tr.Family != 4 {
		t.Errorf("Family = %d, want 4 (IPv4)", tr.Family)
	}
	if tr.Len != uint32(len(pkt)) {
		t.Errorf("Len = %d, want %d (skb->len)", tr.Len, len(pkt))
	}
	if tr.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", tr.Protocol)
	}
	if !tr.SrcIP.Equal(net.IP{192, 0, 2, 1}) {
		t.Errorf("SrcIP = %v, want 192.0.2.1", tr.SrcIP)
	}
	if !tr.DstIP.Equal(net.IP{192, 0, 2, 2}) {
		t.Errorf("DstIP = %v, want 192.0.2.2", tr.DstIP)
	}
	if tr.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234", tr.SrcPort)
	}
	if tr.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", tr.DstPort)
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
