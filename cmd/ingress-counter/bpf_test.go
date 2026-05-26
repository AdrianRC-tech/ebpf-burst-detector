package main

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
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

	total, err := readTotal(objs.NodeIngressBytes)
	if err != nil {
		t.Fatalf("readTotal: %v", err)
	}
	if total != uint64(len(pkt)) {
		t.Fatalf("counter = %d, want %d (skb->len)", total, len(pkt))
	}
}

// makeTestPacket builds a syntactically-plausible Ethernet+IPv4+TCP frame of
// the requested total length. Content beyond the headers is zero-padded;
// the data-path program only inspects skb->len, so payload contents don't
// matter.
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
