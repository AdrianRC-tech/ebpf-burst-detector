package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// readTotal returns the cumulative byte total observed by the data-path
// program across all CPUs since program load.
//
// node_ingress_bytes is a single-entry BPF_MAP_TYPE_PERCPU_ARRAY: every CPU
// has its own copy of slot 0, and the kernel does NOT sum the slots on read.
// cilium/ebpf populates a []uint64 destination with one entry per possible
// CPU; userspace owns the aggregation.
func readTotal(m *ebpf.Map) (uint64, error) {
	var perCPU []uint64
	err := m.Lookup(uint32(0), &perCPU);
	if err != nil {
		return 0, fmt.Errorf("looking up node_ingress_bytes: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// activeCPUs returns the number of per-CPU slots that have observed any
// traffic. Diagnostic-only — a surprisingly-low count under load usually
// signals an IRQ-affinity or NIC-RSS quirk worth investigating.
func activeCPUs(perCPU []uint64) int {
	n := 0
	for _, v := range perCPU {
		if v > 0 {
			n++
		}
	}
	return n
}

// readTotalAndCPUs is a single-Lookup variant that returns both the sum and
// the count of active CPU slots. Useful in the tick loop, which wants both
// numbers from one map read rather than two.
func readTotalAndCPUs(m *ebpf.Map) (total uint64, active int, err error) {
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return 0, 0, fmt.Errorf("looking up node_ingress_bytes: %w", err)
	}
	for _, v := range perCPU {
		total += v
		if v > 0 {
			active++
		}
	}
	return total, active, nil
}
