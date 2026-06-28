package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfPinDir is the BPF filesystem directory that holds maps shared with cusum-detector
// binary and the ingress-counter binary. Both binaries must agree on this path; the shared
// node_ingr_bytes map (declared with LIBBPF_PIN_BY_NAME in
// ebpf/headers/shared_maps.h) is pinned at bpfPinDir/node_ingr_bytes.
const bpfPinDir = "/sys/fs/bpf/burst-detector"

// cusumParams holds the CUSUM tuning parameters baked into the BPF object's
// .rodata at load time. They cannot be changed after loadCusumDetector returns.
// A nil pointer means "use the C default baked into the .o file".
type cusumParams struct {
	Mu0           *uint64 // baseline bytes per window
	K             *uint64 // slack factor (half the expected step)
	HOnset        *uint64 // onset threshold (bytes)
	HDrain        *uint64 // drain threshold (bytes)
	WindowNs      *uint64 // CUSUM window in nanoseconds
	SampleWindows *bool   // emit per-window byte samples to the window_samples ringbuf
}

// detector owns the live BPF objects for the CUSUM program. Caller must call
// Close when finished to release kernel resources.
type detector struct {
	objs bpfObjects
}

// loadCusumDetector loads the CUSUM BPF object into the kernel.
//
// Map sharing: node_ingr_bytes is declared with LIBBPF_PIN_BY_NAME and
// pinned at bpfPinDir/node_ingr_bytes. cilium/ebpf opens the existing pin
// (created by ingress-counter on first load) and reuses the same kernel map.
// If the pin does not yet exist (e.g. cusum-detector starts before
// ingress-counter), cilium/ebpf creates the map and pins it; ingress-counter
// then picks it up on its own load.
//
// Parameter injection: cusumParams values are written to .rodata via the
// generated bpfVariableSpecs before LoadAndAssign, so the BPF program sees
// them as `volatile const` constants.
func loadCusumDetector(params cusumParams) (*detector, error) {
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

	// Rewrite only the .rodata constants that were explicitly provided.
	// Nil entries keep the C default baked into the .o file.
	overrides := map[string]*uint64{
		"mu_0":      params.Mu0,
		"k":         params.K,
		"h_onset":   params.HOnset,
		"h_drain":   params.HDrain,
		"window_ns": params.WindowNs,
	}
	for name, val := range overrides {
		if val == nil {
			continue
		}
		vs, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in BPF object", name)
		}
		if err := vs.Set(*val); err != nil {
			return nil, fmt.Errorf("setting variable %q: %w", name, err)
		}
	}

	// SampleWindows is a bool flag (__u8 in BPF), not a uint64 tunable, so it is
	// handled separately from the overrides map above.
	if params.SampleWindows != nil && *params.SampleWindows {
		vs, ok := spec.Variables["sample_windows"]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in BPF object", "sample_windows")
		}
		if err := vs.Set(uint8(1)); err != nil {
			return nil, fmt.Errorf("setting variable %q: %w", "sample_windows", err)
		}
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	}); err != nil {
		return nil, fmt.Errorf("loading and assigning bpf objects: %w", err)
	}

	return &detector{objs: objs}, nil
}

// seedPrevTotal initialises cusum_state.PrevTotal to the current sum of
// node_ingr_bytes across all CPUs. This prevents a spurious onset on the
// first tick: node_ingr_bytes is pinned and carries accumulated state
// across restarts, while cusum_state is zero-initialised on every load. Without
// seeding, delta = current_total - 0 = huge -> guaranteed false onset.
func (d *detector) seedPrevTotal() error {
	var perCPU []uint64
	if err := d.objs.NodeIngrBytes.Lookup(uint32(0), &perCPU); err != nil {
		return fmt.Errorf("reading node_ingr_bytes for seeding: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}

	state := bpfCusumStateT{PrevTotal: total} // UpperSum and LowerSum default to zero
	if err := d.objs.CusumState.Put(uint32(0), state); err != nil {
		return fmt.Errorf("seeding cusum_state.prev_total: %w", err)
	}
	return nil
}

// armTimer invokes the SEC("syscall") arm_timer BPF program once to
// initialise and start the self-rearming bpf_timer. Must be called after
// loadCusumDetector and seedPrevTotal.
func (d *detector) armTimer() error {
	// SEC("syscall") programs use ctx_in (not data_in) in BPF_PROG_TEST_RUN.
	// Program.Test() sets data_in, which the kernel rejects with EINVAL for
	// BPF_PROG_TYPE_SYSCALL. Program.Run with Context sets ctx_in correctly.
	// 256 bytes covers pt_regs on x86-64 (168 bytes); arm_timer never reads ctx.
	ret, err := d.objs.ArmTimer.Run(&ebpf.RunOptions{
		Context: make([]byte, 256),
	})
	if err != nil {
		return fmt.Errorf("running arm_timer: %w", err)
	}
	if ret != 0 {
		return fmt.Errorf("arm_timer returned %d (expected 0)", ret)
	}
	return nil
}

// Close releases all kernel BPF resources owned by this detector.
func (d *detector) Close() error {
	return d.objs.Close()
}
