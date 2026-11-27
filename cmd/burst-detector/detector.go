package main

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// cusumParams holds the user-set CUSUM parameters baked into the BPF object's
// .rodata at load time. mu/sigma are learned online in kernel, so only the
// window is a real knob. A nil pointer means "use the C default".
type cusumParams struct {
	HSlackMult    *uint64 // drain threshold in slack units (h_drain = h_slack_mult * k_drain)
	WindowNs      *uint64 // CUSUM window in nanoseconds
	SampleWindows *bool   // emit per-window byte samples to the window_samples ringbuf
}

// detector owns the live BPF objects for the CUSUM program. Caller must call
// Close when finished to release kernel resources.
type detector struct {
	objs cusumObjects

	// windowNs is the effective CUSUM window in nanoseconds — either the
	// caller's explicit override or the C .rodata default read back from
	// spec.Variables. Used as the default flow-snapshot poll interval.
	windowNs uint64
	// tauNs and ewmaDiv are the derived baseline memory and its EWMA divisor.
	tauNs   uint64
	ewmaDiv uint64
}

// baselineTau returns the EWMA memory tau = max(10 s, 300 * W) and the
// divisor D = round(tau / W) the kernel uses as alpha = 1/D once past the
// Welford phase (docs/design-decisions-cusum-calibration.md §7). tau >= 300 W
// keeps 1/D <= 1/300, so the weight never increases at the n = 300 switch.
func baselineTau(windowNs uint64) (tauNs, ewmaDiv uint64) {
	tauNs = max(uint64(10*time.Second), 300*windowNs)
	return tauNs, (tauNs + windowNs/2) / windowNs
}

// loadCusumDetector loads the CUSUM BPF object into the kernel.
//
// Map sharing: node_ingr_bytes and the flow maps are declared with
// LIBBPF_PIN_BY_NAME and pinned under bpfPinDir. The counter and flow objects
// are loaded first (initAttachment), so cilium/ebpf opens their pins and reuses
// the same kernel maps. The caller must have removed the memlock rlimit and
// created bpfPinDir.
//
// Parameter injection: values are written to .rodata via spec.Variables
// before LoadAndAssign, so the BPF program sees them as `volatile const`.
func loadCusumDetector(params cusumParams) (*detector, error) {
	spec, err := loadCusum()
	if err != nil {
		return nil, fmt.Errorf("loading bpf collection spec: %w", err)
	}
	return loadCusumSpec(spec, params, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	})
}

// loadCusumSpec injects params (and the tau-derived ewma_div / t_max_ns)
// into spec and loads it. Split from loadCusumDetector so tests can load an
// unpinned copy with the same derivation.
func loadCusumSpec(spec *ebpf.CollectionSpec, params cusumParams, opts *ebpf.CollectionOptions) (*detector, error) {
	// The effective window drives tau, so resolve it first: the flag value
	// when given, else the C .rodata default.
	var windowNs uint64
	if params.WindowNs != nil {
		windowNs = *params.WindowNs
	} else if err := spec.Variables["window_ns"].Get(&windowNs); err != nil {
		return nil, fmt.Errorf("reading variable %q: %w", "window_ns", err)
	}
	if windowNs == 0 {
		return nil, fmt.Errorf("window must be > 0")
	}
	tauNs, ewmaDiv := baselineTau(windowNs)

	overrides := map[string]*uint64{
		"h_slack_mult": params.HSlackMult,
		"window_ns":    &windowNs,
		"ewma_div":     &ewmaDiv,
		"t_max_ns":     &tauNs,
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

	var objs cusumObjects
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, fmt.Errorf("loading and assigning bpf objects: %w", err)
	}

	return &detector{objs: objs, windowNs: windowNs, tauNs: tauNs, ewmaDiv: ewmaDiv}, nil
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

	state := cusumCusumStateT{PrevTotal: total} // everything else zero: n = 0 starts the setup phase
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
