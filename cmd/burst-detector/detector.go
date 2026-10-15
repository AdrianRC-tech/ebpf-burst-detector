package main

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// cusumParams holds the CUSUM tuning parameters baked into the BPF object's
// .rodata at load time. They cannot be changed after loadCusumDetector returns.
// A nil pointer means "use the C default baked into the .o file".
type cusumParams struct {
	Mu0           *uint64 // baseline bytes per window
	K             *uint64 // slack factor (half the expected step)
	HOnset        *uint64 // onset threshold (bytes)
	HDrain        *uint64 // static drain threshold override (bytes); nil/unset derives from HSlackMult * k_drain
	HSlackMult    *uint64 // drain threshold in slack units (h_drain = h_slack_mult * k_drain); nil derives from h_onset/k
	WindowNs      *uint64 // CUSUM window in nanoseconds
	SampleWindows *bool   // emit per-window byte samples to the window_samples ringbuf
}

// detector owns the live BPF objects for the CUSUM program. Caller must call
// Close when finished to release kernel resources.
type detector struct {
	objs cusumObjects

	// hSlackMult is the effective h_slack_mult value injected into .rodata —
	// either the caller's explicit override or the value deriveHSlackMult
	// computed. Recorded here so the caller can log the effective value
	// (armed-log parameter reconstruction depends on this being visible,
	// not just "kernel-default").
	hSlackMult uint64

	// windowNs is the effective CUSUM window in nanoseconds — either the
	// caller's explicit override or the C .rodata default read back from
	// spec.Variables. Used as the default flow-snapshot poll interval.
	windowNs uint64
}

// deriveHSlackMult resolves the drain-side threshold multiplier in slack
// units (h_drain = h_slack_mult * k_drain — see docs/design-decisions-
// cusum-calibration.md §5-6, "the key realisation: m is already the onset
// arm's operating point"). If the caller passed --h-slack-mult explicitly,
// that value wins unconditionally, matching the override semantics of
// every other parameter in this file. Otherwise m is derived from the
// onset arm's own operating point: m = effective_h_onset / effective_k,
// where "effective" means the flag value when passed, else the C .rodata
// default read back from spec.Variables.
func deriveHSlackMult(spec *ebpf.CollectionSpec, params cusumParams) (*uint64, error) {
	if params.HSlackMult != nil {
		return params.HSlackMult, nil
	}

	effectiveHOnset := uint64(0)
	effectiveK := uint64(0)

	if params.HOnset != nil {
		effectiveHOnset = *params.HOnset
	} else {
		vs, ok := spec.Variables["h_onset"]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in BPF object", "h_onset")
		}
		if err := vs.Get(&effectiveHOnset); err != nil {
			return nil, fmt.Errorf("reading variable %q: %w", "h_onset", err)
		}
	}

	if params.K != nil {
		effectiveK = *params.K
	} else {
		vs, ok := spec.Variables["k"]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in BPF object", "k")
		}
		if err := vs.Get(&effectiveK); err != nil {
			return nil, fmt.Errorf("reading variable %q: %w", "k", err)
		}
	}

	if effectiveK == 0 {
		return nil, fmt.Errorf("deriveHSlackMult: effective_k is zero; cannot compute h_slack_mult")
	}

	m := effectiveHOnset / effectiveK
	return &m, nil
}

// loadCusumDetector loads the CUSUM BPF object into the kernel.
//
// Map sharing: node_ingr_bytes and the flow maps are declared with
// LIBBPF_PIN_BY_NAME and pinned under bpfPinDir. The counter and flow objects
// are loaded first (initAttachment), so cilium/ebpf opens their pins and reuses
// the same kernel maps. The caller must have removed the memlock rlimit and
// created bpfPinDir.
//
// Parameter injection: cusumParams values are written to .rodata via the
// generated cusumVariableSpecs before LoadAndAssign, so the BPF program sees
// them as `volatile const` constants.
func loadCusumDetector(params cusumParams) (*detector, error) {
	spec, err := loadCusum()
	if err != nil {
		return nil, fmt.Errorf("loading bpf collection spec: %w", err)
	}

	// h_slack_mult unifies both CUSUM arms onto one shared threshold currency
	// (see docs/design-decisions-cusum-calibration.md §5-6): when the caller
	// does not pass --h-slack-mult explicitly, it defaults to the onset arm's
	// own operating point (h_onset / k), so a different --h-mult at
	// calibration time propagates to the drain side automatically.
	hSlackMult, err := deriveHSlackMult(spec, params)
	if err != nil {
		return nil, fmt.Errorf("deriving h_slack_mult: %w", err)
	}

	// Rewrite only the .rodata constants that were explicitly provided (or,
	// for h_slack_mult, derived above). Nil entries keep the C default baked
	// into the .o file.
	overrides := map[string]*uint64{
		"mu_0":         params.Mu0,
		"k":            params.K,
		"h_onset":      params.HOnset,
		"h_drain":      params.HDrain,
		"h_slack_mult": hSlackMult,
		"window_ns":    params.WindowNs,
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

	// effectiveWindowNs mirrors the hSlackMult pattern above: the flag value
	// when given, else the C .rodata default read back from spec.Variables.
	// Used by the caller as the default flow-snapshot poll interval
	// when --snapshot-interval is not passed.
	effectiveWindowNs := uint64(0)
	if params.WindowNs != nil {
		effectiveWindowNs = *params.WindowNs
	} else {
		vs, ok := spec.Variables["window_ns"]
		if !ok {
			return nil, fmt.Errorf("variable %q not found in BPF object", "window_ns")
		}
		if err := vs.Get(&effectiveWindowNs); err != nil {
			return nil, fmt.Errorf("reading variable %q: %w", "window_ns", err)
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
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinDir},
	}); err != nil {
		return nil, fmt.Errorf("loading and assigning bpf objects: %w", err)
	}

	return &detector{objs: objs, hSlackMult: *hSlackMult, windowNs: effectiveWindowNs}, nil
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

	state := cusumCusumStateT{PrevTotal: total} // UpperSum and LowerSum default to zero
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
