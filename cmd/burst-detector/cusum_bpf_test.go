package main

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestBaselineTau(t *testing.T) {
	for _, tc := range []struct {
		w       time.Duration
		tau     time.Duration
		ewmaDiv uint64
	}{
		{5 * time.Millisecond, 10 * time.Second, 2000},
		{7 * time.Millisecond, 10 * time.Second, 1429}, // 1428.57 rounds up
		{10 * time.Millisecond, 10 * time.Second, 1000},
		{25 * time.Millisecond, 10 * time.Second, 400},
		{50 * time.Millisecond, 15 * time.Second, 300},
		{100 * time.Millisecond, 30 * time.Second, 300},
	} {
		tau, d := baselineTau(uint64(tc.w))
		if tau != uint64(tc.tau) || d != tc.ewmaDiv {
			t.Errorf("W=%v: tau=%v ewma_div=%d, want %v %d", tc.w, time.Duration(tau), d, tc.tau, tc.ewmaDiv)
		}
	}
}

// cusumHarness drives cusum_test_step (the FSM body shared with the timer
// callback) on a fresh unpinned copy of the CUSUM object.
type cusumHarness struct {
	t   *testing.T
	det *detector
	rd  *ringbuf.Reader
	now uint64
}

func newCusumHarness(t *testing.T, window time.Duration) *cusumHarness {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock failed (need CAP_BPF / root): %v", err)
	}
	spec, err := loadCusum()
	if err != nil {
		t.Fatalf("loadCusum: %v", err)
	}
	clearPinning(spec)
	w := uint64(window)
	det, err := loadCusumSpec(spec, cusumParams{WindowNs: &w}, nil)
	if err != nil {
		skipUnlessPrivileged(t, "loading cusum spec", err)
	}
	t.Cleanup(func() { det.Close() })
	rd, err := ringbuf.NewReader(det.objs.BurstEvents)
	if err != nil {
		t.Fatalf("ringbuf reader: %v", err)
	}
	t.Cleanup(func() { rd.Close() })
	return &cusumHarness{t: t, det: det, rd: rd, now: uint64(time.Hour)}
}

// step runs one window of delta bytes, advancing now by the window, and
// returns any events it emitted.
func (h *cusumHarness) step(delta uint64) []BurstEvent {
	h.t.Helper()
	h.now += h.det.windowNs
	ctx := make([]byte, 16)
	binary.LittleEndian.PutUint64(ctx[0:], delta)
	binary.LittleEndian.PutUint64(ctx[8:], h.now)
	ret, err := h.det.objs.CusumTestStep.Run(&ebpf.RunOptions{Context: ctx})
	if err != nil || ret != 0 {
		h.t.Fatalf("cusum_test_step: ret=%d err=%v", ret, err)
	}
	var evs []BurstEvent
	for {
		h.rd.SetDeadline(time.Now())
		rec, err := h.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return evs
		}
		if err != nil {
			h.t.Fatalf("reading event: %v", err)
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			h.t.Fatal(err)
		}
		evs = append(evs, ev)
	}
}

func (h *cusumHarness) state() cusumCusumStateT {
	h.t.Helper()
	var st cusumCusumStateT
	if err := h.det.objs.CusumState.Lookup(uint32(0), &st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *cusumHarness) flag() uint32 {
	h.t.Helper()
	var f uint32
	if err := h.det.objs.BurstFlag.Lookup(uint32(0), &f); err != nil {
		h.t.Fatal(err)
	}
	return f
}

// mustQuiet steps and fails on any event.
func (h *cusumHarness) mustQuiet(delta uint64) {
	h.t.Helper()
	if evs := h.step(delta); len(evs) != 0 {
		h.t.Fatalf("delta=%d: unexpected events %+v (state %+v)", delta, evs, h.state())
	}
}

// noisy is a deterministic baseline of 100 kB ± 1 kB: sigma ~577 B, under
// the 1500 B floor, so k = 1500, h_onset = 9000, gate = mu + 4500.
func noisy(i int) uint64 { return 99_000 + uint64(i*7919%2001) }

// warm runs the 30-window setup phase on the noisy baseline.
func (h *cusumHarness) warm() {
	for i := range 30 {
		h.mustQuiet(noisy(i))
	}
}

// refWelford is the float reference: population Welford (alpha = 1/n) up to
// n = 300, then alpha = 1/ewmaDiv.
type refWelford struct{ n, mu, v float64 }

func (r *refWelford) add(x float64, ewmaDiv uint64) {
	r.n++
	d := r.n
	if r.n > 300 {
		d = float64(ewmaDiv)
	}
	a := 1 / d
	dx := x - r.mu
	r.mu += a * dx
	r.v = (1 - a) * (r.v + a*dx*dx)
}

func TestCusumSetupSuppressesOnset(t *testing.T) {
	h := newCusumHarness(t, 100*time.Millisecond)
	for i := range 30 {
		x := uint64(100_000)
		if i == 15 {
			x = 10_000_000 // huge, but detection is not armed yet
		}
		h.mustQuiet(x)
	}
	if st := h.state(); st.N != 30 || h.flag() != 0 {
		t.Fatalf("after setup: n=%d flag=%d, want 30 0", st.N, h.flag())
	}
	evs := h.step(1_000_000_000)
	if len(evs) != 1 || evs[0].Type != EventOnset {
		t.Fatalf("window 31: events %+v, want one onset", evs)
	}
}

func TestCusumWelfordThenEWMA(t *testing.T) {
	for _, w := range []time.Duration{10 * time.Millisecond, 100 * time.Millisecond} {
		t.Run(w.String(), func(t *testing.T) {
			h := newCusumHarness(t, w)
			var ref refWelford
			for i := range 300 {
				x := noisy(i)
				h.mustQuiet(x)
				ref.add(float64(x), h.det.ewmaDiv)
				st := h.state()
				// Integer truncation always rounds toward the previous mu; the
				// drift stays well under 0.1% at these magnitudes.
				if math.Abs(float64(st.Mu)-ref.mu) > 50 || math.Abs(float64(st.Var)-ref.v) > 0.01*ref.v+50 {
					t.Fatalf("n=%d: mu=%d var=%d, ref mu=%.1f var=%.1f", st.N, st.Mu, st.Var, ref.mu, ref.v)
				}
			}
			// Window 301 must use alpha = 1/ewma_div, not 1/301.
			before := h.state()
			x := before.Mu + 4000 // inside the 4500 B gate, below onset
			h.mustQuiet(x)
			after := h.state()
			if want := before.Mu + 4000/h.det.ewmaDiv; after.N != 301 || after.Mu != want {
				t.Fatalf("n=%d mu=%d, want n=301 mu=%d (ewma_div=%d)", after.N, after.Mu, want, h.det.ewmaDiv)
			}
		})
	}
}

func TestCusumGateIsOneSided(t *testing.T) {
	h := newCusumHarness(t, 100*time.Millisecond)
	h.warm()

	before := h.state()
	h.mustQuiet(before.Mu + 5000) // > mu + 3 sigma: rejected, but < h_onset
	if after := h.state(); after.N != before.N || after.Mu != before.Mu || after.Var != before.Var {
		t.Fatalf("upward outlier was learned: %+v -> %+v", before, after)
	}

	before = h.state()
	h.mustQuiet(0) // far below mu: always learned
	if after := h.state(); after.N != before.N+1 || after.Mu >= before.Mu {
		t.Fatalf("downward outlier not learned: %+v -> %+v", before, after)
	}

	// A sustained downward step is tracked without any onset or timeout.
	for range 200 {
		h.mustQuiet(50_000)
	}
	if st := h.state(); st.Mu > 75_000 || h.flag() != 0 {
		t.Fatalf("downward step not tracked: mu=%d flag=%d", st.Mu, h.flag())
	}
}

func TestCusumOnsetFreezesLearningUntilDrain(t *testing.T) {
	h := newCusumHarness(t, 100*time.Millisecond)
	h.warm()
	base := h.state()

	evs := h.step(130_000) // ~ +20 sigma
	if len(evs) != 1 || evs[0].Type != EventOnset {
		t.Fatalf("onset: events %+v", evs)
	}
	if evs[0].Mu != base.Mu || evs[0].Sigma != 1500 {
		t.Fatalf("onset event mu/sigma = %d/%d, want %d/1500", evs[0].Mu, evs[0].Sigma, base.Mu)
	}
	frozen := func() {
		t.Helper()
		if st := h.state(); st.N != base.N || st.Mu != base.Mu || st.Var != base.Var {
			t.Fatalf("baseline moved during burst: %+v -> %+v", base, st)
		}
	}
	frozen()
	for range 5 {
		h.mustQuiet(130_000)
		frozen()
	}
	// k_drain = 15000, h_drain = 90000: back at ~100 kB the lower arm gains
	// ~15000 per window, so drain fires within ~6 windows.
	for i := range 10 {
		evs = h.step(100_000)
		if len(evs) > 0 {
			break
		}
		frozen()
		if i == 9 {
			t.Fatal("no drain after returning to baseline")
		}
	}
	if len(evs) != 1 || evs[0].Type != EventDrain || evs[0].Reason != ReasonThreshold {
		t.Fatalf("drain: events %+v", evs)
	}
	frozen() // the drain window is not learned either
	if h.flag() != 0 {
		t.Fatal("flag not cleared at drain")
	}
}

func TestCusumTimeoutRerunsSetup(t *testing.T) {
	h := newCusumHarness(t, 100*time.Millisecond)
	h.warm()
	if evs := h.step(130_000); len(evs) != 1 {
		t.Fatalf("onset: %+v", evs)
	}
	h.mustQuiet(130_000)
	h.now += h.det.tauNs // jump past t_max_ns = tau
	evs := h.step(130_000)
	if len(evs) != 1 || evs[0].Type != EventDrain || evs[0].Reason != ReasonTimeout || evs[0].ChangePointNs != h.now {
		t.Fatalf("timeout drain: events %+v (now %d)", evs, h.now)
	}
	if st := h.state(); h.flag() != 0 || st.N != 0 || st.UpperSum != 0 || st.LowerSum != 0 {
		t.Fatalf("after timeout: flag=%d state=%+v", h.flag(), st)
	}
	// Setup re-runs: 30 windows at the new level never fire, the new mu is that level.
	for range 30 {
		h.mustQuiet(10_000_000)
	}
	if st := h.state(); st.Mu != 10_000_000 {
		t.Fatalf("re-setup mu=%d, want 10000000", st.Mu)
	}
}

func TestCusumSigmaFloor(t *testing.T) {
	h := newCusumHarness(t, 100*time.Millisecond)
	for range 30 {
		h.mustQuiet(0)
	}
	// var = 0, so k/h/gate all come from the 1500 B floor: 5000 B is
	// neither an onset (needs 7 sigma) nor learned (> 3 sigma)...
	n := h.state().N
	h.mustQuiet(5000)
	if h.state().N != n {
		t.Fatal("5000 B window learned past a 4500 B gate")
	}
	// ...while a small rise is learned, so mu can follow traffic back up.
	h.mustQuiet(3000)
	if h.state().N != n+1 {
		t.Fatal("3000 B window not learned after a silent baseline")
	}
}
