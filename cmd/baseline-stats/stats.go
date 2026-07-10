package main

import (
	"fmt"
	"io"
	"math"
	"sort"
)

// Stats holds distribution statistics for per-window delta_bytes values.
type Stats struct {
	Count    int
	Mean     float64
	Stdev    float64
	Median   float64
	MAD      float64
	SigmaHat float64 // 1.4826 × MAD — consistent scale estimate under normality
	Max      float64
}

// SuggestedParams holds the CUSUM parameters derived from baseline statistics.
type SuggestedParams struct {
	Mu0 uint64
	K   uint64
	H   uint64 // single threshold; caller emits as both --h-onset and --h-drain
}

// computeStats computes distribution statistics over a slice of per-window
// byte deltas. Mean and variance use Welford's online algorithm for numerical
// stability; median, percentiles, and MAD are computed from a sorted copy.
func computeStats(deltas []uint64) Stats {
	n := len(deltas)
	if n == 0 {
		return Stats{}
	}

	// Welford single-pass mean and variance.
	var mean, m2, maxVal float64
	for i, v := range deltas {
		x := float64(v)
		if x > maxVal {
			maxVal = x
		}
		cnt := float64(i + 1)
		delta := x - mean
		mean += delta / cnt
		m2 += delta * (x - mean)
	}
	var stdev float64
	if n > 1 {
		stdev = math.Sqrt(m2 / float64(n-1))
	}

	// Sort a copy for percentile and MAD computation.
	sorted := make([]float64, n)
	for i, v := range deltas {
		sorted[i] = float64(v)
	}
	sort.Float64s(sorted)

	median := percentile(sorted, 50)

	// MAD: median of |x − median| for each x.
	absDevs := make([]float64, n)
	for i, v := range sorted {
		d := v - median
		if d < 0 {
			d = -d
		}
		absDevs[i] = d
	}
	sort.Float64s(absDevs)
	mad := percentile(absDevs, 50)

	return Stats{
		Count:    n,
		Mean:     mean,
		Stdev:    stdev,
		Median:   median,
		MAD:      mad,
		SigmaHat: 1.4826 * mad,
		Max:      maxVal,
	}
}

// percentile returns the p-th percentile (0–100) of a pre-sorted slice using
// the nearest-rank method (no interpolation between adjacent values).
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[n-1]
	}
	idx := int(math.Ceil(p/100*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// deriveParams maps baseline statistics to CUSUM tuning parameters.
func deriveParams(s Stats, kMult, hMult float64) SuggestedParams {
	// TODO(human): implement the mapping from robust stats to CUSUM parameters.
	return SuggestedParams{
		Mu0: uint64(s.Median),
		K:   uint64(kMult * s.SigmaHat),
		H:   uint64(hMult * s.SigmaHat),
	}
}

// printReport writes a human-readable statistics block and the suggested
// cusum-detector flags to w.
func printReport(w io.Writer, s Stats, params SuggestedParams, kMult, hMult float64) {
	fmt.Fprintf(w, "=== Baseline Statistics (n=%d windows) ===\n\n", s.Count)
	fmt.Fprintf(w, "  mean              %14.0f bytes\n", s.Mean)
	fmt.Fprintf(w, "  stdev             %14.0f bytes\n", s.Stdev)
	fmt.Fprintf(w, "  median            %14.0f bytes   ← mu_0\n", s.Median)
	fmt.Fprintf(w, "  MAD               %14.0f bytes\n", s.MAD)
	fmt.Fprintf(w, "  σ̂ (1.4826×MAD)   %14.0f bytes\n", s.SigmaHat)
	fmt.Fprintf(w, "  max               %14.0f bytes\n\n", s.Max)
	fmt.Fprintf(w, "  k  = %.2f × σ̂   = %14d bytes\n", kMult, params.K)
	fmt.Fprintf(w, "  h  = %.2f × σ̂   = %14d bytes\n\n", hMult, params.H)
	fmt.Fprintln(w, "Note: values assume the --window size used during capture.")
	fmt.Fprintln(w, "      Re-capture at a different --window before re-tuning.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "=== Suggested flags ===")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  --mu0=%d --k=%d --h-onset=%d --h-drain=%d\n",
		params.Mu0, params.K, params.H, params.H)
}
