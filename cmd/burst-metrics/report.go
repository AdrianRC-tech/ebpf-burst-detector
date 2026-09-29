package main

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// formatReport renders m as a plain-text table: one row per ground-truth
// burst, followed by a TP/FP/FN summary and (when the run had any
// ground-truth bursts) mean/stdev latency and overall coverage.
func formatReport(m Metrics) string {
	var b strings.Builder

	if len(m.PerBurst) > 0 {
		fmt.Fprintf(&b, "%-6s %-14s %-14s %s\n", "burst", "onset_latency", "drain_latency", "coverage")
		for _, r := range m.PerBurst {
			onset, drain := "missed", "missed"
			coverage := "-"
			if r.HasOnsetLatency {
				onset = time.Duration(r.OnsetLatencyNs).String()
				drain = "n/a"
				if r.HasDrainLatency {
					drain = time.Duration(r.DrainLatencyNs).String()
				}
				coverage = fmt.Sprintf("%.1f%%", r.CoverageRatio*100)
			}
			fmt.Fprintf(&b, "%-6d %-14s %-14s %s\n", r.Index, onset, drain, coverage)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "TP=%d FP=%d FN=%d\n", m.TP, m.FP, m.FN)

	if !m.HasGroundTruth {
		b.WriteString("no ground-truth bursts in this run (scenario A) — FP is the false-alarm total\n")
		return b.String()
	}

	onsetMean, onsetStdev := latencyStats(m.PerBurst, func(r BurstResult) (int64, bool) { return r.OnsetLatencyNs, r.HasOnsetLatency })
	drainMean, drainStdev := latencyStats(m.PerBurst, func(r BurstResult) (int64, bool) { return r.DrainLatencyNs, r.HasDrainLatency })

	fmt.Fprintf(&b, "onset latency: mean %s, stdev %s\n", time.Duration(int64(onsetMean)), time.Duration(int64(onsetStdev)))
	fmt.Fprintf(&b, "drain latency: mean %s, stdev %s\n", time.Duration(int64(drainMean)), time.Duration(int64(drainStdev)))
	fmt.Fprintf(&b, "overall coverage: %.1f%%\n", m.CoverageRatio*100)

	return b.String()
}

// latencyStats returns the mean and population stdev, in nanoseconds, of the
// values selected by get across results where get's second return is true.
func latencyStats(results []BurstResult, get func(BurstResult) (int64, bool)) (mean, stdev float64) {
	var values []float64
	for _, r := range results {
		if v, ok := get(r); ok {
			values = append(values, float64(v))
		}
	}
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean = sum / float64(len(values))

	var sqDiff float64
	for _, v := range values {
		d := v - mean
		sqDiff += d * d
	}
	stdev = math.Sqrt(sqDiff / float64(len(values)))
	return mean, stdev
}
