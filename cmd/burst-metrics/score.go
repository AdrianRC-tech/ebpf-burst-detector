package main

// BurstResult is the scoring outcome for one ground-truth burst: either it
// matched a detected interval (TP, latencies and coverage populated) or it
// didn't (FN, HasOnsetLatency false).
type BurstResult struct {
	Index           int
	OnsetLatencyNs  int64
	HasOnsetLatency bool
	DrainLatencyNs  int64
	HasDrainLatency bool
	CoverageRatio   float64
}

// Metrics is the scored result of one run: a scenario's ground-truth bursts
// matched against the detector's onset/drain intervals.
type Metrics struct {
	PerBurst       []BurstResult
	TP, FP, FN     int
	HasGroundTruth bool
	CoverageRatio  float64 // meaningful only when HasGroundTruth (scenario A has none)
}

// score matches ground-truth bursts against detected intervals and computes
// TP/FP/FN, onset/drain latency, and % of each bursty window covered by the
// detector's flag.
//
// Both bursts and intervals are non-overlapping and time-ordered (the k6
// executor owns burst timing; the detector's FSM alternates onset/drain on a
// single flag), so a burst is matched to the first unmatched interval that
// overlaps it. toleranceNs extends how late an onset may arrive after a
// burst's nominal end and still count as a match — needed because a fixed
// tolerance long enough for widely-spaced bursts (scenario B) would blur
// together the tightly-spaced bursts of scenario C.
func score(bursts []Burst, intervals []DetectedInterval, toleranceNs int64) Metrics {
	matched := make([]bool, len(intervals))
	var perBurst []BurstResult
	var totalOverlap, totalDuration int64
	tp, fn := 0, 0

	for _, b := range bursts {
		totalDuration += b.EndTodNs - b.StartTodNs

		matchIdx := -1
		for i, iv := range intervals {
			if matched[i] {
				continue
			}
			onsetInRange := iv.OnsetChangePointNs <= b.EndTodNs+toleranceNs
			stillCoversStart := !iv.HasDrain || iv.DrainTimeNs >= b.StartTodNs
			if onsetInRange && stillCoversStart {
				matchIdx = i
				break
			}
		}

		if matchIdx == -1 {
			fn++
			perBurst = append(perBurst, BurstResult{Index: b.Index})
			continue
		}
		matched[matchIdx] = true
		tp++
		iv := intervals[matchIdx]

		overlapStart := max(iv.OnsetChangePointNs, b.StartTodNs)
		overlapEnd := b.EndTodNs
		var drainLatency int64
		if iv.HasDrain {
			overlapEnd = min(iv.DrainTimeNs, b.EndTodNs)
			drainLatency = iv.DrainTimeNs - b.EndTodNs
		}
		overlap := max(0, overlapEnd-overlapStart)
		totalOverlap += overlap

		perBurst = append(perBurst, BurstResult{
			Index:           b.Index,
			OnsetLatencyNs:  iv.OnsetChangePointNs - b.StartTodNs,
			HasOnsetLatency: true,
			DrainLatencyNs:  drainLatency,
			HasDrainLatency: iv.HasDrain,
			CoverageRatio:   float64(overlap) / float64(b.EndTodNs-b.StartTodNs),
		})
	}

	fp := 0
	for _, m := range matched {
		if !m {
			fp++
		}
	}

	metrics := Metrics{
		PerBurst:       perBurst,
		TP:             tp,
		FP:             fp,
		FN:             fn,
		HasGroundTruth: len(bursts) > 0,
	}
	if metrics.HasGroundTruth {
		metrics.CoverageRatio = float64(totalOverlap) / float64(totalDuration)
	}
	return metrics
}
