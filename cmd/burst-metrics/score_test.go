package main

import "testing"

func TestScore_CleanMatch(t *testing.T) {
	bursts := []Burst{{Index: 0, StartTodNs: 1000, EndTodNs: 2000}}
	intervals := []DetectedInterval{{OnsetChangePointNs: 1010, DrainTimeNs: 2005, HasDrain: true}}

	m := score(bursts, intervals, 0)

	if m.TP != 1 || m.FP != 0 || m.FN != 0 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 1/0/0", m.TP, m.FP, m.FN)
	}
	if !m.HasGroundTruth {
		t.Fatal("HasGroundTruth = false, want true")
	}
	if len(m.PerBurst) != 1 {
		t.Fatalf("got %d per-burst results, want 1", len(m.PerBurst))
	}
	r := m.PerBurst[0]
	if !r.HasOnsetLatency || r.OnsetLatencyNs != 10 {
		t.Errorf("onset latency = %d (has=%v), want 10 (has=true)", r.OnsetLatencyNs, r.HasOnsetLatency)
	}
	if !r.HasDrainLatency || r.DrainLatencyNs != 5 {
		t.Errorf("drain latency = %d (has=%v), want 5 (has=true)", r.DrainLatencyNs, r.HasDrainLatency)
	}
	if r.CoverageRatio != 0.99 {
		t.Errorf("per-burst coverage = %v, want 0.99", r.CoverageRatio)
	}
	if m.CoverageRatio != 0.99 {
		t.Errorf("overall coverage = %v, want 0.99", m.CoverageRatio)
	}
}

func TestScore_MissedBurstIsFN(t *testing.T) {
	bursts := []Burst{{Index: 0, StartTodNs: 1000, EndTodNs: 2000}}
	var intervals []DetectedInterval

	m := score(bursts, intervals, 0)

	if m.TP != 0 || m.FP != 0 || m.FN != 1 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 0/0/1", m.TP, m.FP, m.FN)
	}
	if len(m.PerBurst) != 1 || m.PerBurst[0].HasOnsetLatency {
		t.Errorf("expected one unmatched per-burst result, got %+v", m.PerBurst)
	}
}

func TestScore_NonOverlappingIntervalIsFPAndBurstIsFN(t *testing.T) {
	bursts := []Burst{{Index: 0, StartTodNs: 1000, EndTodNs: 2000}}
	intervals := []DetectedInterval{{OnsetChangePointNs: 5000, DrainTimeNs: 5100, HasDrain: true}}

	m := score(bursts, intervals, 0)

	if m.TP != 0 || m.FP != 1 || m.FN != 1 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 0/1/1", m.TP, m.FP, m.FN)
	}
}

func TestScore_LateOnsetWithinToleranceStillMatches(t *testing.T) {
	bursts := []Burst{{Index: 0, StartTodNs: 1000, EndTodNs: 2000}}
	// Onset fires 100ns after the burst nominally ended.
	intervals := []DetectedInterval{{OnsetChangePointNs: 2100, DrainTimeNs: 2200, HasDrain: true}}

	m := score(bursts, intervals, 200)

	if m.TP != 1 || m.FP != 0 || m.FN != 0 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 1/0/0", m.TP, m.FP, m.FN)
	}
	r := m.PerBurst[0]
	if r.OnsetLatencyNs != 1100 {
		t.Errorf("onset latency = %d, want 1100", r.OnsetLatencyNs)
	}
	if r.CoverageRatio != 0 {
		t.Errorf("coverage = %v, want 0 (onset arrived after the burst ended)", r.CoverageRatio)
	}
}

func TestScore_ZeroGroundTruthBurstsIsFalseAlarmOnly(t *testing.T) {
	var bursts []Burst
	intervals := []DetectedInterval{{OnsetChangePointNs: 100, DrainTimeNs: 150, HasDrain: true}}

	m := score(bursts, intervals, 0)

	if m.TP != 0 || m.FP != 1 || m.FN != 0 {
		t.Fatalf("TP/FP/FN = %d/%d/%d, want 0/1/0", m.TP, m.FP, m.FN)
	}
	if m.HasGroundTruth {
		t.Error("HasGroundTruth = true, want false for a baseline-only (scenario A) run")
	}
}

func TestScore_UnterminatedIntervalCountsCoverageThroughBurstEnd(t *testing.T) {
	bursts := []Burst{{Index: 0, StartTodNs: 1000, EndTodNs: 2000}}
	intervals := []DetectedInterval{{OnsetChangePointNs: 1010, HasDrain: false}}

	m := score(bursts, intervals, 0)

	if m.TP != 1 {
		t.Fatalf("TP = %d, want 1", m.TP)
	}
	r := m.PerBurst[0]
	if r.HasDrainLatency {
		t.Error("HasDrainLatency = true, want false (no drain observed)")
	}
	if r.CoverageRatio != 0.99 {
		t.Errorf("coverage = %v, want 0.99", r.CoverageRatio)
	}
}
