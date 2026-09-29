package main

import (
	"strings"
	"testing"
)

func TestFormatReport_CleanMatch(t *testing.T) {
	m := Metrics{
		PerBurst: []BurstResult{
			{Index: 0, OnsetLatencyNs: 10_000_000, HasOnsetLatency: true, DrainLatencyNs: 5_000_000, HasDrainLatency: true, CoverageRatio: 0.99},
		},
		TP:             1,
		FP:             0,
		FN:             0,
		HasGroundTruth: true,
		CoverageRatio:  0.99,
	}

	out := formatReport(m)

	for _, want := range []string{"TP=1", "FP=0", "FN=0", "10ms", "5ms", "99.0%"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestFormatReport_MissedBurstShownAsMissed(t *testing.T) {
	m := Metrics{
		PerBurst:       []BurstResult{{Index: 2}},
		TP:             0,
		FP:             0,
		FN:             1,
		HasGroundTruth: true,
	}

	out := formatReport(m)
	if !strings.Contains(out, "missed") {
		t.Errorf("expected a 'missed' marker for the FN burst:\n%s", out)
	}
}

func TestFormatReport_UnobservedDrainShownAsNotApplicable(t *testing.T) {
	m := Metrics{
		PerBurst: []BurstResult{
			{Index: 0, OnsetLatencyNs: 10_000_000, HasOnsetLatency: true, HasDrainLatency: false, CoverageRatio: 0.99},
		},
		TP:             1,
		HasGroundTruth: true,
		CoverageRatio:  0.99,
	}

	out := formatReport(m)
	if !strings.Contains(out, "n/a") {
		t.Errorf("expected an n/a marker for the unobserved drain:\n%s", out)
	}
}

func TestFormatReport_ZeroGroundTruthOmitsLatencyAndCoverageLines(t *testing.T) {
	m := Metrics{TP: 0, FP: 3, FN: 0, HasGroundTruth: false}

	out := formatReport(m)
	if !strings.Contains(out, "FP=3") {
		t.Errorf("expected FP=3 in report:\n%s", out)
	}
	if strings.Contains(out, "coverage") {
		t.Errorf("did not expect a coverage line with zero ground-truth bursts:\n%s", out)
	}
}
