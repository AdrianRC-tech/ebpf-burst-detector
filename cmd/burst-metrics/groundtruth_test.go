package main

import (
	"strings"
	"testing"
)

func TestParseGroundTruth_BurstsShape(t *testing.T) {
	log := strings.Join([]string{
		"plan: baseline=100rps peak=200rps window=800ms ramp=0ms n=2 gap=5s target=http://172.18.0.2:30500",
		"plan: expected 160 requests per bursty window",
		"plan: burst_idx  start_ns  end_ns  start_utc  end_utc  (anchored at setup; hold-at-peak segment, excludes ramp)",
		"plan: 000  66000000000  866000000000  11:00:30.066000000  11:00:30.866000000",
		"plan: 001  71000000000  871000000000  11:00:35.066000000  11:00:35.866000000",
		"scenario_start: 66000000000 ns  11:00:30.066000000 UTC",
	}, "\n")

	bursts, err := parseGroundTruth(strings.NewReader(log))
	if err != nil {
		t.Fatalf("parseGroundTruth returned error: %v", err)
	}

	want := []Burst{
		{Index: 0, StartTodNs: 39630*1_000_000_000 + 66_000_000, EndTodNs: 39630*1_000_000_000 + 866_000_000},
		{Index: 1, StartTodNs: 39635*1_000_000_000 + 66_000_000, EndTodNs: 39635*1_000_000_000 + 866_000_000},
	}
	if len(bursts) != len(want) {
		t.Fatalf("got %d bursts, want %d: %+v", len(bursts), len(want), bursts)
	}
	for i := range want {
		if bursts[i] != want[i] {
			t.Errorf("burst[%d] = %+v, want %+v", i, bursts[i], want[i])
		}
	}
}

func TestParseGroundTruth_StaircaseShapeKeepsOnlyPeakLevel(t *testing.T) {
	log := strings.Join([]string{
		"plan: floor=50rps peak=200rps levels=[50,100,150,200,150,100,50] step=500ms cycles=1 gap=5s target=http://172.18.0.2:30500",
		"plan: step_idx  target_rps  start_ns  end_ns  start_utc  end_utc  (anchored at setup)",
		"plan: 000  50  10000000000  10500000000  10:00:10.000000000  10:00:10.500000000",
		"plan: 001  100  10500000000  11000000000  10:00:10.500000000  10:00:11.000000000",
		"plan: 002  150  11000000000  11500000000  10:00:11.000000000  10:00:11.500000000",
		"plan: 003  200  11500000000  12000000000  10:00:11.500000000  10:00:12.000000000",
		"plan: 004  150  12000000000  12500000000  10:00:12.000000000  10:00:12.500000000",
		"plan: 005  100  12500000000  13000000000  10:00:12.500000000  10:00:13.000000000",
		"plan: 006  50  13000000000  13500000000  10:00:13.000000000  10:00:13.500000000",
	}, "\n")

	bursts, err := parseGroundTruth(strings.NewReader(log))
	if err != nil {
		t.Fatalf("parseGroundTruth returned error: %v", err)
	}

	want := Burst{
		Index:      3,
		StartTodNs: 36000*1_000_000_000 + 11*1_000_000_000 + 500_000_000,
		EndTodNs:   36000*1_000_000_000 + 12*1_000_000_000,
	}
	if len(bursts) != 1 {
		t.Fatalf("got %d bursts, want 1 (only the peak step): %+v", len(bursts), bursts)
	}
	if bursts[0] != want {
		t.Errorf("burst = %+v, want %+v", bursts[0], want)
	}
}

func TestParseGroundTruth_NoBursts(t *testing.T) {
	// Scenario A: N_BURSTS=0, k6 never prints a per-burst `plan:` line.
	log := "plan: baseline=100rps peak=100rps window=800ms ramp=0ms n=0 gap=10s target=http://172.18.0.2:30500\n" +
		"plan: expected 0 requests per bursty window\n"

	bursts, err := parseGroundTruth(strings.NewReader(log))
	if err != nil {
		t.Fatalf("parseGroundTruth returned error: %v", err)
	}
	if len(bursts) != 0 {
		t.Errorf("got %d bursts, want 0: %+v", len(bursts), bursts)
	}
}
