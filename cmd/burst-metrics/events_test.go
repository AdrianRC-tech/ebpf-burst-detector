package main

import (
	"strings"
	"testing"
)

const eventCSVHeader = "timestamp_ns,type,cusum_value,window_bytes,time_utc,change_point_utc,lookback\n"

func TestParseDetectedIntervals_OnePair(t *testing.T) {
	csv := eventCSVHeader +
		"1000000000,onset,5100000,300000,11:00:30.100000000,11:00:30.010000000,90ms\n" +
		"1900000000,drain,0,10000,11:00:30.900000000,11:00:30.010000000,890ms\n"

	got, err := parseDetectedIntervals(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseDetectedIntervals returned error: %v", err)
	}

	want := DetectedInterval{
		OnsetChangePointNs: 39630*1_000_000_000 + 10_000_000,
		DrainTimeNs:        39630*1_000_000_000 + 900_000_000,
		HasDrain:           true,
	}
	if len(got) != 1 {
		t.Fatalf("got %d intervals, want 1: %+v", len(got), got)
	}
	if got[0] != want {
		t.Errorf("interval = %+v, want %+v", got[0], want)
	}
}

func TestParseDetectedIntervals_TwoPairs(t *testing.T) {
	csv := eventCSVHeader +
		"1000000000,onset,5100000,300000,11:00:30.100000000,11:00:30.010000000,90ms\n" +
		"1900000000,drain,0,10000,11:00:30.900000000,11:00:30.010000000,890ms\n" +
		"6000000000,onset,5100000,300000,11:00:35.100000000,11:00:35.010000000,90ms\n" +
		"6900000000,drain,0,10000,11:00:35.900000000,11:00:35.010000000,890ms\n"

	got, err := parseDetectedIntervals(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseDetectedIntervals returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d intervals, want 2: %+v", len(got), got)
	}
}

func TestParseDetectedIntervals_TrailingUnpairedOnset(t *testing.T) {
	// Detector stopped (or log was cut) mid-burst: an onset with no matching drain.
	csv := eventCSVHeader +
		"1000000000,onset,5100000,300000,11:00:30.100000000,11:00:30.010000000,90ms\n"

	got, err := parseDetectedIntervals(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseDetectedIntervals returned error: %v", err)
	}

	want := DetectedInterval{
		OnsetChangePointNs: 39630*1_000_000_000 + 10_000_000,
		HasDrain:           false,
	}
	if len(got) != 1 {
		t.Fatalf("got %d intervals, want 1: %+v", len(got), got)
	}
	if got[0] != want {
		t.Errorf("interval = %+v, want %+v", got[0], want)
	}
}

func TestParseDetectedIntervals_NoEvents(t *testing.T) {
	got, err := parseDetectedIntervals(strings.NewReader(eventCSVHeader))
	if err != nil {
		t.Fatalf("parseDetectedIntervals returned error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d intervals, want 0: %+v", len(got), got)
	}
}

func TestParseDetectedIntervals_UnknownType(t *testing.T) {
	csv := eventCSVHeader + "1000000000,wat,0,0,11:00:30.100000000,11:00:30.010000000,90ms\n"
	if _, err := parseDetectedIntervals(strings.NewReader(csv)); err == nil {
		t.Fatal("expected an error for an unknown event type, got nil")
	}
}
