package main

import (
	"encoding/csv"
	"fmt"
	"io"
)

// DetectedInterval is one onset-to-drain span from the CUSUM detector, expressed
// in nanoseconds since UTC midnight (see parseTimeOfDayNs). OnsetChangePointNs
// comes from the onset event's change_point_utc (the changepoint-backdated
// estimate). DrainTimeNs comes from the drain event's raw time_utc, not its
// change_point_utc: the detector never updates accum_start_ns on the drain arm
// (see ebpf/cusum_detector.bpf.c cusum_tick), so a drain event's change_point_ns
// is stale — frozen from the preceding onset — rather than a real drain-side
// changepoint estimate.
type DetectedInterval struct {
	OnsetChangePointNs int64
	DrainTimeNs        int64
	HasDrain           bool
}

// parseDetectedIntervals reads a CSV produced by cusum-detector --event-csv
// (see cmd/cusum-detector/eventlog.go) and pairs each onset row with the next
// drain row. The detector's FSM alternates onset/drain strictly (a single
// burst_flag), so rows arrive in matching pairs; a trailing unpaired onset
// (the detector stopped, or the log was cut, mid-burst) is returned with
// HasDrain false.
func parseDetectedIntervals(r io.Reader) ([]DetectedInterval, error) {
	cr := csv.NewReader(r)
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("reading event csv header: %w", err)
	}
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[name] = i
	}
	for _, want := range []string{"type", "time_utc", "change_point_utc"} {
		if _, ok := col[want]; !ok {
			return nil, fmt.Errorf("event csv missing required column %q", want)
		}
	}

	var intervals []DetectedInterval
	var pendingOnsetCP int64
	havePending := false

	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading event csv row: %w", err)
		}

		switch typ := row[col["type"]]; typ {
		case "onset":
			if havePending {
				intervals = append(intervals, DetectedInterval{OnsetChangePointNs: pendingOnsetCP})
			}
			cp, err := parseTimeOfDayNs(row[col["change_point_utc"]])
			if err != nil {
				return nil, fmt.Errorf("parsing change_point_utc %q: %w", row[col["change_point_utc"]], err)
			}
			pendingOnsetCP = cp
			havePending = true
		case "drain":
			if !havePending {
				continue // drain with no preceding onset in this file; ignore
			}
			t, err := parseTimeOfDayNs(row[col["time_utc"]])
			if err != nil {
				return nil, fmt.Errorf("parsing time_utc %q: %w", row[col["time_utc"]], err)
			}
			intervals = append(intervals, DetectedInterval{
				OnsetChangePointNs: pendingOnsetCP,
				DrainTimeNs:        t,
				HasDrain:           true,
			})
			havePending = false
		default:
			return nil, fmt.Errorf("unknown event type %q", typ)
		}
	}

	if havePending {
		intervals = append(intervals, DetectedInterval{OnsetChangePointNs: pendingOnsetCP})
	}
	return intervals, nil
}
