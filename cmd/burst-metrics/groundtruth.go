package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Burst is a single ground-truth bursty window, expressed in nanoseconds since
// UTC midnight (see parseTimeOfDayNs) so it is directly comparable with
// detector event timestamps parsed the same way.
type Burst struct {
	Index      int
	StartTodNs int64
	EndTodNs   int64
}

// parseGroundTruth reads a k6 stdout log and returns the ground-truth bursty
// windows it printed via its `plan: ...` lines (see loadgen/k6/bursts.js and
// loadgen/k6/staircase.js setup()).
//
// bursts.js (scenarios A/B/C/E) emits 5 fields per burst: index, start_ns,
// end_ns, start_utc, end_utc. Scenario A (N_BURSTS=0) emits no per-burst
// lines at all — an empty, non-error result.
//
// staircase.js (scenario D) emits 6 fields: index, target_rps, start_ns,
// end_ns, start_utc, end_utc. Only the rows at the run's peak target_rps are
// kept as ground truth; the ramp-through steps are not scored either way.
//
// All other `plan: ...` lines (headers, summaries) fail to parse as a data
// row and are silently skipped.
func parseGroundTruth(r io.Reader) ([]Burst, error) {
	type row struct {
		idx        int
		targetRps  int64
		hasRps     bool
		startTodNs int64
		endTodNs   int64
	}

	var rows []row
	maxRps := int64(-1)

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(line, "plan:")
		if !ok {
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) != 5 && len(fields) != 6 {
			continue
		}

		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		var rw row
		rw.idx = idx

		var startUtc, endUtc string
		if len(fields) == 6 {
			rps, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			rw.targetRps = rps
			rw.hasRps = true
			if rps > maxRps {
				maxRps = rps
			}
			startUtc, endUtc = fields[4], fields[5]
		} else {
			startUtc, endUtc = fields[3], fields[4]
		}

		rw.startTodNs, err = parseTimeOfDayNs(startUtc)
		if err != nil {
			return nil, fmt.Errorf("parsing start_utc %q on line %q: %w", startUtc, line, err)
		}
		rw.endTodNs, err = parseTimeOfDayNs(endUtc)
		if err != nil {
			return nil, fmt.Errorf("parsing end_utc %q on line %q: %w", endUtc, line, err)
		}

		rows = append(rows, rw)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading ground truth log: %w", err)
	}

	var bursts []Burst
	for _, rw := range rows {
		if rw.hasRps && rw.targetRps != maxRps {
			continue
		}
		bursts = append(bursts, Burst{Index: rw.idx, StartTodNs: rw.startTodNs, EndTodNs: rw.endTodNs})
	}
	return bursts, nil
}
