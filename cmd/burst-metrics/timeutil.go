package main

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTimeOfDayNs parses a "HH:MM:SS[.nnnnnnnnn]" UTC time-only string — the
// format both k6's utcNanos() and the detector's walltime.WallClockString emit —
// into nanoseconds since UTC midnight. This is the only domain in which k6
// ground-truth timestamps and detector event timestamps can be compared: k6
// prints real epoch-ns, but the detector's timestamps are CLOCK_MONOTONIC and
// carry no epoch of their own, so the time-only wall-clock string is the sole
// common field.
func parseTimeOfDayNs(s string) (int64, error) {
	hms := strings.SplitN(s, ":", 3)
	if len(hms) != 3 {
		return 0, fmt.Errorf("invalid time-of-day %q: want HH:MM:SS[.nnnnnnnnn]", s)
	}

	hour, err := strconv.ParseInt(hms[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hour in %q: %w", s, err)
	}
	minute, err := strconv.ParseInt(hms[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid minute in %q: %w", s, err)
	}

	secStr, fracStr, _ := strings.Cut(hms[2], ".")
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid second in %q: %w", s, err)
	}

	var fracNs int64
	if fracStr != "" {
		if len(fracStr) > 9 {
			return 0, fmt.Errorf("fractional seconds %q in %q exceed nanosecond precision", fracStr, s)
		}
		fracStr = fracStr + strings.Repeat("0", 9-len(fracStr))
		fracNs, err = strconv.ParseInt(fracStr, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid fractional seconds in %q: %w", s, err)
		}
	}

	return (hour*3600+minute*60+sec)*1_000_000_000 + fracNs, nil
}
