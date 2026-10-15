package main

import (
	"time"

	"golang.org/x/sys/unix"
)

// wallAnchor pins kernel CLOCK_MONOTONIC to wall-clock time at one instant.
type wallAnchor struct {
	wall   time.Time
	monoNs int64
}

// newWallAnchor captures wall clock and CLOCK_MONOTONIC back-to-back. The matching clock
// is CLOCK_MONOTONIC because BPF uses bpf_ktime_get_ns() (not CLOCK_BOOTTIME).
func newWallAnchor() (wallAnchor, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return wallAnchor{}, err
	}
	return wallAnchor{wall: time.Now(), monoNs: ts.Nano()}, nil
}

// timeOnlyNanos is the fixed-width time-only UTC format used in CSV output.
// Always 9 fractional digits so columns align in the terminal.
const timeOnlyNanos = "15:04:05.000000000"

// WallClock maps a BPF monotonic-ns timestamp to wall-clock time.
func (a wallAnchor) WallClock(monoNs uint64) time.Time {
	return a.wall.Add(time.Duration(int64(monoNs) - a.monoNs))
}

// WallClockString renders a BPF monotonic-ns timestamp as a time-only UTC string.
func (a wallAnchor) WallClockString(monoNs uint64) string {
	return a.WallClock(monoNs).UTC().Format(timeOnlyNanos)
}
