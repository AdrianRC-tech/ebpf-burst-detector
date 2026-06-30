package walltime

import (
	"time"

	"golang.org/x/sys/unix"
)

// Anchor pins kernel CLOCK_MONOTONIC to wall-clock time at one instant.
type Anchor struct {
	wall   time.Time
	monoNs int64
}

// Now captures wall clock and CLOCK_MONOTONIC back-to-back. The matching clock
// is CLOCK_MONOTONIC because BPF uses bpf_ktime_get_ns() (not CLOCK_BOOTTIME).
func Now() (Anchor, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return Anchor{}, err
	}
	return Anchor{wall: time.Now(), monoNs: ts.Nano()}, nil
}

// TimeOnlyNanos is the fixed-width time-only UTC format used in CSV output.
// Always 9 fractional digits so columns align in the terminal.
const TimeOnlyNanos = "15:04:05.000000000"

// WallClock maps a BPF monotonic-ns timestamp to wall-clock time.
func (a Anchor) WallClock(monoNs uint64) time.Time {
	// TODO(human): apply the monotonic delta to the wall anchor and return the wall time
	return a.wall.Add(time.Duration(int64(monoNs) - a.monoNs))
}

// WallClockString renders a BPF monotonic-ns timestamp as a time-only UTC string.
func (a Anchor) WallClockString(monoNs uint64) string {
	return a.WallClock(monoNs).UTC().Format(TimeOnlyNanos)
}
