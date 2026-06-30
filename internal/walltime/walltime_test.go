package walltime

import (
	"testing"
	"time"
)

func TestWallClock(t *testing.T) {
	base := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	// Anchor: wall=base, monoNs=1_000_000_000 (1 s since some boot reference).
	anchor := Anchor{wall: base, monoNs: 1_000_000_000}

	tests := []struct {
		name   string
		monoNs uint64
		want   time.Time
	}{
		{
			name:   "exact anchor point",
			monoNs: 1_000_000_000,
			want:   base,
		},
		{
			name:   "100ms after anchor",
			monoNs: 1_100_000_000,
			want:   base.Add(100 * time.Millisecond),
		},
		{
			name:   "50ms before anchor — backward offset",
			monoNs: 950_000_000,
			want:   base.Add(-50 * time.Millisecond),
		},
		{
			name:   "1 second after anchor",
			monoNs: 2_000_000_000,
			want:   base.Add(time.Second),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := anchor.WallClock(tc.monoNs)
			if !got.Equal(tc.want) {
				t.Errorf("WallClock(%d) = %v, want %v", tc.monoNs, got, tc.want)
			}
		})
	}
}
