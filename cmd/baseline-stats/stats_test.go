package main

import (
	"math"
	"testing"
)

func TestComputeStats(t *testing.T) {
	// Hand-computed expected values for [1,2,3,4,5]:
	//   mean=3, stdev=sqrt(2.5), median=3, MAD=1, p90=5, max=5
	tests := []struct {
		name       string
		deltas     []uint64
		wantMean   float64
		wantStdev  float64
		wantMedian float64
		wantMAD    float64
		wantMax    float64
	}{
		{
			name:       "arithmetic sequence 1-5",
			deltas:     []uint64{1, 2, 3, 4, 5},
			wantMean:   3.0,
			wantStdev:  math.Sqrt(2.5), // sample stdev = sqrt(10/4)
			wantMedian: 3.0,            // nearest-rank p50: ceil(2.5)-1=2, sorted[2]=3
			wantMAD:    1.0,            // abs devs [2,1,0,1,2] → sorted [0,1,1,2,2] → median=1
			wantMax:    5.0,
		},
		{
			name:       "single element",
			deltas:     []uint64{42},
			wantMean:   42.0,
			wantStdev:  0.0,
			wantMedian: 42.0,
			wantMAD:    0.0,
			wantMax:    42.0,
		},
	}

	const eps = 1e-9
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := computeStats(tc.deltas)
			if math.Abs(s.Mean-tc.wantMean) > eps {
				t.Errorf("Mean: got %v, want %v", s.Mean, tc.wantMean)
			}
			if math.Abs(s.Stdev-tc.wantStdev) > eps {
				t.Errorf("Stdev: got %v, want %v", s.Stdev, tc.wantStdev)
			}
			if math.Abs(s.Median-tc.wantMedian) > eps {
				t.Errorf("Median: got %v, want %v", s.Median, tc.wantMedian)
			}
			if math.Abs(s.MAD-tc.wantMAD) > eps {
				t.Errorf("MAD: got %v, want %v", s.MAD, tc.wantMAD)
			}
			if math.Abs(s.Max-tc.wantMax) > eps {
				t.Errorf("Max: got %v, want %v", s.Max, tc.wantMax)
			}
		})
	}
}

func TestComputeStatsSigmaHat(t *testing.T) {
	// MAD of [1,2,3,4,5] = 1.0, so SigmaHat = 1.4826 × 1 = 1.4826.
	s := computeStats([]uint64{1, 2, 3, 4, 5})
	const want = 1.4826
	if math.Abs(s.SigmaHat-want) > 1e-4 {
		t.Errorf("SigmaHat: got %v, want %v", s.SigmaHat, want)
	}
}

func TestComputeStatsEmpty(t *testing.T) {
	s := computeStats(nil)
	if s.Count != 0 {
		t.Errorf("expected zero Stats for empty input, got Count=%d", s.Count)
	}
}
