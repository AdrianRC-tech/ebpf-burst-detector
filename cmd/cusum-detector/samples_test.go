package main

import (
	"encoding/binary"
	"testing"
)

// The byte layout under test must match struct window_sample in
// ebpf/cusum_detector.bpf.c:
//
//	timestamp_ns  __u64  offset  0
//	total         __u64  offset  8
//	delta         __u64  offset 16
//	                           ----
//	                           24 bytes

func TestDecodeSample_Valid(t *testing.T) {
	raw := make([]byte, windowSampleSize)
	binary.LittleEndian.PutUint64(raw[0:], 1_000_000_000) // 1s
	binary.LittleEndian.PutUint64(raw[8:], 5_000_000_000)
	binary.LittleEndian.PutUint64(raw[16:], 2_000_000)

	s, err := decodeSample(raw)
	if err != nil {
		t.Fatalf("decodeSample: %v", err)
	}
	if s.TimestampNs != 1_000_000_000 {
		t.Errorf("TimestampNs = %d, want 1_000_000_000", s.TimestampNs)
	}
	if s.Total != 5_000_000_000 {
		t.Errorf("Total = %d, want 5_000_000_000", s.Total)
	}
	if s.Delta != 2_000_000 {
		t.Errorf("Delta = %d, want 2_000_000", s.Delta)
	}
}

func TestDecodeSample_TooShort(t *testing.T) {
	if _, err := decodeSample(make([]byte, 10)); err == nil {
		t.Fatal("expected error for short input, got nil")
	}
}
