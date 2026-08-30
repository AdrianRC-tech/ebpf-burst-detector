package main

import (
	"encoding/binary"
	"testing"
)

// The byte layout under test must match struct burst_event in
// ebpf/cusum_detector.bpf.c:
//
//   timestamp_ns     __u64  offset  0
//   type             __u32  offset  8
//   _pad             __u32  offset 12
//   cusum_value      __u64  offset 16
//   window_bytes     __u64  offset 24
//   change_point_ns  __u64  offset 32
//                                 ----
//                                 40 bytes

func TestDecodeEvent_Onset(t *testing.T) {
	raw := make([]byte, burstEventSize)
	binary.LittleEndian.PutUint64(raw[0:], 1_000_000_000) // 1s
	binary.LittleEndian.PutUint32(raw[8:], EventOnset)
	binary.LittleEndian.PutUint64(raw[16:], 5_000_001)
	binary.LittleEndian.PutUint64(raw[24:], 2_000_000)
	binary.LittleEndian.PutUint64(raw[32:], 900_000_000) // 1-window lookback

	ev, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if ev.TimestampNs != 1_000_000_000 {
		t.Errorf("TimestampNs = %d, want 1_000_000_000", ev.TimestampNs)
	}
	if ev.Type != EventOnset {
		t.Errorf("Type = %d, want EventOnset (%d)", ev.Type, EventOnset)
	}
	if ev.CusumValue != 5_000_001 {
		t.Errorf("CusumValue = %d, want 5_000_001", ev.CusumValue)
	}
	if ev.WindowBytes != 2_000_000 {
		t.Errorf("WindowBytes = %d, want 2_000_000", ev.WindowBytes)
	}
	if ev.ChangePointNs != 900_000_000 {
		t.Errorf("ChangePointNs = %d, want 900_000_000", ev.ChangePointNs)
	}
}

func TestDecodeEvent_Drain(t *testing.T) {
	raw := make([]byte, burstEventSize)
	binary.LittleEndian.PutUint64(raw[0:], 2_000_000_000)
	binary.LittleEndian.PutUint32(raw[8:], EventDrain)
	binary.LittleEndian.PutUint64(raw[16:], 6_000_000)
	binary.LittleEndian.PutUint64(raw[24:], 500_000)
	binary.LittleEndian.PutUint64(raw[32:], 1_900_000_000)

	ev, err := decodeEvent(raw)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if ev.Type != EventDrain {
		t.Errorf("Type = %d, want EventDrain (%d)", ev.Type, EventDrain)
	}
	if ev.ChangePointNs != 1_900_000_000 {
		t.Errorf("ChangePointNs = %d, want 1_900_000_000", ev.ChangePointNs)
	}
}

func TestDecodeEvent_TooShort(t *testing.T) {
	if _, err := decodeEvent(make([]byte, 10)); err == nil {
		t.Fatal("expected error for short input, got nil")
	}
}

func TestDecodeEvent_StaleLayout(t *testing.T) {
	if _, err := decodeEvent(make([]byte, 32)); err == nil {
		t.Fatal("expected error for pre-change_point_ns 32-byte layout, got nil")
	}
}

func TestLookbackString(t *testing.T) {
	tests := []struct {
		name string
		ev   BurstEvent
		want string
	}{
		{
			name: "one window lookback",
			ev:   BurstEvent{TimestampNs: 1_000_000_000, ChangePointNs: 900_000_000},
			want: "100ms",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lookbackString(tt.ev); got != tt.want {
				t.Errorf("lookbackString(%+v) = %q, want %q", tt.ev, got, tt.want)
			}
		})
	}
}

func TestEventTypeString(t *testing.T) {
	if s := eventTypeString(EventOnset); s != "onset" {
		t.Errorf("EventOnset → %q, want %q", s, "onset")
	}
	if s := eventTypeString(EventDrain); s != "drain" {
		t.Errorf("EventDrain → %q, want %q", s, "drain")
	}
	if s := eventTypeString(99); s != "unknown" {
		t.Errorf("unknown type → %q, want %q", s, "unknown")
	}
}
