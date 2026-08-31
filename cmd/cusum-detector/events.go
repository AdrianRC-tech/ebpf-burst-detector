package main

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	EventOnset uint32 = 0
	EventDrain uint32 = 1

	// burstEventSize is sizeof(struct burst_event) in ebpf/cusum_detector.bpf.c.
	// Layout: timestamp_ns(8) + type(4) + _pad(4) + cusum_value(8) + window_bytes(8) + change_point_ns(8).
	burstEventSize = 40
)

// BurstEvent is the Go mirror of struct burst_event from the BPF program.
type BurstEvent struct {
	TimestampNs   uint64
	Type          uint32
	CusumValue    uint64
	WindowBytes   uint64
	ChangePointNs uint64
}

func decodeEvent(raw []byte) (BurstEvent, error) {
	if len(raw) < burstEventSize {
		return BurstEvent{}, fmt.Errorf("burst event too short: got %d bytes, want %d", len(raw), burstEventSize)
	}
	return BurstEvent{
		TimestampNs:   binary.LittleEndian.Uint64(raw[0:8]),
		Type:          binary.LittleEndian.Uint32(raw[8:12]),
		CusumValue:    binary.LittleEndian.Uint64(raw[16:24]),
		WindowBytes:   binary.LittleEndian.Uint64(raw[24:32]),
		ChangePointNs: binary.LittleEndian.Uint64(raw[32:40]),
	}, nil
}

// lookbackString renders how far change_point_ns reaches back from the event
// timestamp, as a human-readable duration.
func lookbackString(ev BurstEvent) string {
	// ChangePointNs > TimestampNs would underflow the uint64 subtraction into
	// a ~584-year duration instead of going negative; render it loudly rather
	// than let a bad estimate hide as a plausible-looking value.
	if ev.ChangePointNs > ev.TimestampNs {
		return fmt.Sprintf("%s (overflowed)", time.Duration(ev.ChangePointNs-ev.TimestampNs).String())
	}
	return time.Duration(ev.TimestampNs - ev.ChangePointNs).String()
}

func eventTypeString(t uint32) string {
	switch t {
	case EventOnset:
		return "onset"
	case EventDrain:
		return "drain"
	default:
		return "unknown"
	}
}
