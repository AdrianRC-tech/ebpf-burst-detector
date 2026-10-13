package main

import (
	"encoding/binary"
	"fmt"
)

const (
	EventOnset uint32 = 0
	EventDrain uint32 = 1

	// burstEventSize is sizeof(struct burst_event) in ebpf/cusum_detector.bpf.c.
	// Layout: type(4) + _pad(4) + cusum_value(8) + window_bytes(8) + change_point_ns(8).
	burstEventSize = 32
)

// BurstEvent is the Go mirror of struct burst_event from the BPF program.
type BurstEvent struct {
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
		Type:          binary.LittleEndian.Uint32(raw[0:4]),
		CusumValue:    binary.LittleEndian.Uint64(raw[8:16]),
		WindowBytes:   binary.LittleEndian.Uint64(raw[16:24]),
		ChangePointNs: binary.LittleEndian.Uint64(raw[24:32]),
	}, nil
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
