package main

import (
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/AdrianRC-tech/ebpf-burst-detector/internal/walltime"
)

const pktTraceSize = 32

// PktTrace is the decoded form of the 32-byte struct pkt_trace emitted by the
// BPF program when trace_packets=1. Addresses are copied out of the ring buffer
// slice so they are safe to retain after the ringbuf record is released.
// Ports are converted from network byte order to host byte order.
type PktTrace struct {
	TimestampNs uint64
	Len         uint32
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	Family      uint8
}

// decodePktTrace parses a raw 32-byte ring buffer record into a PktTrace.
// BPF struct layout (offsets in bytes):
//
//	0  timestamp_ns  uint64 (little-endian)
//	8  len           uint32 (little-endian)
//	12 saddr         uint32 (network byte order)
//	16 daddr         uint32 (network byte order)
//	20 sport         uint16 (network byte order)
//	22 dport         uint16 (network byte order)
//	24 protocol      uint8
//	25 family        uint8
//	26 _pad[6]
func decodePktTrace(raw []byte) (PktTrace, error) {
	if len(raw) < pktTraceSize {
		return PktTrace{}, fmt.Errorf("packet trace too short: got %d bytes, want %d", len(raw), pktTraceSize)
	}
	t := PktTrace{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:8]),
		Len:         binary.LittleEndian.Uint32(raw[8:12]),
		// saddr/daddr: copy raw network-order bytes into net.IP (4-byte form)
		SrcIP:    net.IP{raw[12], raw[13], raw[14], raw[15]},
		DstIP:    net.IP{raw[16], raw[17], raw[18], raw[19]},
		// ports: network byte order → host byte order
		SrcPort:  binary.BigEndian.Uint16(raw[20:22]),
		DstPort:  binary.BigEndian.Uint16(raw[22:24]),
		Protocol: raw[24],
		Family:   raw[25],
	}
	return t, nil
}

// traceLoop reads per-packet trace records from rd and writes them as CSV rows
// to w. It returns when the reader is closed (clean shutdown) or on a non-EOF
// read error.
//
// CSV columns: timestamp_ns, len, src_ip, dst_ip, src_port, dst_port, protocol, time_utc
func traceLoop(logger *slog.Logger, w io.Writer, rd *ringbuf.Reader) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	anchor, anchorErr := walltime.Now()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; time_utc column will be empty", "err", anchorErr)
	}

	if err := cw.Write([]string{"timestamp_ns", "len", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "time_utc"}); err != nil {
		return fmt.Errorf("writing csv header: %w", err)
	}
	cw.Flush()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading packet trace ringbuf: %w", err)
		}

		t, err := decodePktTrace(rec.RawSample)
		if err != nil {
			logger.Warn("skipping malformed packet trace", "err", err, "raw_len", len(rec.RawSample))
			continue
		}

		wallStr := ""
		if anchorErr == nil {
			wallStr = anchor.WallClockString(t.TimestampNs)
		}

		if err := cw.Write([]string{
			strconv.FormatUint(t.TimestampNs, 10),
			strconv.FormatUint(uint64(t.Len), 10),
			t.SrcIP.String(),
			t.DstIP.String(),
			strconv.FormatUint(uint64(t.SrcPort), 10),
			strconv.FormatUint(uint64(t.DstPort), 10),
			strconv.FormatUint(uint64(t.Protocol), 10),
			wallStr,
		}); err != nil {
			return fmt.Errorf("writing csv row: %w", err)
		}
		cw.Flush()
	}
}
