package main

import (
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf/ringbuf"
)

const windowSampleSize = 24

type WindowSample struct {
	TimestampNs uint64
	Total       uint64
	Delta       uint64
}

func decodeSample(raw []byte) (WindowSample, error) {
	if len(raw) < windowSampleSize {
		return WindowSample{}, fmt.Errorf("window sample too short: got %d bytes, want %d", len(raw), windowSampleSize)
	}
	return WindowSample{
		TimestampNs: binary.LittleEndian.Uint64(raw[0:8]),
		Total:       binary.LittleEndian.Uint64(raw[8:16]),
		Delta:       binary.LittleEndian.Uint64(raw[16:24]),
	}, nil
}

func sampleLoop(logger *slog.Logger, w io.Writer, rd *ringbuf.Reader) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	anchor, anchorErr := newWallAnchor()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; time_utc column will be empty", "err", anchorErr)
	}

	if err := cw.Write([]string{"timestamp_ns", "total_bytes", "delta_bytes", "time_utc"}); err != nil {
		return fmt.Errorf("writing csv header: %w", err)
	}
	cw.Flush()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading window sample ringbuf: %w", err)
		}

		s, err := decodeSample(rec.RawSample)
		if err != nil {
			logger.Warn("skipping malformed window sample", "err", err, "raw_len", len(rec.RawSample))
			continue
		}

		wallStr := ""
		if anchorErr == nil {
			wallStr = anchor.WallClockString(s.TimestampNs)
		}

		if err := cw.Write([]string{
			strconv.FormatUint(s.TimestampNs, 10),
			strconv.FormatUint(s.Total, 10),
			strconv.FormatUint(s.Delta, 10),
			wallStr,
		}); err != nil {
			return fmt.Errorf("writing csv row: %w", err)
		}
		cw.Flush()
	}
}
