package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/AdrianRC-tech/ebpf-burst-detector/internal/walltime"
)

// eventLogLoop reads burst_events from rd and writes one CSV row per event to w.
// Columns: timestamp_ns, type, cusum_value, window_bytes, time_utc, change_point_utc, lookback.
// Blocks until rd is closed.
func eventLogLoop(logger *slog.Logger, w io.Writer, rd *ringbuf.Reader) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	anchor, anchorErr := walltime.Now()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; time_utc column will be empty", "err", anchorErr)
	}

	if err := cw.Write([]string{"timestamp_ns", "type", "cusum_value", "window_bytes", "time_utc", "change_point_utc", "lookback"}); err != nil {
		return fmt.Errorf("writing event csv header: %w", err)
	}
	cw.Flush()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading burst event ringbuf: %w", err)
		}

		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			logger.Warn("skipping malformed event in event log", "err", err)
			continue
		}

		wallStr := ""
		changeStr := ""
		if anchorErr == nil {
			wallStr = anchor.WallClockString(ev.TimestampNs)
			changeStr = anchor.WallClockString(ev.ChangePointNs)
		}

		row := []string{
			strconv.FormatUint(ev.TimestampNs, 10),
			eventTypeString(ev.Type),
			strconv.FormatUint(ev.CusumValue, 10),
			strconv.FormatUint(ev.WindowBytes, 10),
			wallStr,
			changeStr,
			lookbackString(ev),
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing event csv row: %w", err)
		}
		cw.Flush()
	}
}
