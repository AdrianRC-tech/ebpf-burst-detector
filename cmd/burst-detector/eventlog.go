package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf/ringbuf"
)

// eventLogLoop reads burst_events from rd and writes one CSV row per event to w.
// Columns: type, cusum_value, window_bytes, change_point_ns, change_point_utc, reason, mu, sigma.
// Blocks until rd is closed.
func eventLogLoop(logger *slog.Logger, w io.Writer, rd *ringbuf.Reader, onEvent func(BurstEvent)) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	anchor, anchorErr := newWallAnchor()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; change_point_utc column will be empty", "err", anchorErr)
	}

	if err := cw.Write([]string{"type", "cusum_value", "window_bytes", "change_point_ns", "change_point_utc", "reason", "mu", "sigma"}); err != nil {
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

		changeStr := ""
		if anchorErr == nil {
			changeStr = anchor.WallClockString(ev.ChangePointNs)
		}

		row := []string{
			eventTypeString(ev.Type),
			strconv.FormatUint(ev.CusumValue, 10),
			strconv.FormatUint(ev.WindowBytes, 10),
			strconv.FormatUint(ev.ChangePointNs, 10),
			changeStr,
			eventReasonString(ev.Reason),
			strconv.FormatUint(ev.Mu, 10),
			strconv.FormatUint(ev.Sigma, 10),
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing event csv row: %w", err)
		}
		cw.Flush()

		if ev.Type == EventDrain && ev.Reason == ReasonTimeout {
			logger.Warn("burst held longer than tau: forced drain, baseline re-learning (setup re-runs)")
		}
		if onEvent != nil {
			onEvent(ev)
		}
	}
}
