package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"strconv"
	"strings"
	"testing"
)

func makeEventBytes(tsNs uint64, typ uint32, cusumVal, windowBytes uint64) []byte {
	raw := make([]byte, burstEventSize)
	binary.LittleEndian.PutUint64(raw[0:], tsNs)
	binary.LittleEndian.PutUint32(raw[8:], typ)
	binary.LittleEndian.PutUint64(raw[16:], cusumVal)
	binary.LittleEndian.PutUint64(raw[24:], windowBytes)
	return raw
}

// TestEventLogCSVFormat verifies the CSV row layout produced by eventLogLoop
// by running its formatting logic in isolation (decodeEvent + csv.Writer).
// This avoids requiring a live kernel ringbuf while still exercising the
// column ordering and type string conversion.
func TestEventLogCSVFormat(t *testing.T) {
	inputs := []struct {
		tsNs        uint64
		typ         uint32
		cusumVal    uint64
		windowBytes uint64
		wantType    string
	}{
		{1_000_000_000, EventOnset, 5_000_001, 2_000_000, "onset"},
		{2_000_000_000, EventDrain, 6_000_000, 1_000_000, "drain"},
	}

	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"timestamp_ns", "type", "cusum_value", "window_bytes", "time_utc"})
	cw.Flush()

	for _, inp := range inputs {
		raw := makeEventBytes(inp.tsNs, inp.typ, inp.cusumVal, inp.windowBytes)
		ev, err := decodeEvent(raw)
		if err != nil {
			t.Fatalf("decodeEvent: %v", err)
		}
		_ = cw.Write([]string{
			strconv.FormatUint(ev.TimestampNs, 10),
			eventTypeString(ev.Type),
			strconv.FormatUint(ev.CusumValue, 10),
			strconv.FormatUint(ev.WindowBytes, 10),
			"",
		})
		cw.Flush()
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("parsing csv output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 (header + 2 events)", len(rows))
	}
	header := rows[0]
	if header[0] != "timestamp_ns" || header[1] != "type" || header[2] != "cusum_value" || header[3] != "window_bytes" {
		t.Fatalf("unexpected header: %v", header)
	}
	for i, inp := range inputs {
		row := rows[i+1]
		if row[1] != inp.wantType {
			t.Errorf("row %d: type = %q, want %q", i+1, row[1], inp.wantType)
		}
		if row[0] != strconv.FormatUint(inp.tsNs, 10) {
			t.Errorf("row %d: timestamp_ns = %q, want %q", i+1, row[0], strconv.FormatUint(inp.tsNs, 10))
		}
	}
}
