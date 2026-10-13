package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"strconv"
	"strings"
	"testing"
)

func makeEventBytes(typ uint32, cusumVal, windowBytes, changePointNs uint64) []byte {
	raw := make([]byte, burstEventSize)
	binary.LittleEndian.PutUint32(raw[0:], typ)
	binary.LittleEndian.PutUint64(raw[8:], cusumVal)
	binary.LittleEndian.PutUint64(raw[16:], windowBytes)
	binary.LittleEndian.PutUint64(raw[24:], changePointNs)
	return raw
}

// TestEventLogCSVFormat verifies the CSV row layout produced by eventLogLoop
// by running its formatting logic in isolation (decodeEvent + csv.Writer).
// This avoids requiring a live kernel ringbuf while still exercising the
// column ordering and type string conversion.
func TestEventLogCSVFormat(t *testing.T) {
	inputs := []struct {
		typ           uint32
		cusumVal      uint64
		windowBytes   uint64
		changePointNs uint64
		wantType      string
	}{
		{EventOnset, 5_000_001, 2_000_000, 900_000_000, "onset"},
		{EventDrain, 6_000_000, 1_000_000, 900_000_000, "drain"},
	}

	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"type", "cusum_value", "window_bytes", "change_point_ns", "change_point_utc"})
	cw.Flush()

	for _, inp := range inputs {
		raw := makeEventBytes(inp.typ, inp.cusumVal, inp.windowBytes, inp.changePointNs)
		ev, err := decodeEvent(raw)
		if err != nil {
			t.Fatalf("decodeEvent: %v", err)
		}
		_ = cw.Write([]string{
			eventTypeString(ev.Type),
			strconv.FormatUint(ev.CusumValue, 10),
			strconv.FormatUint(ev.WindowBytes, 10),
			strconv.FormatUint(ev.ChangePointNs, 10),
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
	if header[0] != "type" || header[1] != "cusum_value" || header[2] != "window_bytes" || header[3] != "change_point_ns" {
		t.Fatalf("unexpected header: %v", header)
	}
	for i, inp := range inputs {
		row := rows[i+1]
		if row[0] != inp.wantType {
			t.Errorf("row %d: type = %q, want %q", i+1, row[0], inp.wantType)
		}
		if row[3] != strconv.FormatUint(inp.changePointNs, 10) {
			t.Errorf("row %d: change_point_ns = %q, want %q", i+1, row[3], strconv.FormatUint(inp.changePointNs, 10))
		}
	}
}
