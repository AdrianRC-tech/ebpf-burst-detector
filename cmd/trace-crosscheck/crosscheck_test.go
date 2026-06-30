package main

import (
	"testing"
)

func TestBucketPackets(t *testing.T) {
	mkWin := func(ts, delta uint64) windowSample { return windowSample{ts, delta} }
	mkPkt := func(ts uint64, l uint32) pktRecord { return pktRecord{timestampNs: ts, lenBytes: l} }

	tests := []struct {
		name    string
		windows []windowSample
		pkts    []pktRecord
		// want[i] = {packetSum, packetCount} for window i
		want []windowResult
	}{
		{
			name:    "no windows",
			windows: nil,
			pkts:    []pktRecord{mkPkt(100, 10)},
			want:    nil,
		},
		{
			name:    "no packets",
			windows: []windowSample{mkWin(1000, 500), mkWin(2000, 600)},
			pkts:    nil,
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 500, packetSum: 0, packetCount: 0},
				{windowTs: 2000, deltaBytes: 600, packetSum: 0, packetCount: 0},
			},
		},
		{
			name:    "packets cleanly inside windows",
			windows: []windowSample{mkWin(1000, 100), mkWin(2000, 200), mkWin(3000, 300)},
			pkts: []pktRecord{
				mkPkt(500, 10),  // before any window → window[0]
				mkPkt(900, 30),  // ≤1000 → window[0]
				mkPkt(1500, 50), // 1000 < ts ≤ 2000 → window[1]
				mkPkt(2500, 70), // 2000 < ts ≤ 3000 → window[2]
			},
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 100, packetSum: 40, packetCount: 2},
				{windowTs: 2000, deltaBytes: 200, packetSum: 50, packetCount: 1},
				{windowTs: 3000, deltaBytes: 300, packetSum: 70, packetCount: 1},
			},
		},
		{
			name:    "packet exactly on window boundary goes to that window",
			windows: []windowSample{mkWin(1000, 100), mkWin(2000, 200)},
			pkts:    []pktRecord{mkPkt(1000, 99)},
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 100, packetSum: 99, packetCount: 1},
				{windowTs: 2000, deltaBytes: 200, packetSum: 0, packetCount: 0},
			},
		},
		{
			name:    "packet after last window is dropped",
			windows: []windowSample{mkWin(1000, 100)},
			pkts:    []pktRecord{mkPkt(1001, 50)},
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 100, packetSum: 0, packetCount: 0},
			},
		},
		{
			name:    "out-of-order ringbuf timestamps are handled after sort",
			windows: []windowSample{mkWin(2000, 200), mkWin(1000, 100)}, // unsorted input
			pkts:    []pktRecord{mkPkt(1500, 40), mkPkt(500, 10)},       // unsorted input
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 100, packetSum: 10, packetCount: 1},
				{windowTs: 2000, deltaBytes: 200, packetSum: 40, packetCount: 1},
			},
		},
		{
			name:    "empty window (delta=0, no packets)",
			windows: []windowSample{mkWin(1000, 100), mkWin(2000, 0), mkWin(3000, 50)},
			pkts:    []pktRecord{mkPkt(500, 20), mkPkt(2800, 15)},
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 100, packetSum: 20, packetCount: 1},
				{windowTs: 2000, deltaBytes: 0, packetSum: 0, packetCount: 0},
				{windowTs: 3000, deltaBytes: 50, packetSum: 15, packetCount: 1},
			},
		},
		{
			name:    "multiple packets in same window",
			windows: []windowSample{mkWin(1000, 300)},
			pkts:    []pktRecord{mkPkt(100, 100), mkPkt(200, 100), mkPkt(300, 100)},
			want: []windowResult{
				{windowTs: 1000, deltaBytes: 300, packetSum: 300, packetCount: 3},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bucketPackets(tc.windows, tc.pkts)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d windows, want %d", len(got), len(tc.want))
			}
			for i, g := range got {
				w := tc.want[i]
				if g.windowTs != w.windowTs {
					t.Errorf("window[%d] ts: got %d, want %d", i, g.windowTs, w.windowTs)
				}
				if g.deltaBytes != w.deltaBytes {
					t.Errorf("window[%d] deltaBytes: got %d, want %d", i, g.deltaBytes, w.deltaBytes)
				}
				if g.packetSum != w.packetSum {
					t.Errorf("window[%d] packetSum: got %d, want %d", i, g.packetSum, w.packetSum)
				}
				if g.packetCount != w.packetCount {
					t.Errorf("window[%d] packetCount: got %d, want %d", i, g.packetCount, w.packetCount)
				}
			}
		})
	}
}
