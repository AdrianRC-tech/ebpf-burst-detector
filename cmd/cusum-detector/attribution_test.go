package main

import (
	"strconv"
	"testing"
)

func mkSnapshot(stampNs uint64, entries map[bpfFlowKey]flowVal) snapshot {
	index := make(map[bpfFlowKey]int32, len(entries))
	values := make([]flowVal, len(entries))
	var i int32
	for k, v := range entries {
		index[k] = i
		values[i] = v
		i++
	}
	return snapshot{stampNs: stampNs, index: index, values: values}
}

func fk(srcIP, dstIP uint32, srcPort, dstPort uint16) bpfFlowKey {
	return bpfFlowKey{SrcIp: srcIP, DstIp: dstIP, SrcPort: srcPort, DstPort: dstPort, Proto: 6}
}

// TestScoreRanksByBytesAndShares: contributors are one per flow, ordered by
// burst bytes, with total_bytes the sum over all flows.
// untruncated.
func TestScoreRanksByBytesAndShares(t *testing.T) {
	small := fk(1, 100, 1111, 80)
	big := fk(2, 100, 2222, 80)
	mid := fk(3, 100, 3333, 80)

	s0 := mkSnapshot(0, map[bpfFlowKey]flowVal{
		small: {bytes: 10, skbs: 1, firstSeen: 1},
		big:   {bytes: 10, skbs: 1, firstSeen: 1},
		mid:   {bytes: 10, skbs: 1, firstSeen: 1},
	})
	s1 := mkSnapshot(1_000_000_000, map[bpfFlowKey]flowVal{
		small: {bytes: 110, skbs: 11, firstSeen: 1}, // +100
		big:   {bytes: 710, skbs: 71, firstSeen: 1}, // +700
		mid:   {bytes: 210, skbs: 21, firstSeen: 1}, // +200
	})

	rec := score(s0, s1, 10)

	if rec.TotalBytes != 1000 || rec.Flows != 3 {
		t.Fatalf("TotalBytes=%d Flows=%d, want 1000/3", rec.TotalBytes, rec.Flows)
	}
	wantBytes := []uint64{700, 200, 100}
	if len(rec.Contributors) != 3 {
		t.Fatalf("len(Contributors) = %d, want 3", len(rec.Contributors))
	}
	var sum uint64
	for i, c := range rec.Contributors {
		if c.Bytes != wantBytes[i] {
			t.Errorf("Contributors[%d].Bytes = %d, want %d", i, c.Bytes, wantBytes[i])
		}
		sum += c.Bytes
	}
	if sum != rec.TotalBytes {
		t.Errorf("sum(Bytes)=%d, want TotalBytes %d", sum, rec.TotalBytes)
	}
	if got := rec.Contributors[0].Src; got != "2.0.0.0:"+itoa(portHost(2222)) {
		t.Errorf("Contributors[0].Src = %s", got)
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

// TestScoreHeaviestFlowNeverDroppedByTopN is the regression for the
// 10.0.2.176 burst: six flows from one source, one idle and one a busy pool
// connection. With a baseline-relative ranking the heavy flow was hidden by
// the cap; ranked by bytes it is always first and a lighter flow is never
// kept in its place.
func TestScoreHeaviestFlowNeverDroppedByTopN(t *testing.T) {
	src := uint32(176)
	flows := make([]bpfFlowKey, 6)
	s0m := map[bpfFlowKey]flowVal{}
	s1m := map[bpfFlowKey]flowVal{}
	delta := []uint64{0, 5_000, 536_000, 20_000, 1_000, 226_000}
	for i := range flows {
		flows[i] = fk(src, 100, uint16(1000+i), 11211)
		s0m[flows[i]] = flowVal{bytes: 1_000_000, skbs: 1000, firstSeen: 1}
		s1m[flows[i]] = flowVal{bytes: 1_000_000 + delta[i], skbs: 1000 + delta[i]/1000, firstSeen: 1}
	}
	rec := score(mkSnapshot(0, s0m), mkSnapshot(1, s1m), 3)

	if len(rec.Contributors) != 3 {
		t.Fatalf("len(Contributors) = %d, want 3", len(rec.Contributors))
	}
	want := []uint64{536_000, 226_000, 20_000}
	for i, w := range want {
		if rec.Contributors[i].Bytes != w {
			t.Errorf("Contributors[%d].Bytes = %d, want %d", i, rec.Contributors[i].Bytes, w)
		}
	}
	if rec.Flows != 6 {
		t.Errorf("Flows = %d, want 6 (topN must not shrink the flow count)", rec.Flows)
	}
	var listed uint64
	for _, c := range rec.Contributors {
		listed += c.Bytes
	}
	if listed >= rec.TotalBytes {
		t.Errorf("listed bytes %d should be below TotalBytes %d when the cap hides flows", listed, rec.TotalBytes)
	}
}

// TestScoreTieBreakIsDeterministic: equal bytes order by skbs desc, then
// src, then dst.
func TestScoreTieBreakIsDeterministic(t *testing.T) {
	a := fk(1, 100, 1, 80)
	b := fk(2, 100, 1, 80)
	c := fk(3, 100, 1, 80)
	s0 := mkSnapshot(0, map[bpfFlowKey]flowVal{})
	s1 := mkSnapshot(1, map[bpfFlowKey]flowVal{
		a: {bytes: 100, skbs: 1, firstSeen: 1},
		b: {bytes: 100, skbs: 5, firstSeen: 1},
		c: {bytes: 100, skbs: 5, firstSeen: 1},
	})
	for i := 0; i < 20; i++ {
		rec := score(s0, s1, 10)
		got := []string{rec.Contributors[0].Src, rec.Contributors[1].Src, rec.Contributors[2].Src}
		if got[0][:2] != "2." || got[1][:2] != "3." || got[2][:2] != "1." {
			t.Fatalf("order = %v, want srcs 2,3,1", got)
		}
	}
}

// TestScoreDetectsResetByValueDecrease: an LRU evict-then-recreate where the
// new incarnation's byte count is lower than the old one must be treated as
// a fresh flow (raw s1 value), not a negative delta.
func TestScoreDetectsResetByValueDecrease(t *testing.T) {
	f := fk(1, 100, 1111, 80)
	s0 := mkSnapshot(1_000_000_000, map[bpfFlowKey]flowVal{f: {bytes: 900_000, skbs: 900, firstSeen: 1}})
	s1 := mkSnapshot(2_000_000_000, map[bpfFlowKey]flowVal{f: {bytes: 500, skbs: 5, firstSeen: 1}})

	rec := score(s0, s1, 10)

	if len(rec.Contributors) != 1 {
		t.Fatalf("len(Contributors) = %d, want 1", len(rec.Contributors))
	}
	if rec.Contributors[0].Bytes != 500 {
		t.Errorf("Bytes = %d, want 500 (raw s1 value via reset guard)", rec.Contributors[0].Bytes)
	}
}

// TestScoreDetectsResetByFirstSeenChange: a same-or-higher byte count can
// still be a reset if first_seen_ns changed.
func TestScoreDetectsResetByFirstSeenChange(t *testing.T) {
	f := fk(1, 100, 1111, 80)
	s0 := mkSnapshot(1_000_000_000, map[bpfFlowKey]flowVal{f: {bytes: 900_000, skbs: 900, firstSeen: 1}})
	s1 := mkSnapshot(2_000_000_000, map[bpfFlowKey]flowVal{f: {bytes: 1_000_100, skbs: 5, firstSeen: 2_000_000_000}})

	rec := score(s0, s1, 10)

	if len(rec.Contributors) != 1 {
		t.Fatalf("len(Contributors) = %d, want 1", len(rec.Contributors))
	}
	if rec.Contributors[0].Bytes != 1_000_100 {
		t.Errorf("Bytes = %d, want 1000100 (raw s1 value via first_seen reset guard, not the 100 naive diff)",
			rec.Contributors[0].Bytes)
	}
}

// TestScoreHandlesEvictedFlow: a flow present in s0 but gone from s1 counts
// toward evicted_flows and contributes nothing.
func TestScoreHandlesEvictedFlow(t *testing.T) {
	survivor := fk(1, 100, 1111, 80)
	evicted := fk(2, 100, 2222, 80)

	s0 := mkSnapshot(1_000_000_000, map[bpfFlowKey]flowVal{
		survivor: {bytes: 100, skbs: 1, firstSeen: 1},
		evicted:  {bytes: 200, skbs: 2, firstSeen: 1},
	})
	s1 := mkSnapshot(2_000_000_000, map[bpfFlowKey]flowVal{
		survivor: {bytes: 300, skbs: 3, firstSeen: 1},
	})

	rec := score(s0, s1, 10)

	if rec.EvictedFlows != 1 {
		t.Errorf("EvictedFlows = %d, want 1", rec.EvictedFlows)
	}
	if len(rec.Contributors) != 1 {
		t.Fatalf("len(Contributors) = %d, want 1 (only the survivor)", len(rec.Contributors))
	}
}

// TestScoreNewFlowCountsFully: a flow absent from s0 contributes its whole
// byte count.
func TestScoreNewFlowCountsFully(t *testing.T) {
	f := fk(1, 100, 1111, 80)
	s0 := mkSnapshot(0, map[bpfFlowKey]flowVal{})
	s1 := mkSnapshot(1, map[bpfFlowKey]flowVal{f: {bytes: 1234, skbs: 2, firstSeen: 1}})

	rec := score(s0, s1, 10)

	if rec.Contributors[0].Bytes != 1234 || rec.Contributors[0].BytesPerSkb != 617 {
		t.Errorf("got %+v, want bytes 1234, bytes_per_skb 617", rec.Contributors[0])
	}
}

func TestScoreRespectsTopN(t *testing.T) {
	a := fk(1, 100, 1111, 80)
	b := fk(2, 100, 2222, 80)
	s0 := mkSnapshot(0, map[bpfFlowKey]flowVal{})
	s1 := mkSnapshot(1, map[bpfFlowKey]flowVal{
		a: {bytes: 100, skbs: 1, firstSeen: 1},
		b: {bytes: 300, skbs: 3, firstSeen: 1},
	})

	rec := score(s0, s1, 1)

	if len(rec.Contributors) != 1 || rec.Contributors[0].Bytes != 300 {
		t.Fatalf("Contributors = %+v, want just the 300-byte flow", rec.Contributors)
	}
	if rec.Flows != 2 || rec.TotalBytes != 400 {
		t.Errorf("Flows=%d TotalBytes=%d, want 2/400 (uncapped)", rec.Flows, rec.TotalBytes)
	}
}

func TestScoreContributorCarriesTuple(t *testing.T) {
	k := bpfFlowKey{SrcIp: 1, DstIp: 2, SrcPort: 0x5000, DstPort: 0x5000, Proto: 6}
	s1 := mkSnapshot(1, map[bpfFlowKey]flowVal{k: {bytes: 10, skbs: 1, firstSeen: 1}})
	rec := score(mkSnapshot(0, map[bpfFlowKey]flowVal{}), s1, 10)
	c := rec.Contributors[0]
	if c.Src != endpointString(1, 0x5000) || c.Dst != endpointString(2, 0x5000) || c.Proto != "tcp" {
		t.Errorf("contributor = %+v", c)
	}
}
