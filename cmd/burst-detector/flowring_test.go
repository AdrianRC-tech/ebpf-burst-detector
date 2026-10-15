package main

import "testing"

func mustPoll(t *testing.T, r *flowRing, stampNs uint64, reader flowStatsReader) {
	t.Helper()
	r.reader = reader
	if err := r.poll(stampNs); err != nil {
		t.Fatalf("poll(%d): %v", stampNs, err)
	}
}

// fakeFlowStatsReader is a scripted flowStatsReader: each call to readAll
// returns the next entry in calls, so a test can drive the ring through a
// sequence of BPF map states without any real BPF.
type fakeFlowStatsReader struct {
	calls [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}
	i int
}

func (f *fakeFlowStatsReader) readAll() ([]cusumFlowKey, []cusumFlowStat, int, error) {
	if f.i >= len(f.calls) {
		f.i = len(f.calls) - 1 // repeat the last state if over-polled
	}
	entries := f.calls[f.i]
	f.i++

	possibleCPU := 1
	for _, e := range entries {
		if len(e.cpuValues) > possibleCPU {
			possibleCPU = len(e.cpuValues)
		}
	}

	keys := make([]cusumFlowKey, len(entries))
	values := make([]cusumFlowStat, len(entries)*possibleCPU)
	for i, e := range entries {
		keys[i] = e.key
		copy(values[i*possibleCPU:(i+1)*possibleCPU], e.cpuValues)
	}
	return keys, values, possibleCPU, nil
}

func key(srcIP uint32) cusumFlowKey {
	return cusumFlowKey{SrcIp: srcIP, DstIp: 1, SrcPort: 1, DstPort: 2, Proto: 6}
}

func TestFlowRingAtReturnsNewestSlotAtOrBeforeT(t *testing.T) {
	r := newFlowRing(nil, 4)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 10}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 200, Skbs: 2, FirstSeenNs: 10}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 300, Skbs: 3, FirstSeenNs: 10}}}},
	}}

	mustPoll(t, r, 100, reader)
	mustPoll(t, r, 200, reader)
	mustPoll(t, r, 300, reader)

	// Exactly at a slot's stamp.
	snap, ok := r.at(200)
	if !ok {
		t.Fatal("at(200): ok = false, want true")
	}
	if snap.stampNs != 200 {
		t.Errorf("at(200): stampNs = %d, want 200", snap.stampNs)
	}
	v, ok := snap.value(key(1))
	if !ok || v.bytes != 200 {
		t.Errorf("at(200): value = %+v, ok = %v, want bytes=200", v, ok)
	}

	// Between two slots: newest slot with stamp <= t.
	snap, ok = r.at(250)
	if !ok || snap.stampNs != 200 {
		t.Errorf("at(250): stampNs = %d, ok = %v, want 200, true", snap.stampNs, ok)
	}

	// After the newest slot: still returns the newest slot.
	snap, ok = r.at(1000)
	if !ok || snap.stampNs != 300 {
		t.Errorf("at(1000): stampNs = %d, ok = %v, want 300, true", snap.stampNs, ok)
	}

	// Before the oldest slot: truncated, ok = false.
	_, ok = r.at(50)
	if ok {
		t.Error("at(50): ok = true, want false (older than oldest retained slot)")
	}
}

// TestFlowRingKeepsSlotsSortedUnderOutOfOrderPolls reproduces a code-review
// finding: production callers read "now" before calling poll, which
// acquires the ring's mutex — two nearly-simultaneous callers can be
// granted the lock in an order that doesn't match which one read the later
// timestamp. If poll just appended, the resulting slots would not be sorted
// by stamp, and at()'s linear scan (which assumes ascending order and
// breaks at the first newer stamp) can then return stale data instead of an
// exact match — in the worst case, silently collapsing a fresh synchronous
// drain-time snapshot onto an older one (spec correction 5's whole point).
func TestFlowRingKeepsSlotsSortedUnderOutOfOrderPolls(t *testing.T) {
	r := newFlowRing(&fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 1}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 201, Skbs: 1, FirstSeenNs: 1}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 200, Skbs: 1, FirstSeenNs: 1}}}},
	}}, 4)

	if err := r.poll(100); err != nil {
		t.Fatalf("poll(100): %v", err)
	}
	// "201" is appended before "200" — simulates the lock-race reordering.
	if err := r.poll(201); err != nil {
		t.Fatalf("poll(201): %v", err)
	}
	if err := r.poll(200); err != nil {
		t.Fatalf("poll(200): %v", err)
	}

	snap, ok := r.at(200)
	if !ok {
		t.Fatal("at(200): ok = false")
	}
	if snap.stampNs != 200 {
		t.Errorf("at(200): stampNs = %d, want an exact match at 200, not the out-of-order 201 slot", snap.stampNs)
	}
	if v, ok := snap.value(key(1)); !ok || v.bytes != 200 {
		t.Errorf("at(200): value = %+v, ok=%v, want bytes=200", v, ok)
	}

	snap, ok = r.at(201)
	if !ok || snap.stampNs != 201 {
		t.Errorf("at(201): stampNs = %d, ok=%v, want 201", snap.stampNs, ok)
	}
}

func TestFlowRingWraparoundDropsOldestSlot(t *testing.T) {
	r := newFlowRing(nil, 2) // depth 2
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 10}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 200, Skbs: 2, FirstSeenNs: 10}}}},
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 300, Skbs: 3, FirstSeenNs: 10}}}},
	}}

	mustPoll(t, r, 100, reader) // slot at 100
	mustPoll(t, r, 200, reader) // slot at 200; ring now full (depth 2)
	mustPoll(t, r, 300, reader) // slot at 300; should evict the slot at 100

	if _, ok := r.at(100); ok {
		t.Error("at(100): ok = true, want false — slot at 100 should have been evicted")
	}
	snap, ok := r.at(200)
	if !ok || snap.stampNs != 200 {
		t.Errorf("at(200): stampNs = %d, ok = %v, want 200, true", snap.stampNs, ok)
	}
	snap, ok = r.at(300)
	if !ok || snap.stampNs != 300 {
		t.Errorf("at(300): stampNs = %d, ok = %v, want 300, true", snap.stampNs, ok)
	}
}

func TestSumFlowValueAcrossCPUsTakesMinNonZeroFirstSeen(t *testing.T) {
	cases := []struct {
		name   string
		values []cusumFlowStat
		want   flowVal
	}{
		{
			name: "single cpu",
			values: []cusumFlowStat{
				{Bytes: 100, Skbs: 1, FirstSeenNs: 500},
			},
			want: flowVal{bytes: 100, skbs: 1, firstSeen: 500},
		},
		{
			name: "insert cpu has lower first_seen than a later-contributing cpu",
			values: []cusumFlowStat{
				{Bytes: 100, Skbs: 1, FirstSeenNs: 500}, // the CPU that ran BPF_NOEXIST
				{Bytes: 50, Skbs: 1, FirstSeenNs: 0},    // -EEXIST fallback: bytes added, first_seen stays 0
			},
			want: flowVal{bytes: 150, skbs: 2, firstSeen: 500},
		},
		{
			name: "all cpus zero",
			values: []cusumFlowStat{
				{Bytes: 0, Skbs: 0, FirstSeenNs: 0},
				{Bytes: 0, Skbs: 0, FirstSeenNs: 0},
			},
			want: flowVal{},
		},
		{
			name: "min across two nonzero first_seen values",
			values: []cusumFlowStat{
				{Bytes: 10, Skbs: 1, FirstSeenNs: 900},
				{Bytes: 20, Skbs: 1, FirstSeenNs: 300},
			},
			want: flowVal{bytes: 30, skbs: 2, firstSeen: 300},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sumFlowValueAcrossCPUs(tc.values)
			if got != tc.want {
				t.Errorf("sumFlowValueAcrossCPUs(%+v) = %+v, want %+v", tc.values, got, tc.want)
			}
		})
	}
}

// TestFlowRingCompactionKeepsLiveValuesIntact drives the ring through an
// actual compaction (not merely a state where a dead key's value happens to
// read as zero because it was never written into the newest slot — that
// was a code-review finding: with depth 3 and only 3 polls, the slot from
// poll 1 (which still has keys 2/3) is still retained, so dead=0 and
// compaction never fires; the test passed anyway because slot 3 simply
// never wrote keys 2/3 into it). A 4th poll evicts that first slot, which
// is what actually makes keys 2/3 dead in every retained slot.
func TestFlowRingCompactionKeepsLiveValuesIntact(t *testing.T) {
	r := newFlowRing(nil, 3) // depth 3

	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{ // poll @100: keys 1,2,3 all present
			{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 10, Skbs: 1, FirstSeenNs: 1}}},
			{key: key(2), cpuValues: []cusumFlowStat{{Bytes: 20, Skbs: 1, FirstSeenNs: 1}}},
			{key: key(3), cpuValues: []cusumFlowStat{{Bytes: 30, Skbs: 1, FirstSeenNs: 1}}},
		},
		{ // poll @200: only key 1 (2,3 evicted from the BPF map / never seen again)
			{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 11, Skbs: 2, FirstSeenNs: 1}}},
		},
		{ // poll @300: only key 1 — the slot@100 is still retained here (depth 3),
			// so keys 2/3 are still "live" in it; compaction must NOT fire yet.
			{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 12, Skbs: 3, FirstSeenNs: 1}}},
		},
		{ // poll @400: only key 1 — this evicts slot@100, so keys 2/3 are now dead
			// in every retained slot (200,300,400); compaction fires here.
			{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 13, Skbs: 4, FirstSeenNs: 1}}},
		},
	}}

	mustPoll(t, r, 100, reader)
	mustPoll(t, r, 200, reader)
	mustPoll(t, r, 300, reader)

	if r.nextIdx != 3 {
		t.Fatalf("nextIdx before the compacting poll = %d, want 3 (compaction must not have fired yet)", r.nextIdx)
	}

	// A snapshot taken before compaction must keep reading correctly after
	// the ring's own index/slots are replaced underneath it — this is the
	// concurrency invariant the whole copy-on-grow/copy-on-compact design
	// exists for (a caller holding this snapshot released the ring's mutex
	// before the next poll could run).
	preCompactionSnap, ok := r.at(300)
	if !ok {
		t.Fatal("at(300) before compaction: ok = false")
	}

	mustPoll(t, r, 400, reader) // evicts slot@100 -> triggers compaction

	if r.nextIdx != 1 {
		t.Fatalf("nextIdx after compaction = %d, want 1 (only key(1) survives)", r.nextIdx)
	}

	if v, ok := preCompactionSnap.value(key(1)); !ok || v.bytes != 12 || v.skbs != 3 {
		t.Errorf("pre-compaction snapshot's key(1), read after the ring compacted: value = %+v, ok = %v, want bytes=12 skbs=3",
			v, ok)
	}

	snap, ok := r.at(400)
	if !ok {
		t.Fatal("at(400) after compaction: ok = false")
	}
	if v, ok := snap.value(key(1)); !ok || v.bytes != 13 || v.skbs != 4 {
		t.Errorf("key(1) after compaction: value = %+v, ok = %v, want bytes=13 skbs=4", v, ok)
	}
	if _, ok := snap.value(key(2)); ok {
		t.Error("key(2) should be gone after compaction (dead in every retained slot)")
	}
	if _, ok := snap.value(key(3)); ok {
		t.Error("key(3) should be gone after compaction (dead in every retained slot)")
	}

	// The oldest retained slot (200) must also still resolve key(1) correctly
	// after compaction rewrote its value array.
	snap, ok = r.at(200)
	if !ok {
		t.Fatal("at(200): ok = false")
	}
	if v, ok := snap.value(key(1)); !ok || v.bytes != 11 || v.skbs != 2 {
		t.Errorf("key(1) at slot 200 after compaction: value = %+v, ok = %v, want bytes=11 skbs=2", v, ok)
	}
}

func TestFlowRingAbsentKeyIsNotOK(t *testing.T) {
	r := newFlowRing(nil, 4)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: key(1), cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 10}}}},
	}}
	mustPoll(t, r, 100, reader)

	snap, ok := r.at(100)
	if !ok {
		t.Fatal("at(100): ok = false")
	}
	if _, ok := snap.value(key(99)); ok {
		t.Error("value(key never seen): ok = true, want false")
	}
}
