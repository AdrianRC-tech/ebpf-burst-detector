package main

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDeriveSnapshotInterval(t *testing.T) {
	cases := []struct {
		name        string
		flagVal     time.Duration
		effWindowNs uint64
		want        time.Duration
		wantErr     bool
	}{
		{name: "explicit flag wins", flagVal: 50 * time.Millisecond, effWindowNs: 100_000_000, want: 50 * time.Millisecond},
		{name: "falls back to effective window", flagVal: 0, effWindowNs: 100_000_000, want: 100 * time.Millisecond},
		{name: "no flag and zero effective window is an error", flagVal: 0, effWindowNs: 0, wantErr: true},
		{
			name: "default is floored for a small CUSUM window", flagVal: 0, effWindowNs: 5_000_000, // 5ms
			want: 50 * time.Millisecond, // the floor, not the raw 5ms window
		},
		{
			name: "explicit flag below the floor is still honored", flagVal: time.Millisecond, effWindowNs: 100_000_000,
			want: time.Millisecond, // the floor only applies to the derived default, never to an explicit flag
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveSnapshotInterval(tc.flagVal, tc.effWindowNs)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (result %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestComputeRingDepth(t *testing.T) {
	cases := []struct {
		name      string
		retention time.Duration
		interval  time.Duration
		want      int
	}{
		{name: "exact multiple", retention: 6400 * time.Millisecond, interval: 100 * time.Millisecond, want: 64},
		{name: "rounds up", retention: 6400 * time.Millisecond, interval: 25 * time.Millisecond, want: 256},
		{name: "at least 1", retention: 10 * time.Millisecond, interval: time.Second, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computeRingDepth(tc.retention, tc.interval)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// --- fakes shared by the pairing/watchdog tests below ---

type fakeAnomalyReader struct {
	parseAnomaly, lruSaturated uint64
}

func (f *fakeAnomalyReader) read() (uint64, uint64, error) {
	return f.parseAnomaly, f.lruSaturated, nil
}

type fakeRecordWriter struct {
	records []attributionRecord
}

func (f *fakeRecordWriter) write(rec attributionRecord) error {
	f.records = append(f.records, rec)
	return nil
}

type fakeClock struct{ nowNs uint64 }

func (c *fakeClock) now() uint64 { return c.nowNs }

func newTestAttributionState(reader flowStatsReader, clock *fakeClock, anomalies *fakeAnomalyReader, writer *fakeRecordWriter) *attributionState {
	return &attributionState{
		ring:      newFlowRing(reader, 64),
		anomalies: anomalies,
		topN:      10,
		writer:    writer,
		logger:    discardLogger(),
		now:       clock.now,
	}
}

func onsetEvent(changePointNs uint64) BurstEvent {
	return BurstEvent{Type: EventOnset, ChangePointNs: changePointNs}
}

func drainEvent(changePointNs uint64) BurstEvent {
	return BurstEvent{Type: EventDrain, ChangePointNs: changePointNs}
}

func TestAttributionStatePairsOnsetAndDrain(t *testing.T) {
	f := fk(1, 100, 1111, 80)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 100_000, Skbs: 100, FirstSeenNs: 1}}}}, // seed poll @0ns
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 200_000, Skbs: 200, FirstSeenNs: 1}}}}, // s0 poll @1s (onset)
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 500_000, Skbs: 500, FirstSeenNs: 1}}}}, // s1 poll @2s (drain, fresh sync)
	}}
	clock := &fakeClock{}
	anomalies := &fakeAnomalyReader{parseAnomaly: 5, lruSaturated: 1}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, anomalies, writer)

	// Baseline history: a poll at t=0.
	clock.nowNs = 0
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}
	// A poll at t=1s establishes the ring slot the onset's change point will
	// resolve to via at().
	clock.nowNs = 1_000_000_000
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("onset-time poll: %v", err)
	}

	s.onEvent(onsetEvent(1_000_000_000))

	clock.nowNs = 2_000_000_000
	anomalies.parseAnomaly = 8
	anomalies.lruSaturated = 3
	s.onEvent(drainEvent(1_500_000_000))

	if len(writer.records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(writer.records))
	}
	rec := writer.records[0]
	if rec.Unpaired {
		t.Error("Unpaired = true, want false")
	}
	if rec.ParseAnomalyDelta != 3 {
		t.Errorf("ParseAnomalyDelta = %d, want 3 (8-5)", rec.ParseAnomalyDelta)
	}
	if rec.LruSaturatedDelta != 2 {
		t.Errorf("LruSaturatedDelta = %d, want 2 (3-1)", rec.LruSaturatedDelta)
	}
	if rec.Truncated {
		t.Error("Truncated = true, want false (onset change point is within the ring)")
	}
	if len(rec.Contributors) != 1 {
		t.Fatalf("len(Contributors) = %d, want 1", len(rec.Contributors))
	}
	// burst = s1(500,000) - s0(200,000) = 300,000, the only flow.
	c := rec.Contributors[0]
	if c.Bytes != 300_000 {
		t.Errorf("Contributors[0].Bytes = %d, want 300000", c.Bytes)
	}
	if c.Bytes != rec.TotalBytes || rec.TotalBytes != 300_000 {
		t.Errorf("Bytes = %d TotalBytes = %d, want both 300000", c.Bytes, rec.TotalBytes)
	}
}

// TestAttributionStateEmitFallsBackToOldestSlotAndSetsTruncated covers the
// spec §5 truncation path end-to-end through onEvent/emit: when the onset's
// change point precedes every retained ring slot, s0 falls back to the
// oldest retained slot (rather than dropping the record) and Truncated is
// set so a consumer knows the measurement window was cut short.
func TestAttributionStateEmitFallsBackToOldestSlotAndSetsTruncated(t *testing.T) {
	f := fk(1, 100, 1, 2)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 1000, Skbs: 1, FirstSeenNs: 1}}}}, // oldest retained slot @1000
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 2000, Skbs: 2, FirstSeenNs: 1}}}}, // fresh drain-time poll @2000
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)
	s.ring = newFlowRing(reader, 2) // depth 2: both @1000 and the fresh @2000 poll are retained

	clock.nowNs = 1000
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}

	// Onset change point (500) precedes every retained slot (oldest is
	// 1000): at(500) must fail, forcing the oldest()-slot fallback.
	s.onEvent(onsetEvent(500))

	clock.nowNs = 2000
	s.onEvent(drainEvent(1500))

	if len(writer.records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(writer.records))
	}
	rec := writer.records[0]
	if !rec.Truncated {
		t.Error("Truncated = false, want true (onset change point precedes the oldest retained slot)")
	}
}

// TestAttributionStateEmitSerializesWriterAccess covers a code-review
// finding: attributionState's doc comment promises "safe for concurrent
// use", but nothing serialized the actual writer.write call — a real drain
// (via onEvent) and a watchdog firing for a different, subsequent onset can
// both reach emit and therefore write concurrently. Run under `go test
// -race`: an unsynchronized fakeRecordWriter.write (a plain slice append)
// would be flagged as a data race without a fix serializing the calls.
func TestAttributionStateEmitSerializesWriterAccess(t *testing.T) {
	f := fk(1, 100, 1, 2)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 1}}}},
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)

	clock.nowNs = 1000
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := &pendingOnset{ev: onsetEvent(1000)}
			s.emit(p, drainEvent(1000), 1000, false)
		}(i)
	}
	wg.Wait()

	if len(writer.records) != 20 {
		t.Fatalf("len(records) = %d, want 20 (one per concurrent emit)", len(writer.records))
	}
}

func TestAttributionStateDrainWithNoPendingOnsetIsIgnored(t *testing.T) {
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: fk(1, 100, 1, 2), cpuValues: []cusumFlowStat{{Bytes: 1, Skbs: 1, FirstSeenNs: 1}}}},
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)

	s.onEvent(drainEvent(1)) // no prior onset

	if len(writer.records) != 0 {
		t.Fatalf("len(records) = %d, want 0 (drain with no pending onset)", len(writer.records))
	}
}

func TestAttributionStateWatchdogEmitsUnpairedAndIgnoresLateDrain(t *testing.T) {
	f := fk(1, 100, 1, 2)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 1}}}},
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 200, Skbs: 2, FirstSeenNs: 1}}}},
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 300, Skbs: 3, FirstSeenNs: 1}}}}, // watchdog's fresh snapshot
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)

	clock.nowNs = 0
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}
	clock.nowNs = 1_000_000_000
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("onset-time poll: %v", err)
	}

	s.onEvent(onsetEvent(1_000_000_000))

	timeout := 500 * time.Millisecond
	clock.nowNs = 1_000_000_000 + uint64(timeout) // exactly at the timeout: due
	s.checkWatchdog(timeout)

	if len(writer.records) != 1 {
		t.Fatalf("len(records) = %d, want 1 (watchdog-emitted unpaired record)", len(writer.records))
	}
	if !writer.records[0].Unpaired {
		t.Error("Unpaired = false, want true")
	}

	// A late real drain for the same (now-cleared) onset must be ignored.
	s.onEvent(drainEvent(1_100_000_000))
	if len(writer.records) != 1 {
		t.Fatalf("len(records) = %d after late drain, want still 1", len(writer.records))
	}
}

func TestAttributionStateWatchdogDoesNothingBeforeTimeout(t *testing.T) {
	f := fk(1, 100, 1, 2)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 1}}}},
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)

	clock.nowNs = 1_000_000_000
	s.onEvent(onsetEvent(1_000_000_000))

	timeout := 500 * time.Millisecond
	clock.nowNs = 1_000_000_000 + uint64(timeout) - 1 // just under the timeout
	s.checkWatchdog(timeout)

	if len(writer.records) != 0 {
		t.Fatalf("len(records) = %d, want 0 (timeout not yet reached)", len(writer.records))
	}
}

type fakeServiceResolver map[string]string

func (f fakeServiceResolver) resolve(ip string) string { return f[ip] }

// TestAttributionStateEmitLabelsServices: emit fills src/dst_service from the
// resolver; an unresolvable IP leaves the field empty rather than failing.
func TestAttributionStateEmitLabelsServices(t *testing.T) {
	f := fk(1, 2, 1111, 80)
	reader := &fakeFlowStatsReader{calls: [][]struct {
		key       cusumFlowKey
		cpuValues []cusumFlowStat
	}{
		{{key: f, cpuValues: []cusumFlowStat{{Bytes: 100, Skbs: 1, FirstSeenNs: 1}}}},
	}}
	clock := &fakeClock{}
	writer := &fakeRecordWriter{}
	s := newTestAttributionState(reader, clock, &fakeAnomalyReader{}, writer)
	s.resolver = fakeServiceResolver{"1.0.0.0": "default/frontend"} // dst 2.0.0.0 unknown

	clock.nowNs = 1000
	if err := s.ring.poll(clock.now()); err != nil {
		t.Fatalf("seed poll: %v", err)
	}
	s.emit(&pendingOnset{ev: onsetEvent(1000)}, drainEvent(1000), 1000, false)

	c := writer.records[0].Contributors[0]
	if c.SrcService != "default/frontend" || c.DstService != "" {
		t.Errorf("services = %q / %q, want default/frontend / empty", c.SrcService, c.DstService)
	}
}
