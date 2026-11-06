package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/bits"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// attributionRecord is one NDJSON record per burst, listing the flows that
// carried the most burst-window bytes. score fills in the snapshot-derived
// fields (TotalBytes/Flows/EvictedFlows/Contributors); the
// event-derived fields (onset/drain change points as _utc
// strings, Truncated, Unpaired) are set by
// the caller in main.go, which has the BurstEvent pair that score has no
// access to. Service names on the
// contributors are filled in by emit via the serviceResolver.
type attributionRecord struct {
	OnsetChangePointUTC string `json:"onset_change_point_utc,omitempty"`
	DrainChangePointUTC string `json:"drain_change_point_utc,omitempty"`

	// TotalBytes is the burst-window byte sum over every flow (not just the
	// listed contributors).
	TotalBytes uint64 `json:"total_bytes"`
	Flows      int    `json:"flows"`

	Truncated    bool `json:"truncated"`
	Unpaired     bool `json:"unpaired"`
	EvictedFlows int  `json:"evicted_flows"`

	// SnapshotsUsed are the stamps of the snapshots that bounded the window
	// (s0 and s1), same format as the change points. Omitted without a
	// wall-clock anchor.
	SnapshotsUsed *snapshotsUsed `json:"timestamp_snapshots_used,omitempty"`

	Contributors []contributor `json:"contributors"`
}

type snapshotsUsed struct {
	StartUTC string `json:"start_utc"`
	EndUTC   string `json:"end_utc"`
}

// contributor is one flow's burst-window contribution, identified by its
// src_ip:port -> dst_ip:port (proto) tuple. Flows are ranked by bytes, not
// by any baseline-relative excess: 5-tuples are ephemeral under connection
// pooling, so a per-key "recent past" is not a meaningful reference.
type contributor struct {
	Src         string  `json:"src"`
	Dst         string  `json:"dst"`
	Proto       string  `json:"proto"`
	SrcService  string  `json:"src_service,omitempty"`
	DstService  string  `json:"dst_service,omitempty"`
	Bytes       uint64  `json:"bytes"`
	Skbs        uint64  `json:"skbs"`
	BytesPerSkb float64 `json:"bytes_per_skb"`
}

// portHost converts a flow_key port (a __be16 read back as a plain Go
// uint16 with no byte-swap, like ipString's input) to host order.
func portHost(raw uint16) uint16 { return bits.ReverseBytes16(raw) }

func protoString(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	}
	return strconv.Itoa(int(p))
}

func endpointString(ip uint32, rawPort uint16) string {
	return net.JoinHostPort(ipString(ip), strconv.Itoa(int(portHost(rawPort))))
}

// ipString renders a flow_key's raw src_ip/dst_ip field (a __be32 read back
// as a plain Go uint32 with no byte-swap — see rawIPv4 in bpf_test.go) as a
// dotted-decimal address. It is the exact inverse of that raw encoding.
func ipString(raw uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], raw)
	return net.IP(b[:]).String()
}

// flowDelta is one flow's reset-guarded delta between two snapshots: bytes
// and skbs the flow gained, and whether a reset (LRU evict-then-recreate)
// was detected, in which case delta is the raw newer value rather than a
// diff. present is false when the flow does not exist in the newer snapshot
// at all.
type flowDelta struct {
	bytes   uint64
	skbs    uint64
	reset   bool
	present bool
}

// deltaBetween computes flowDelta for one flow between an older (from) and
// newer (to) snapshot value. from, fromOK describe the flow's state in the
// older snapshot (fromOK=false means absent there).
func deltaBetween(from flowVal, fromOK bool, to flowVal) flowDelta {
	if !fromOK || to.bytes < from.bytes || (fromOK && to.firstSeen != from.firstSeen) {
		return flowDelta{bytes: to.bytes, skbs: to.skbs, reset: true, present: true}
	}
	return flowDelta{bytes: to.bytes - from.bytes, skbs: to.skbs - from.skbs, present: true}
}

// score builds an attributionRecord listing the flows that carried the
// burst, ranked by burst-window bytes (s0 to s1, each flow reset-guarded by
// deltaBetween). topN caps Contributors; TotalBytes/Flows always reflect
// every flow seen, uncapped. Ties break on skbs (desc), then src, dst.
func score(s0, s1 snapshot, topN int) attributionRecord {
	evictedFlows := 0
	s0.all(func(key cusumFlowKey, _ flowVal) {
		if _, ok := s1.value(key); !ok {
			evictedFlows++
		}
	})

	var totalBytes uint64
	contributors := make([]contributor, 0, 64)
	s1.all(func(key cusumFlowKey, v1 flowVal) {
		v0, v0OK := s0.value(key)
		burst := deltaBetween(v0, v0OK, v1)
		totalBytes += burst.bytes

		var bytesPerSkb float64
		if burst.skbs > 0 {
			bytesPerSkb = float64(burst.bytes) / float64(burst.skbs)
		}
		contributors = append(contributors, contributor{
			Src:         endpointString(key.SrcIp, key.SrcPort),
			Dst:         endpointString(key.DstIp, key.DstPort),
			Proto:       protoString(key.Proto),
			Bytes:       burst.bytes,
			Skbs:        burst.skbs,
			BytesPerSkb: bytesPerSkb,
		})
	})
	totalFlows := len(contributors)

	sort.Slice(contributors, func(i, j int) bool {
		a, b := contributors[i], contributors[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		if a.Skbs != b.Skbs {
			return a.Skbs > b.Skbs
		}
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		return a.Dst < b.Dst
	})
	if topN >= 0 && len(contributors) > topN {
		contributors = contributors[:topN]
	}

	return attributionRecord{
		TotalBytes:   totalBytes,
		Flows:        totalFlows,
		EvictedFlows: evictedFlows,
		Contributors: contributors,
	}
}

// minDefaultSnapshotInterval floors the *default* (CUSUM-window-derived)
// snapshot interval. The ring's memory is O(depth x distinct flows), and
// depth = ring-retention / interval — at this project's smaller CUSUM
// windows (5-25ms, used in tmp/6.layer_1_validations), that default would
// otherwise put depth in the hundreds and the ring's memory in the hundreds
// of MB per node. score reads each snapshot's actual stamp, never the nominal
// interval, so a coarser default poll cadence than the CUSUM window doesn't
// corrupt the math — only the ring's temporal resolution. An explicit
// --snapshot-interval always wins over this floor, but memory needs
// attention: 10ms with the default 3s retention holds 300 slots, not 60.
const minDefaultSnapshotInterval = 50 * time.Millisecond

// deriveSnapshotInterval resolves the flow-ring poll interval: an explicit
// --snapshot-interval always wins; otherwise it falls back to the CUSUM
// detector's effective window (read back from the BPF object's .rodata, the
// same pattern as deriveHSlackMult in loader.go), floored at
// minDefaultSnapshotInterval. An error means neither is available.
func deriveSnapshotInterval(flagVal time.Duration, effectiveWindowNs uint64) (time.Duration, error) {
	if flagVal > 0 {
		return flagVal, nil
	}
	if effectiveWindowNs == 0 {
		return 0, fmt.Errorf("no --snapshot-interval given and the effective CUSUM window is zero")
	}
	interval := time.Duration(effectiveWindowNs)
	if interval < minDefaultSnapshotInterval {
		interval = minDefaultSnapshotInterval
	}
	return interval, nil
}

// computeRingDepth is ceil(retention / interval), at least 1.
func computeRingDepth(retention, interval time.Duration) int {
	if interval <= 0 {
		return 1
	}
	depth := int(math.Ceil(float64(retention) / float64(interval)))
	if depth < 1 {
		depth = 1
	}
	return depth
}

// monotonicNowNs reads CLOCK_MONOTONIC, the same clock bpf_ktime_get_ns and
// walltime.go use, as a nanosecond timestamp comparable to ring
// snapshot stamps and BurstEvent timestamps.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Nano())
}

// recordWriter abstracts writing one attributionRecord, so attributionState's
// pairing/watchdog logic can be tested without a real output file.
type recordWriter interface {
	write(rec attributionRecord) error
}

type jsonRecordWriter struct {
	enc *json.Encoder
}

func newJSONRecordWriter(w io.Writer) *jsonRecordWriter {
	return &jsonRecordWriter{enc: json.NewEncoder(w)}
}

func (w *jsonRecordWriter) write(rec attributionRecord) error {
	return w.enc.Encode(rec)
}

// pendingOnset is a burst onset waiting for its drain.
type pendingOnset struct {
	ev BurstEvent
}

// attributionState owns the flow snapshot ring and the onset/drain pairing
// state machine that turns a burst_event pair into one attributionRecord.
//
// Safe for concurrent use: onEvent (called from the ringbuf event loop) and
// checkWatchdog (called from the watchdog ticker) both take mu around the
// pending-onset state; the ring has its own internal mutex.
type attributionState struct {
	mu      sync.Mutex
	pending *pendingOnset

	ring     *flowRing
	resolver serviceResolver
	topN     int

	// writeMu serializes calls to writer.write, kept separate from mu (which
	// guards pending-onset state only) because a real drain and a watchdog
	// firing for a later onset can both reach emit and therefore write
	// concurrently — see TestAttributionStateEmitSerializesWriterAccess.
	writeMu sync.Mutex
	writer  recordWriter

	anchor    wallAnchor
	anchorErr error

	logger *slog.Logger
	now    func() uint64 // monotonic-ns "now"; production wires monotonicNowNs
}

// onEvent is the callback eventLoop/eventLogLoop invoke for every decoded
// burst_event. An onset stores the pending state; a drain takes a fresh
// synchronous ring snapshot (guarantees a slot at or after the drain change
// point for emit's after() lookup) and, if a pending onset exists, scores
// and emits a record.
func (s *attributionState) onEvent(ev BurstEvent) {
	switch ev.Type {
	case EventOnset:
		s.mu.Lock()
		s.pending = &pendingOnset{ev: ev}
		s.mu.Unlock()

	case EventDrain:
		nowNs := s.now()
		if err := s.ring.poll(nowNs); err != nil {
			s.logger.Warn("fresh snapshot at drain failed", "err", err)
			return
		}

		s.mu.Lock()
		pending := s.pending
		s.pending = nil
		s.mu.Unlock()

		if pending == nil {
			s.logger.Warn("drain event with no pending onset, skipping attribution",
				"drain_change_point_ns", ev.ChangePointNs)
			return
		}
		s.emit(pending, ev, nowNs, false)
	}
}

// checkWatchdog emits a partial (Unpaired) record once the pending onset has
// aged past timeout (the ring retention, measured from the onset change
// point) without a drain, then clears it so a late real drain for
// the same onset is ignored (logged, not double-emitted).
func (s *attributionState) checkWatchdog(timeout time.Duration) {
	s.mu.Lock()
	pending := s.pending
	s.mu.Unlock()
	if pending == nil {
		return
	}

	nowNs := s.now()
	// Age from the change point: that is the slot the ring must still hold.
	age := int64(nowNs) - int64(pending.ev.ChangePointNs)
	if age < int64(timeout) {
		return
	}

	if err := s.ring.poll(nowNs); err != nil {
		s.logger.Warn("watchdog snapshot failed", "err", err)
		return
	}

	s.mu.Lock()
	if s.pending != pending {
		// A real drain (or an earlier watchdog tick) already handled this
		// onset; do not double-emit.
		s.mu.Unlock()
		return
	}
	s.pending = nil
	s.mu.Unlock()

	s.logger.Warn("burst onset watchdog: no drain within ring-retention, emitting unpaired record",
		"onset_change_point_ns", pending.ev.ChangePointNs, "timeout", timeout)
	s.emit(pending, BurstEvent{}, nowNs, true)
}

// emit resolves s0/s1 against the ring (s0: newest slot at or before the
// onset change point; s1: first slot at or after the drain change point, or
// s1Stamp for an unpaired record), scores the burst, fills in
// the event/flag fields score cannot derive on its own, and writes
// the record.
func (s *attributionState) emit(pending *pendingOnset, drain BurstEvent, s1Stamp uint64, unpaired bool) {
	t0 := pending.ev.ChangePointNs

	s0, ok := s.ring.at(t0)
	truncated := !ok
	if !ok {
		// spec §5: fall back to the oldest retained slot rather than
		// dropping the record, but say so via Truncated.
		s0, ok = s.ring.oldest()
		if !ok {
			s.logger.Warn("no flow snapshot data available at all; dropping attribution record",
				"onset_change_point_ns", t0)
			return
		}
	}

	var s1 snapshot
	if unpaired {
		s1, ok = s.ring.at(s1Stamp)
	} else if s1, ok = s.ring.after(drain.ChangePointNs); !ok {
		s1, ok = s.ring.at(s1Stamp)
	}
	if !ok {
		// The synchronous poll onEvent/checkWatchdog just took must be the
		// newest slot; this is defensive, not expected to trigger.
		s1 = s0
	}

	rec := score(s0, s1, s.topN)
	s.resolveServices(rec.Contributors)

	if s.anchorErr == nil {
		rec.OnsetChangePointUTC = s.anchor.WallClockString(pending.ev.ChangePointNs)
		if !unpaired {
			rec.DrainChangePointUTC = s.anchor.WallClockString(drain.ChangePointNs)
		}
		rec.SnapshotsUsed = &snapshotsUsed{
			StartUTC: s.anchor.WallClockString(s0.stampNs),
			EndUTC:   s.anchor.WallClockString(s1.stampNs),
		}
	}
	rec.Truncated = truncated
	rec.Unpaired = unpaired

	s.writeMu.Lock()
	err := s.writer.write(rec)
	s.writeMu.Unlock()
	if err != nil {
		s.logger.Warn("writing attribution record", "err", err)
	}
}

// resolveServices fills src_service/dst_service on the (already top-N
// capped) contributors. A nil resolver or an unresolvable IP leaves the
// field empty (omitted from the JSON); it never fails a record.
func (s *attributionState) resolveServices(cs []contributor) {
	if s.resolver == nil {
		return
	}
	for i := range cs {
		cs[i].SrcService = s.resolver.resolve(hostOf(cs[i].Src))
		cs[i].DstService = s.resolver.resolve(hostOf(cs[i].Dst))
	}
}

func hostOf(endpoint string) string {
	h, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	return h
}
