package main

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
)

// flowVal is one flow's per-CPU-summed state as of a single snapshot
// instant. The zero value means "absent" — a flow with genuinely zero
// bytes/skbs/first_seen never gets inserted in the first place, so a
// present-but-zero flowVal cannot occur.
type flowVal struct {
	bytes     uint64
	skbs      uint64
	firstSeen uint64
}

// sumFlowValueAcrossCPUs sums bytes/skbs across every per-CPU slot for one
// key and takes the min non-zero first_seen_ns. first_seen_ns is per-CPU: a
// BPF_NOEXIST insert only sets the inserting CPU's slot and zeroes every
// other CPU's slot for that key (ebpf/flow_stats.bpf.c), so a CPU that only
// ever added bytes via the -EEXIST fallback path has first_seen_ns == 0 and
// must not affect the min.
func sumFlowValueAcrossCPUs(cpuValues []bpfFlowStat) flowVal {
	var v flowVal
	for _, c := range cpuValues {
		v.bytes += c.Bytes
		v.skbs += c.Skbs
		if c.FirstSeenNs != 0 && (v.firstSeen == 0 || c.FirstSeenNs < v.firstSeen) {
			v.firstSeen = c.FirstSeenNs
		}
	}
	return v
}

// flowStatsReader abstracts one full read of the flow_stats map, so
// flowRing's ring/compaction logic can be tested without a real BPF map.
type flowStatsReader interface {
	// readAll returns every (key, per-CPU flat values) pair currently in the
	// map, plus the number of per-CPU slots each key's values are divided
	// into: values[i*possibleCPU : (i+1)*possibleCPU] holds key i's values.
	readAll() (keys []bpfFlowKey, values []bpfFlowStat, possibleCPU int, err error)
}

// bpfFlowStatsReader reads objs.FlowStats via one BatchLookup call per
// readAll, reusing its scratch buffers across calls.
type bpfFlowStatsReader struct {
	m           *ebpf.Map
	possibleCPU int
	keysBuf     []bpfFlowKey
	valuesBuf   []bpfFlowStat
}

func newBPFFlowStatsReader(m *ebpf.Map) (*bpfFlowStatsReader, error) {
	possibleCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("determining possible CPU count: %w", err)
	}
	count := int(m.MaxEntries())
	return &bpfFlowStatsReader{
		m:           m,
		possibleCPU: possibleCPU,
		keysBuf:     make([]bpfFlowKey, count),
		valuesBuf:   make([]bpfFlowStat, count*possibleCPU),
	}, nil
}

func (r *bpfFlowStatsReader) readAll() ([]bpfFlowKey, []bpfFlowStat, int, error) {
	var cursor ebpf.MapBatchCursor
	n, err := r.m.BatchLookup(&cursor, r.keysBuf, r.valuesBuf, nil)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, nil, 0, fmt.Errorf("batch lookup flow_stats: %w", err)
	}
	return r.keysBuf[:n], r.valuesBuf[:n*r.possibleCPU], r.possibleCPU, nil
}

// snapshot is a read-only, point-in-time view over every flow known to one
// ring slot. Safe to read concurrently with further ring polls: once
// returned by flowRing.at, neither its index nor its values are ever
// mutated again — a poll that must change either one always installs a
// freshly built replacement on the ring instead (see flowRing.snapshotLocked
// and compactLocked).
type snapshot struct {
	stampNs uint64
	index   map[bpfFlowKey]int32
	values  []flowVal
}

// value returns the flow's state as of this snapshot, and whether it was
// present at all (a key never seen, or one whose index this slot predates,
// both resolve to ok=false).
func (s snapshot) value(key bpfFlowKey) (flowVal, bool) {
	idx, ok := s.index[key]
	if !ok || int(idx) >= len(s.values) {
		return flowVal{}, false
	}
	v := s.values[idx]
	if v == (flowVal{}) {
		return flowVal{}, false
	}
	return v, true
}

// all calls yield once for every flow present in this snapshot.
func (s snapshot) all(yield func(key bpfFlowKey, v flowVal)) {
	for k, idx := range s.index {
		if int(idx) >= len(s.values) {
			continue
		}
		if v := s.values[idx]; v != (flowVal{}) {
			yield(k, v)
		}
	}
}

// ringSlot is one poll's worth of per-flow state, keyed into values by the
// flowRing's index map current at the time at() is called (see the
// invariant note on snapshot above).
type ringSlot struct {
	stampNs uint64
	values  []flowVal
}

// flowRing is a time-ordered, bounded history of flow_stats snapshots. It
// stores one shared key->index table plus one flat value array per retained
// slot (spec §3's columnar layout) rather than one Go map per slot, to keep
// per-flow overhead at a handful of bytes instead of a map entry's ~80 B.
//
// Safe for concurrent use: poll (the periodic poller) and at (a drain
// handler taking a synchronous snapshot) both take mu.
type flowRing struct {
	mu     sync.Mutex
	reader flowStatsReader
	depth  int

	index   map[bpfFlowKey]int32
	nextIdx int32

	slots []ringSlot // ordered oldest..newest, len <= depth
}

func newFlowRing(reader flowStatsReader, depth int) *flowRing {
	return &flowRing{
		reader: reader,
		depth:  depth,
		index:  make(map[bpfFlowKey]int32),
	}
}

// poll takes one snapshot of the underlying flow_stats map, stamped stampNs,
// and appends it to the ring, evicting the oldest slot if the ring is at
// depth. stampNs should come from the same monotonic clock as the CUSUM
// events being paired against snapshots (CLOCK_MONOTONIC, matching
// bpf_ktime_get_ns's clock).
func (r *flowRing) poll(stampNs uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys, values, possibleCPU, err := r.reader.readAll()
	if err != nil {
		return err
	}

	// Grow the index only when new keys appear; existing keys keep their
	// index unchanged so older slots' values arrays stay valid to read
	// against the (possibly regrown) index — see the snapshot invariant.
	grown := false
	for _, k := range keys {
		if _, ok := r.index[k]; !ok {
			if !grown {
				newIndex := make(map[bpfFlowKey]int32, len(r.index)+len(keys))
				for k, i := range r.index {
					newIndex[k] = i
				}
				r.index = newIndex
				grown = true
			}
			r.index[k] = r.nextIdx
			r.nextIdx++
		}
	}

	slotValues := make([]flowVal, r.nextIdx)
	for i, k := range keys {
		cpuValues := values[i*possibleCPU : (i+1)*possibleCPU]
		slotValues[r.index[k]] = sumFlowValueAcrossCPUs(cpuValues)
	}

	// Insert in sorted position rather than blindly appending: production
	// callers read "now" before calling poll (which then blocks on mu), so
	// two nearly-simultaneous pollers can be granted the lock in an order
	// that doesn't match their stamps. at()'s scan assumes ascending order;
	// keeping slots sorted here (regardless of call order) is what makes
	// that assumption actually hold under concurrent pollers.
	i := sort.Search(len(r.slots), func(i int) bool { return r.slots[i].stampNs > stampNs })
	r.slots = append(r.slots, ringSlot{})
	copy(r.slots[i+1:], r.slots[i:])
	r.slots[i] = ringSlot{stampNs: stampNs, values: slotValues}
	if len(r.slots) > r.depth {
		r.slots = r.slots[len(r.slots)-r.depth:]
	}

	r.compactLocked()
	return nil
}

// at returns the newest retained slot with stamp <= t, as a snapshot. ok is
// false when t is older than the oldest retained slot (the caller should
// treat this as truncation — see spec §5) or when the ring has no slots yet.
func (r *flowRing) at(t uint64) (snapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.slots) == 0 || t < r.slots[0].stampNs {
		return snapshot{}, false
	}
	chosen := 0
	for i, s := range r.slots {
		if s.stampNs > t {
			break
		}
		chosen = i
	}
	s := r.slots[chosen]
	return snapshot{stampNs: s.stampNs, index: r.index, values: s.values}, true
}

// oldest returns the oldest retained slot as a snapshot, for the truncation
// fallback in spec §5: when at(t0) reports t0 precedes every retained slot,
// the caller uses the oldest slot as s0 anyway (rather than dropping the
// record) and sets Truncated on the resulting record.
func (r *flowRing) oldest() (snapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.slots) == 0 {
		return snapshot{}, false
	}
	s := r.slots[0]
	return snapshot{stampNs: s.stampNs, index: r.index, values: s.values}, true
}

// compactLocked rebuilds the index table (and every retained slot's value
// array) when more indices are dead — absent from every retained slot —
// than are live, bounding unbounded growth from connection churn. Must be
// called with mu held.
func (r *flowRing) compactLocked() {
	live := make(map[bpfFlowKey]struct{})
	dead := 0
	for k, idx := range r.index {
		isLive := false
		for _, s := range r.slots {
			if int(idx) < len(s.values) && s.values[idx] != (flowVal{}) {
				isLive = true
				break
			}
		}
		if isLive {
			live[k] = struct{}{}
		} else {
			dead++
		}
	}
	if dead <= len(live) {
		return
	}

	newIndex := make(map[bpfFlowKey]int32, len(live))
	var nextIdx int32
	for k := range live {
		newIndex[k] = nextIdx
		nextIdx++
	}

	newSlots := make([]ringSlot, len(r.slots))
	for i, s := range r.slots {
		newValues := make([]flowVal, nextIdx)
		for k, oldIdx := range r.index {
			newIdx, stillLive := newIndex[k]
			if !stillLive || int(oldIdx) >= len(s.values) {
				continue
			}
			newValues[newIdx] = s.values[oldIdx]
		}
		newSlots[i] = ringSlot{stampNs: s.stampNs, values: newValues}
	}

	r.index = newIndex
	r.nextIdx = nextIdx
	r.slots = newSlots
}
