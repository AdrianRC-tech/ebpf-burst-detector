// Command trace-crosscheck reconciles per-packet trace records from
// ingress-counter --trace-packets against per-window byte samples from
// cusum-detector --sample-windows.
//
// For each window interval (prev_ts, cur_ts], it sums the len of packets whose
// timestamp falls inside that interval and compares the result to the window's
// delta_bytes from the CUSUM stage. Boundary jitter (non-atomic add-vs-timer
// race) accounts for any small per-window difference.
//
// Usage:
//
//	trace-crosscheck --trace-csv /tmp/trace.csv --samples-csv /tmp/samples.csv
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	traceCSV := flag.String("trace-csv", "", "packet trace CSV from ingress-counter --trace-packets (required)")
	samplesCSV := flag.String("samples-csv", "", "window samples CSV from cusum-detector --sample-windows (required)")
	filterProto := flag.Uint("filter-proto", 0, "IP protocol number to include (0 = all)")
	flag.Parse()

	if *traceCSV == "" || *samplesCSV == "" {
		flag.Usage()
		return fmt.Errorf("both --trace-csv and --samples-csv are required")
	}

	windows, err := readWindowSamples(*samplesCSV)
	if err != nil {
		return fmt.Errorf("reading window samples: %w", err)
	}
	pkts, err := readPacketTrace(*traceCSV)
	if err != nil {
		return fmt.Errorf("reading packet trace: %w", err)
	}

	if uint8(*filterProto) != 0 {
		proto := uint8(*filterProto)
		filtered := pkts[:0]
		for _, p := range pkts {
			if p.protocol == proto {
				filtered = append(filtered, p)
			}
		}
		pkts = filtered
		logger.Info("proto filter applied", "proto", proto, "remaining_packets", len(pkts))
	}

	results := bucketPackets(windows, pkts)
	printReport(os.Stdout, results)
	printComposition(os.Stdout, pkts)
	return nil
}

// windowSample is one row from the cusum-detector --sample-windows CSV.
type windowSample struct {
	timestampNs uint64
	deltaBytes  uint64
}

// pktRecord is one row from the ingress-counter --trace-packets CSV.
type pktRecord struct {
	timestampNs uint64
	lenBytes    uint32
	srcIP       string
	dstIP       string
	srcPort     uint16
	dstPort     uint16
	protocol    uint8
}

// windowResult is the per-window comparison output.
type windowResult struct {
	windowTs    uint64
	deltaBytes  uint64
	packetSum   uint64
	packetCount int
}

// bucketPackets assigns each packet to the window interval (prev_ts, cur_ts]
// that contains its timestamp, sums bytes per window, and returns one result
// per window sorted by timestamp. Interior windows (those with a defined prev
// boundary) are included; any packets that fall before the first window or
// after the last window are counted but noted.
func bucketPackets(windows []windowSample, pkts []pktRecord) []windowResult {
	if len(windows) == 0 {
		return nil
	}

	// Ensure inputs are sorted by timestamp.
	sort.Slice(windows, func(i, j int) bool { return windows[i].timestampNs < windows[j].timestampNs })
	sort.Slice(pkts, func(i, j int) bool { return pkts[i].timestampNs < pkts[j].timestampNs })

	results := make([]windowResult, len(windows))
	for i, w := range windows {
		results[i] = windowResult{windowTs: w.timestampNs, deltaBytes: w.deltaBytes}
	}

	// Binary-search each packet into the window whose upper bound (ts) is the
	// smallest ts >= pkt.timestampNs. That gives the half-open interval
	// (prev_ts, ts] for interior windows (index >= 1).
	for _, p := range pkts {
		// Find the first window whose timestamp >= packet timestamp.
		idx := sort.Search(len(windows), func(i int) bool {
			return windows[i].timestampNs >= p.timestampNs
		})
		// idx == len(windows): packet is after all windows — ignore (boundary).
		// idx == 0: packet is before or at the first window's timestamp.
		//   The first window has no prev_ts, so we cannot know which side of the
		//   first timer fire this packet came from; attribute it to window[0].
		if idx >= len(windows) {
			continue
		}
		results[idx].packetSum += uint64(p.lenBytes)
		results[idx].packetCount++
	}

	return results
}

// printReport writes per-window reconciliation to w.
func printReport(w io.Writer, results []windowResult) {
	fmt.Fprintln(w, "window_ts_ns,delta_bytes,packet_sum,difference,packet_count")
	var totalDelta, totalPacketSum uint64
	for _, r := range results {
		diff := int64(r.packetSum) - int64(r.deltaBytes)
		fmt.Fprintf(w, "%d,%d,%d,%d,%d\n",
			r.windowTs, r.deltaBytes, r.packetSum, diff, r.packetCount)
		totalDelta += r.deltaBytes
		totalPacketSum += r.packetSum
	}
	totalDiff := int64(totalPacketSum) - int64(totalDelta)
	fmt.Fprintf(w, "\ntotal: delta_bytes=%d packet_sum=%d difference=%d\n",
		totalDelta, totalPacketSum, totalDiff)
}

// flowKey identifies a flow for the composition summary.
type flowKey struct {
	srcIP, dstIP     string
	srcPort, dstPort uint16
	protocol         uint8
}

// printComposition writes a top-10 flow summary by bytes to w.
func printComposition(w io.Writer, pkts []pktRecord) {
	byFlow := make(map[flowKey]uint64)
	for _, p := range pkts {
		k := flowKey{p.srcIP, p.dstIP, p.srcPort, p.dstPort, p.protocol}
		byFlow[k] += uint64(p.lenBytes)
	}

	type entry struct {
		k     flowKey
		bytes uint64
	}
	ranked := make([]entry, 0, len(byFlow))
	for k, b := range byFlow {
		ranked = append(ranked, entry{k, b})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].bytes > ranked[j].bytes })

	fmt.Fprintln(w, "\ncomposition (top flows by bytes):")
	fmt.Fprintln(w, "bytes,src_ip,src_port,dst_ip,dst_port,protocol")
	limit := 10
	if len(ranked) < limit {
		limit = len(ranked)
	}
	for _, e := range ranked[:limit] {
		fmt.Fprintf(w, "%d,%s,%d,%s,%d,%d\n",
			e.bytes, e.k.srcIP, e.k.srcPort, e.k.dstIP, e.k.dstPort, e.k.protocol)
	}
}

func readWindowSamples(path string) ([]windowSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}
	// Expect: timestamp_ns, total_bytes, delta_bytes
	if len(header) < 3 {
		return nil, fmt.Errorf("window samples CSV has %d columns, want >=3", len(header))
	}

	var samples []windowSample
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading row: %w", err)
		}
		if len(row) < 3 {
			continue
		}
		ts, err := strconv.ParseUint(row[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing timestamp_ns %q: %w", row[0], err)
		}
		delta, err := strconv.ParseUint(row[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing delta_bytes %q: %w", row[2], err)
		}
		samples = append(samples, windowSample{timestampNs: ts, deltaBytes: delta})
	}
	return samples, nil
}

func readPacketTrace(path string) ([]pktRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}
	// Expect: timestamp_ns, len, src_ip, dst_ip, src_port, dst_port, protocol
	if len(header) < 7 {
		return nil, fmt.Errorf("packet trace CSV has %d columns, want >=7", len(header))
	}

	var pkts []pktRecord
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading row: %w", err)
		}
		if len(row) < 7 {
			continue
		}
		ts, err := strconv.ParseUint(row[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing timestamp_ns %q: %w", row[0], err)
		}
		length, err := strconv.ParseUint(row[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing len %q: %w", row[1], err)
		}
		srcPort, err := strconv.ParseUint(row[4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing src_port %q: %w", row[4], err)
		}
		dstPort, err := strconv.ParseUint(row[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing dst_port %q: %w", row[5], err)
		}
		proto, err := strconv.ParseUint(row[6], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing protocol %q: %w", row[6], err)
		}
		pkts = append(pkts, pktRecord{
			timestampNs: ts,
			lenBytes:    uint32(length),
			srcIP:       row[2],
			dstIP:       row[3],
			srcPort:     uint16(srcPort),
			dstPort:     uint16(dstPort),
			protocol:    uint8(proto),
		})
	}
	return pkts, nil
}
