// Command baseline-stats reads a window samples CSV produced by
// cusum-detector --sample-windows and computes the distribution of per-window
// delta_bytes, then emits a statistics report and ready-to-paste CUSUM flags.
//
// Usage:
//
//	baseline-stats --samples-csv /tmp/s.csv
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
	samplesCSV := flag.String("samples-csv", "", "window samples CSV from cusum-detector --sample-windows (required)")
	dropWarmup := flag.Int("drop-warmup", 1, "leading rows to drop; first delta is computed against prev_total=0 and is garbage")
	kMult := flag.Float64("k-mult", 0.5, "slack multiplier: k = k-mult × σ̂")
	hMult := flag.Float64("h-mult", 4.0, "threshold multiplier: h = h-mult × σ̂")
	trimPct := flag.Float64("trim-pct", 0, "exclude windows above this percentile before computing stats (0 = no trim)")
	flag.Parse()

	if *samplesCSV == "" {
		flag.Usage()
		return fmt.Errorf("--samples-csv is required")
	}

	logger.Info("reading samples", "path", *samplesCSV, "drop_warmup", *dropWarmup)

	deltas, err := readDeltas(*samplesCSV, *dropWarmup)
	if err != nil {
		return fmt.Errorf("reading samples CSV: %w", err)
	}
	if len(deltas) == 0 {
		return fmt.Errorf("no samples after warmup drop; file may be empty or --drop-warmup exceeds row count")
	}

	if *trimPct > 0 {
		before := len(deltas)
		deltas = trimAbove(deltas, *trimPct)
		logger.Info("trimmed outliers", "trim_pct", *trimPct, "before", before, "after", len(deltas))
	}

	logger.Info("computing stats", "n_windows", len(deltas))

	s := computeStats(deltas)
	params := deriveParams(s, *kMult, *hMult)
	printReport(os.Stdout, s, params, *kMult, *hMult)
	return nil
}

// readDeltas opens path, skips the CSV header and the first dropWarmup data
// rows, and returns the delta_bytes column (index 2) as []uint64.
func readDeltas(path string, dropWarmup int) ([]uint64, error) {
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
	if len(header) < 3 {
		return nil, fmt.Errorf("CSV has %d columns, want >=3 (timestamp_ns, total_bytes, delta_bytes, ...)", len(header))
	}

	skipped := 0
	var deltas []uint64
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
		if skipped < dropWarmup {
			skipped++
			continue
		}
		delta, err := strconv.ParseUint(row[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing delta_bytes %q: %w", row[2], err)
		}
		deltas = append(deltas, delta)
	}
	return deltas, nil
}

// trimAbove returns a copy of deltas containing only values at or below the
// p-th percentile. Burst windows above the threshold are excluded so they
// do not contaminate the baseline estimate even under robust estimators.
func trimAbove(deltas []uint64, p float64) []uint64 {
	sorted := make([]float64, len(deltas))
	for i, v := range deltas {
		sorted[i] = float64(v)
	}
	sort.Float64s(sorted)
	threshold := percentile(sorted, p)

	result := make([]uint64, 0, len(deltas))
	for _, v := range deltas {
		if float64(v) <= threshold {
			result = append(result, v)
		}
	}
	return result
}
