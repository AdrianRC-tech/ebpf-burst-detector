// Command burst-metrics scores a CUSUM detector run against the k6 scenario
// that drove it: TP/FP/FN, onset/drain detection latency, and % of each
// bursty window covered by the detector's flag.
//
// Usage:
//
//	burst-metrics --k6-log run.log --events-csv events.csv [--tolerance 300ms]
//
// run.log is k6 stdout captured to a file (k6 run bursts.js ... | tee run.log);
// events.csv is produced by cusum-detector --event-csv. Both files must come
// from the same run and the same wall-clock day — timestamps are compared as
// UTC time-of-day (see parseTimeOfDayNs), since that is the only field common
// to both k6 (epoch-ns) and the detector (CLOCK_MONOTONIC).
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	k6Log := flag.String("k6-log", "", "k6 stdout log captured from a bursts.js or staircase.js run (required)")
	eventsCSV := flag.String("events-csv", "", "event CSV from cusum-detector --event-csv (required)")
	tolerance := flag.Duration("tolerance", 300*time.Millisecond, "how late an onset may arrive after a burst's nominal end and still count as a match; "+
		"tighten this for scenario C (bursts only 1s apart) so adjacent bursts don't blur together")
	flag.Parse()

	if *k6Log == "" || *eventsCSV == "" {
		flag.Usage()
		return fmt.Errorf("--k6-log and --events-csv are required")
	}

	logger.Info("reading ground truth", "path", *k6Log)
	gtFile, err := os.Open(*k6Log)
	if err != nil {
		return fmt.Errorf("opening k6 log: %w", err)
	}
	defer gtFile.Close()

	bursts, err := parseGroundTruth(gtFile)
	if err != nil {
		return fmt.Errorf("parsing ground truth: %w", err)
	}

	logger.Info("reading detector events", "path", *eventsCSV)
	evFile, err := os.Open(*eventsCSV)
	if err != nil {
		return fmt.Errorf("opening events csv: %w", err)
	}
	defer evFile.Close()

	intervals, err := parseDetectedIntervals(evFile)
	if err != nil {
		return fmt.Errorf("parsing detector events: %w", err)
	}

	logger.Info("scoring", "ground_truth_bursts", len(bursts), "detected_intervals", len(intervals), "tolerance", tolerance.String())
	m := score(bursts, intervals, int64(*tolerance))

	fmt.Print(formatReport(m))
	return nil
}
