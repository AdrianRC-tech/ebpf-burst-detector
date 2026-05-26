// Command ingress-counter is the userspace driver for Layer 1's data-path
// byte counter. It attaches a TCX program to a single host-side veth's egress
// hook and periodically reports the cumulative and delta byte totals observed
// across all CPUs. The actual burst detection (CUSUM) is a separate BPF
// program added in iteration 2; the binary at that point will likely be
// renamed accordingly.
//
// See README.md for build/run instructions and the design specs under
// docs/superpowers/specs/ for the architectural rationale.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	iface := flag.String("iface", "", "host-side veth to attach to (required)")
	interval := flag.Duration("interval", time.Second, "report interval")
	oracle := flag.Bool("oracle", true, "compare against /sys/class/net/<iface>/statistics/tx_bytes")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if *iface == "" {
		logger.Error("--iface is required")
		os.Exit(2)
	}

	att, err := attachIngressCounter(*iface)
	if err != nil {
		logger.Error("attach failed", "iface", *iface, "err", err)
		os.Exit(1)
	}
	defer att.Close()

	logger.Info("attached", "iface", *iface, "interval", interval.String(), "oracle", *oracle)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := tickLoop(ctx, logger, att, *iface, *interval, *oracle); err != nil {
		logger.Error("tick loop terminated with error", "err", err)
		os.Exit(1)
	}
	logger.Info("detached cleanly")
}

func tickLoop(ctx context.Context, logger *slog.Logger, att *attachment, iface string, interval time.Duration, oracle bool) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prevTotal uint64
	var prevTime time.Time

	// Snapshot the oracle at attach time so drift is relative to the same epoch
	// as the eBPF counter (which starts at 0 on program load).
	var oracleBaseline uint64
	if oracle {
		oracleBaseline, _ = readOracle(iface)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			total, active, err := readTotalAndCPUs(att.counter)
			if err != nil {
				return fmt.Errorf("reading bpf counter: %w", err)
			}

			delta := total - prevTotal
			var bps float64
			if !prevTime.IsZero() {
				elapsed := now.Sub(prevTime).Seconds()
				if elapsed > 0 {
					bps = float64(delta) / elapsed
				}
			}

			attrs := []any{
				"total_bytes", total,
				"delta_bytes", delta,
				"bytes_per_sec", uint64(bps),
				"active_cpus", active,
			}
			if oracle {
				if oracleTotal, ok := readOracle(iface); ok {
					oracleDelta := oracleTotal - oracleBaseline
					drift := int64(total) - int64(oracleDelta)
					attrs = append(attrs, "oracle_total", oracleDelta, "oracle_drift", drift)
				}
			}
			logger.Info("tick", attrs...)

			prevTotal = total
			prevTime = now
		}
	}
}

// readOracle returns the kernel's tx_bytes counter for the host-side veth.
// Egress on a host-side veth equals ingress-to-pod, so this matches what our
// BPF program is counting. Returns false if the stat file can't be read —
// the loader logs without the oracle column rather than failing the whole
// tick.
func readOracle(iface string) (uint64, bool) {
	path := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
