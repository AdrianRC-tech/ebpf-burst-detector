// Command cusum-detector is the userspace driver for the two-sided CUSUM
// burst detector. It loads the CUSUM BPF object (which shares
// node_ingress_bytes with ingress-counter via LIBBPF_PIN_BY_NAME), seeds
// cusum_state.prev_total from the current counter total to avoid a first-tick
// false onset, arms the kernel bpf_timer, and logs onset/drain events as
// structured JSON to stderr.
//
// See README.md for build, attach, and operational guidance.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
)

func main() {
	mu0 := flag.Uint64("mu0", 0, "baseline bytes per CUSUM window (default: C constant)")
	k := flag.Uint64("k", 0, "CUSUM slack factor in bytes (default: C constant)")
	hOnset := flag.Uint64("h-onset", 0, "onset threshold (upper_sum value) in bytes (default: C constant)")
	hDrain := flag.Uint64("h-drain", 0, "drain threshold (lower_sum value) in bytes (default: C constant)")
	window := flag.Duration("window", 0, "CUSUM window duration (e.g. 10ms, 5ms) (default: C constant)")
	flag.Parse()

	// Build params with only the flags the user explicitly provided.
	// Unset flags remain nil so the C .rodata default survives into the kernel.
	var params cusumParams
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "mu0":
			params.Mu0 = mu0
		case "k":
			params.K = k
		case "h-onset":
			params.HOnset = hOnset
		case "h-drain":
			params.HDrain = hDrain
		case "window":
			ns := uint64(window.Nanoseconds())
			params.WindowNs = &ns
		}
	})

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	det, err := loadCusumDetector(params)
	if err != nil {
		logger.Error("loading cusum detector", "err", err)
		os.Exit(1)
	}
	defer det.Close()

	if err := det.seedPrevTotal(); err != nil {
		logger.Error("seeding prev_total", "err", err)
		os.Exit(1)
	}

	if err := det.armTimer(); err != nil {
		logger.Error("arming timer", "err", err)
		os.Exit(1)
	}

	logger.Info("cusum detector armed",
		"mu0", mu0, "k", k,
		"h_onset", hOnset, "h_drain", hDrain,
		"window", window.String(),
		"pin_dir", bpfPinDir,
	)

	rd, err := ringbuf.NewReader(det.objs.BurstEvents)
	if err != nil {
		logger.Error("creating ringbuf reader", "err", err)
		os.Exit(1)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Close the ringbuf reader on shutdown signal so the blocking Read() in
	// the event loop returns immediately. This is the pattern recommended by
	// cilium/ebpf for clean exit.
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	if err := eventLoop(logger, rd); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
		logger.Error("event loop terminated with error", "err", err)
		os.Exit(1)
	}
	logger.Info("cusum detector stopped cleanly")
}

func eventLoop(logger *slog.Logger, rd *ringbuf.Reader) error {
	for {
		rec, err := rd.Read()
		if err != nil {
			return fmt.Errorf("reading ringbuf: %w", err)
		}

		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			logger.Warn("skipping malformed event", "err", err, "raw_len", len(rec.RawSample))
			continue
		}

		logger.Info("burst_event",
			"type", eventTypeString(ev.Type),
			"timestamp_ns", ev.TimestampNs,
			"cusum_value", ev.CusumValue,
			"window_bytes", ev.WindowBytes,
		)
	}
}
