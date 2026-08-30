// Command cusum-detector is the userspace driver for the two-sided CUSUM
// burst detector. It loads the CUSUM BPF object (which shares
// node_ingr_bytes with ingress-counter via LIBBPF_PIN_BY_NAME), seeds
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
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/AdrianRC-tech/ebpf-burst-detector/internal/walltime"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
	logger.Info("cusum detector stopped cleanly")
}

func run(logger *slog.Logger) error {
	mu0 := flag.Uint64("mu0", 0, "baseline bytes per CUSUM window (default: C constant)")
	k := flag.Uint64("k", 0, "CUSUM slack factor in bytes (default: C constant)")
	hOnset := flag.Uint64("h-onset", 0, "onset threshold (upper_sum value) in bytes (default: C constant)")
	hDrain := flag.Uint64("h-drain", 0, "static drain threshold in bytes (default: derived as h-slack-mult × k_drain; set explicitly only to reproduce pre-derivation runs)")
	hSlackMult := flag.Uint64("h-slack-mult", 0, "drain threshold in slack units, h_drain = h-slack-mult × k_drain (default: derived from h_onset/k, i.e. the onset arm's own operating point)")
	window := flag.Duration("window", 0, "CUSUM window duration (e.g. 10ms, 5ms) (default: C constant)")
	sampleWindows := flag.Bool("sample-windows", false, "emit per-window byte samples to CSV for CUSUM parameter tuning")
	sampleCSV := flag.String("sample-csv", "", "path to write window sample CSV (default: stderr)")
	eventCSV := flag.String("event-csv", "", "path to write onset/drain events as CSV for offline latency analysis (default: slog to stderr)")
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
		case "h-slack-mult":
			params.HSlackMult = hSlackMult
		case "window":
			ns := uint64(window.Nanoseconds())
			params.WindowNs = &ns
		case "sample-windows":
			params.SampleWindows = sampleWindows
		}
	})

	det, err := loadCusumDetector(params)
	if err != nil {
		return fmt.Errorf("loading cusum detector: %w", err)
	}
	defer det.Close()

	if err := det.seedPrevTotal(); err != nil {
		return fmt.Errorf("seeding prev_total: %w", err)
	}

	if err := det.armTimer(); err != nil {
		return fmt.Errorf("arming timer: %w", err)
	}

	hDrainMode := "derived"
	if params.HDrain != nil {
		hDrainMode = "static"
	}

	logger.Info("cusum detector armed",
		"mu0", uint64OrDefault(params.Mu0),
		"k", uint64OrDefault(params.K),
		"h_onset", uint64OrDefault(params.HOnset),
		"h_drain", uint64OrDefault(params.HDrain),
		"h_slack_mult", det.hSlackMult,
		"h_drain_mode", hDrainMode,
		"window", windowOrDefault(params.WindowNs),
		"pin_dir", bpfPinDir,
	)

	rd, err := ringbuf.NewReader(det.objs.BurstEvents)
	if err != nil {
		return fmt.Errorf("creating burst event ringbuf reader: %w", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Close the ringbuf reader on shutdown signal so the blocking Read() in
	// the event loop returns immediately. This is the pattern recommended by
	// cilium/ebpf for clean exit.
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	var wg sync.WaitGroup

	if *sampleWindows {
		var csvOut io.Writer = os.Stderr
		if *sampleCSV != "" {
			f, err := os.Create(*sampleCSV)
			if err != nil {
				stop()
				return fmt.Errorf("opening sample CSV file %q: %w", *sampleCSV, err)
			}
			defer f.Close()
			csvOut = f
		}

		srd, err := ringbuf.NewReader(det.objs.WindowSamples)
		if err != nil {
			stop()
			return fmt.Errorf("creating window sample ringbuf reader: %w", err)
		}
		defer srd.Close()

		go func() {
			<-ctx.Done()
			srd.Close()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// A non-ErrClosed failure logs and exits this goroutine while the CUSUM
			// detector keeps running — intentional, since sampling is auxiliary.
			if err := sampleLoop(logger, csvOut, srd); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				logger.Error("sample loop terminated with error", "err", err)
			}
		}()
	}

	var eventErr error
	if *eventCSV != "" {
		f, err := os.Create(*eventCSV)
		if err != nil {
			stop()
			wg.Wait()
			return fmt.Errorf("opening event CSV file %q: %w", *eventCSV, err)
		}
		defer f.Close()
		logger.Info("logging burst events to CSV", "path", *eventCSV)
		eventErr = eventLogLoop(logger, f, rd)
	} else {
		eventErr = eventLoop(logger, rd)
	}

	// Cancel context so the srd closer goroutine fires and sampleLoop unblocks.
	stop()
	wg.Wait()

	if eventErr != nil && !errors.Is(eventErr, ringbuf.ErrClosed) {
		return eventErr
	}
	return nil
}

// uint64OrDefault returns the value pointed to by p, or "kernel-default" when
// p is nil (flag was not provided; C .rodata constant applies in the kernel).
func uint64OrDefault(p *uint64) any {
	if p == nil {
		return "kernel-default"
	}
	return *p
}

// windowOrDefault formats a nanosecond window duration as a human-readable
// string, or "kernel-default" when p is nil.
func windowOrDefault(p *uint64) any {
	if p == nil {
		return "kernel-default"
	}
	return time.Duration(*p).String()
}

func eventLoop(logger *slog.Logger, rd *ringbuf.Reader) error {
	anchor, anchorErr := walltime.Now()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; time_utc/change_point_utc will be empty", "err", anchorErr)
	}

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

		wallStr := ""
		changeStr := ""
		if anchorErr == nil {
			wallStr = anchor.WallClockString(ev.TimestampNs)
			changeStr = anchor.WallClockString(ev.ChangePointNs)
		}

		logger.Info("burst_event",
			"type", eventTypeString(ev.Type),
			"timestamp_ns", ev.TimestampNs,
			"time_utc", wallStr,
			"change_point_utc", changeStr,
			"lookback", lookbackString(ev),
			"cusum_value", ev.CusumValue,
			"window_bytes", ev.WindowBytes,
		)
	}
}
