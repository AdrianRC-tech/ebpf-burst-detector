// Command burst-detector is the Layer 1 daemon: one process that owns both the
// data path and the detector. It attaches the tcx-ingress byte counter (and the
// per-flow counter) to every pod's netkit peer device in the allowed
// namespaces, loads the timer-driven two-sided CUSUM program, arms its
// bpf_timer, and logs onset/drain events from the ring buffer. Optionally it
// writes per-window samples and per-burst flow attribution records.
//
// The three BPF objects stay separate (ingress_counter, flow_stats,
// cusum_detector) and share state through maps pinned under bpfPinDir, which
// downstream layers can also read. A fatal error in either half cancels the
// daemon so the detector never runs on stale maps.
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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// bpfPinDir is the BPF filesystem directory that holds the maps shared by the
// three BPF programs and read by downstream layers.
const bpfPinDir = "/sys/fs/bpf/burst-detector"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
	logger.Info("burst-detector stopped cleanly")
}

func run(logger *slog.Logger) error {
	namespacesFlag := flag.String("namespaces", "default", "comma-separated allow-list of Kubernetes namespaces to attach to")
	ciliumSocket := flag.String("cilium-socket", "/var/run/cilium/cilium.sock", "Cilium agent API socket, used to resolve pod namespaces and to label attribution flows with service names")
	mu0 := flag.Uint64("mu0", 0, "baseline bytes per CUSUM window (default: C constant)")
	k := flag.Uint64("k", 0, "CUSUM slack factor in bytes (default: C constant)")
	hOnset := flag.Uint64("h-onset", 0, "onset threshold (upper_sum value) in bytes (default: C constant)")
	hDrain := flag.Uint64("h-drain", 0, "static drain threshold in bytes (default: derived as h-slack-mult × k_drain; set explicitly only to reproduce pre-derivation runs)")
	hSlackMult := flag.Uint64("h-slack-mult", 0, "drain threshold in slack units, h_drain = h-slack-mult × k_drain (default: derived from h_onset/k, i.e. the onset arm's own operating point)")
	window := flag.Duration("window", 0, "CUSUM window duration (e.g. 10ms, 5ms) (default: C constant)")
	sampleWindows := flag.Bool("sample-windows", false, "emit per-window byte samples to CSV for CUSUM parameter tuning")
	sampleCSV := flag.String("sample-csv", "", "path to write window sample CSV (default: stderr)")
	eventCSV := flag.String("event-csv", "", "path to write onset/drain events as CSV for offline latency analysis (default: slog to stderr)")
	attributionOut := flag.String("attribution-out", "", "path to write one NDJSON burst attribution record per drain (default: attribution disabled)")
	ringRetention := flag.Duration("ring-retention", 3*time.Second, "how far back the flow snapshot ring retains history; must cover onset change point to drain, longer bursts are marked truncated")
	snapshotInterval := flag.Duration("snapshot-interval", 0, "interval between flow snapshots (default: the effective CUSUM window)")
	topN := flag.Int("top-n", 25, "maximum contributors to include per attribution record")
	flag.Parse()

	allowedNS := make(map[string]struct{})
	for _, ns := range strings.Split(*namespacesFlag, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			allowedNS[ns] = struct{}{}
		}
	}

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

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}
	// Drop pins left by a previous run (e.g. one that was killed) so state starts clean.
	if err := os.RemoveAll(bpfPinDir); err != nil {
		return fmt.Errorf("removing stale pin dir %s: %w", bpfPinDir, err)
	}
	if err := os.MkdirAll(bpfPinDir, 0o755); err != nil {
		return fmt.Errorf("creating pin dir %s: %w", bpfPinDir, err)
	}

	// Load the counter and flow objects first: they create the pinned maps the
	// detector object then reuses in-process.
	att, err := initAttachment()
	if err != nil {
		return fmt.Errorf("initializing attachment: %w", err)
	}
	det, err := loadCusumDetector(params)
	if err != nil {
		att.Close()
		return fmt.Errorf("loading cusum detector: %w", err)
	}

	// sigCtx cancels on SIGTERM/SIGINT; cancel lets either half stop the other.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(sigCtx)

	var wg sync.WaitGroup
	var files []io.Closer // output files; closed only after every goroutine has drained

	// Ordered shutdown: cancel ctx (which also closes the ringbuf readers via
	// their closer goroutines) → wg.Wait() → output files → att.Close() (links,
	// flow objs, counter objs) → det.Close() → unpin maps. cancel() and stop() are idempotent.
	defer func() {
		cancel()
		stop()
		wg.Wait()
		for _, f := range files {
			f.Close()
		}
		if err := att.Close(); err != nil {
			logger.Error("closing attachment", "err", err)
		}
		if err := det.Close(); err != nil {
			logger.Error("closing detector", "err", err)
		}
		if err := os.RemoveAll(bpfPinDir); err != nil {
			logger.Error("removing pin dir", "dir", bpfPinDir, "err", err)
		}
	}()

	// closeOnDone closes a ringbuf reader when ctx is cancelled so the blocking
	// Read() in its loop returns immediately (the pattern recommended by
	// cilium/ebpf for clean exit).
	closeOnDone := func(rd *ringbuf.Reader) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			rd.Close()
		}()
	}

	// The attach path runs alongside the detector. If it dies on its own, the
	// detector would keep running on stale maps, so it cancels the daemon.
	attachErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runAttachLoop(ctx, logger, att, newNamespaceResolver(*ciliumSocket), allowedNS)
		if err != nil {
			attachErr <- err
			cancel()
		}
	}()

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
	logger.Info("burst detector armed",
		"namespaces", *namespacesFlag,
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
	closeOnDone(rd)

	var onEvent func(BurstEvent)
	if *attributionOut != "" {
		interval, err := deriveSnapshotInterval(*snapshotInterval, det.windowNs)
		if err != nil {
			return fmt.Errorf("deriving snapshot interval: %w", err)
		}
		depth := computeRingDepth(*ringRetention, interval)
		// A burst still undrained when its onset slot is about to leave the ring
		// is emitted as unpaired, so the watchdog timeout is the ring retention.
		timeout := *ringRetention
		if timeout <= 0 {
			timeout = interval
		}

		flowReader, err := newBPFFlowStatsReader(det.objs.FlowStats)
		if err != nil {
			return fmt.Errorf("creating flow stats reader: %w", err)
		}
		ring := newFlowRing(flowReader, depth)

		attrOutF, err := os.Create(*attributionOut)
		if err != nil {
			return fmt.Errorf("opening attribution output %q: %w", *attributionOut, err)
		}
		files = append(files, attrOutF)

		anchor, anchorErr := newWallAnchor()
		if anchorErr != nil {
			logger.Warn("failed to capture wall-clock anchor; attribution _utc fields will be empty", "err", anchorErr)
		}

		attrState := &attributionState{
			ring:      ring,
			anomalies: newBPFAnomalyReader(det.objs.FlowAnomalies),
			resolver:  newCiliumResolver(*ciliumSocket, logger),
			topN:      *topN,
			writer:    newJSONRecordWriter(attrOutF),
			anchor:    anchor,
			anchorErr: anchorErr,
			logger:    logger,
			now:       monotonicNowNs,
		}
		onEvent = attrState.onEvent

		// Seed the ring immediately so it isn't empty before the first poll tick.
		if err := ring.poll(monotonicNowNs()); err != nil {
			logger.Warn("initial flow snapshot failed", "err", err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := ring.poll(monotonicNowNs()); err != nil {
						logger.Warn("flow snapshot poll failed", "err", err)
					}
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			watchdogTick := timeout / 4
			if watchdogTick <= 0 {
				watchdogTick = time.Second
			}
			ticker := time.NewTicker(watchdogTick)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					attrState.checkWatchdog(timeout)
				}
			}
		}()

		logger.Info("attribution enabled",
			"out", *attributionOut,
			"snapshot_interval", interval,
			"ring_retention", *ringRetention,
			"ring_depth", depth,
			"cilium_socket", *ciliumSocket,
			"top_n", *topN,
		)
	}

	if *sampleWindows {
		var csvOut io.Writer = os.Stderr
		if *sampleCSV != "" {
			f, err := os.Create(*sampleCSV)
			if err != nil {
				return fmt.Errorf("opening sample CSV file %q: %w", *sampleCSV, err)
			}
			files = append(files, f)
			csvOut = f
		}

		srd, err := ringbuf.NewReader(det.objs.WindowSamples)
		if err != nil {
			return fmt.Errorf("creating window sample ringbuf reader: %w", err)
		}
		closeOnDone(srd)

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
			return fmt.Errorf("opening event CSV file %q: %w", *eventCSV, err)
		}
		files = append(files, f)
		logger.Info("logging burst events to CSV", "path", *eventCSV)
		eventErr = eventLogLoop(logger, f, rd, onEvent)
	} else {
		eventErr = eventLoop(logger, rd, onEvent)
	}

	// The event loop returns once ctx is cancelled (reader closed), whether by
	// a signal, a fatal attach error, or a ringbuf failure. Prefer the attach
	// error: it is the root cause when it triggered the shutdown.
	cancel()
	select {
	case err := <-attachErr:
		return fmt.Errorf("attach loop: %w", err)
	default:
	}
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

func eventLoop(logger *slog.Logger, rd *ringbuf.Reader, onEvent func(BurstEvent)) error {
	anchor, anchorErr := newWallAnchor()
	if anchorErr != nil {
		logger.Warn("failed to capture wall-clock anchor; change_point_utc will be empty", "err", anchorErr)
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

		changeStr := ""
		if anchorErr == nil {
			changeStr = anchor.WallClockString(ev.ChangePointNs)
		}

		logger.Info("burst_event",
			"type", eventTypeString(ev.Type),
			"change_point_ns", ev.ChangePointNs,
			"change_point_utc", changeStr,
			"cusum_value", ev.CusumValue,
			"window_bytes", ev.WindowBytes,
		)

		if onEvent != nil {
			onEvent(ev)
		}
	}
}
