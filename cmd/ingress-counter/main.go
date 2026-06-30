// Command ingress-counter is the userspace driver for Layer 1's data-path
// byte counter. It attaches a tcx-ingress BPF program to every pod's netkit
// peer device (via a brief setns crossing) in the specified Kubernetes namespaces.
// Pod lifecycle is tracked via a RTNLGRP_LINK netlink subscription so the daemon
// reacts to creations and deletions without polling.
//
// Pass --trace-packets to enable opt-in per-packet tracing (debug only). Each
// packet record carries timestamp_ns, len, and the IPv4 5-tuple; records are
// written as CSV to --trace-csv (or stderr). Byte-per-window analysis is
// delegated to cusum-detector --sample-windows; offline reconciliation uses
// cmd/trace-crosscheck.
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

	"github.com/cilium/ebpf/ringbuf"
	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
	logger.Info("detached cleanly")
}

// linkEvent is a small decoded view of an RTM_NEWLINK / RTM_DELLINK message.
// The receiver goroutine pushes these onto a buffered channel so that the
// kernel netlink socket is drained immediately; the worker goroutine performs
// the slow peer/netns enrichment, Cilium HTTP, and attach/detach work without
// blocking the socket buffer.
//
// For RTM_NEWLINK (add=true), dev carries only Ifindex and Name; the worker
// calls enrichNetkitDev to populate PeerIfindex and PodNetnsPath before
// calling attachOne. On enrichment failure the worker logs a warning and skips.
// For RTM_DELLINK (add=false), only dev.Ifindex and dev.Name are meaningful.
type linkEvent struct {
	dev netkitDev
	add bool // true = RTM_NEWLINK, false = RTM_DELLINK
}

func run(logger *slog.Logger) error {
	namespacesFlag := flag.String("namespaces", "default", "comma-separated allow-list of Kubernetes namespaces to attach to")
	ciliumSocket := flag.String("cilium-socket", "/var/run/cilium/cilium.sock", "path to Cilium agent unix socket")
	tracePackets := flag.Bool("trace-packets", false, "emit per-packet trace records (debug only; off by default)")
	traceCSV := flag.String("trace-csv", "", "path to write packet trace CSV (default: stderr)")
	flag.Parse()
	fmt.Printf("tracePackets=%v traceCSV=%q ", *tracePackets, *traceCSV)
	allowedNS := make(map[string]struct{})
	for _, ns := range strings.Split(*namespacesFlag, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			allowedNS[ns] = struct{}{}
		}
	}

	att, err := initAttachment(*tracePackets)
	if err != nil {
		return fmt.Errorf("initializing attachment: %w", err)
	}

	resolver := newNamespaceResolver(*ciliumSocket)

	// Subscribe FIRST, before enumeration, to close the enumerate→subscribe
	// window. attachOne's "already attached" guard absorbs any duplicate
	// RTM_NEWLINK events that arrive between subscribe and snapshot delivery.
	// RTNLGRP_LINK delivers RTM_NEWLINK / RTM_DELLINK for every interface in
	// the current netns; we filter to netkit devices in the receiver goroutine.
	nlConn, err := rtnetlink.Dial(&netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
		att.Close()
		return fmt.Errorf("subscribing to netlink link events: %w", err)
	}

	// Two-level context: signal.NotifyContext cancels sigCtx on SIGTERM/SIGINT;
	// cancel() lets error paths cancel ctx explicitly so ctx.Err() is always
	// set before nlConn.Close() unblocks the receiver goroutine.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(sigCtx)

	// Buffered channel keeps the kernel netlink socket drained; backpressure
	// moves to the Go channel rather than the fixed kernel socket buffer.
	events := make(chan linkEvent, 256)

	var wg sync.WaitGroup

	// Deferred shutdown respects ordering: goroutines are drained before BPF
	// objects are torn down. cancel() and stop() are idempotent so calling them
	// here after the normal shutdown path is a no-op.
	defer func() {
		cancel()
		stop()
		wg.Wait()
		att.Close()
	}()

	if *tracePackets {
		var csvOut io.Writer = os.Stderr
		if *traceCSV != "" {
			f, err := os.Create(*traceCSV)
			if err != nil {
				cancel()
				nlConn.Close()
				return fmt.Errorf("opening trace CSV file %q: %w", *traceCSV, err)
			}
			defer f.Close()
			csvOut = f
		}

		trd, err := ringbuf.NewReader(att.objs.PktTraceRb)
		if err != nil {
			cancel()
			nlConn.Close()
			return fmt.Errorf("creating packet trace ringbuf reader: %w", err)
		}
		defer trd.Close()

		go func() {
			<-ctx.Done()
			trd.Close()
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := traceLoop(logger, csvOut, trd); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
				logger.Error("trace loop terminated with error", "err", err)
			}
		}()

		logger.Info("per-packet trace enabled", "csv", func() string {
			if *traceCSV != "" {
				return *traceCSV
			}
			return "stderr"
		}())
	}

	// Receiver goroutine: drain the netlink socket and push small linkEvents.
	// Never calls enrichNetkitDev, Cilium, or link.AttachNetkit — no slow work
	// here. Enrichment is deferred to the worker goroutine so this loop can
	// keep the kernel RTNL socket buffer empty during pod-creation bursts.
	//
	// The loop iterates rawMsgs directly and decodes each message inline to
	// avoid the parallel-index hazard: rtnetlink's decoder silently drops
	// unrecognised message types, which would misalign a separate decoded slice.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(events) // signals worker to drain and exit
		for {
			_, rawMsgs, err := nlConn.Receive()
			if err != nil {
				// ctx.Err() is set before nlConn.Close() fires, so this
				// distinguishes a clean shutdown from an unexpected socket error.
				if ctx.Err() != nil {
					return
				}
				logger.Error("netlink receive error", "err", err)
				return
			}
			for _, raw := range rawMsgs {
				if raw.Header.Type != unix.RTM_NEWLINK && raw.Header.Type != unix.RTM_DELLINK {
					continue
				}
				var linkMsg rtnetlink.LinkMessage
				if err := linkMsg.UnmarshalBinary(raw.Data); err != nil {
					continue
				}
				// Guard against messages without IFLA_LINKINFO (valid for some RTM types).
				if linkMsg.Attributes == nil ||
					linkMsg.Attributes.Info == nil ||
					linkMsg.Attributes.Info.Kind != "netkit" {
					continue
				}
				base := netkitDev{
					Ifindex: uint32(linkMsg.Index),
					Name:    linkMsg.Attributes.Name,
				}
				switch raw.Header.Type {
				case unix.RTM_NEWLINK:
					// Push only the lightweight base dev; the worker enriches it.
					select {
					case events <- linkEvent{dev: base, add: true}:
					case <-ctx.Done():
						return
					}
				case unix.RTM_DELLINK:
					select {
					case events <- linkEvent{dev: base, add: false}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// Worker goroutine: the sole consumer of events and the only caller of
	// enrichNetkitDev, attachOne, and detachOne. Single consumer means the
	// resolver has exactly one accessor at runtime, removing the need for
	// external synchronisation. Enrichment (slow netlink + /proc walk) runs
	// here so the receiver goroutine is never blocked.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range events {
			if ev.add {
				// If PeerIfindex is already set (startup snapshot via
				// discoverNetkitDevices), skip enrichment to avoid a redundant
				// netlink + /proc walk. RTM_NEWLINK events from the receiver
				// carry only Ifindex and Name and always need enrichment.
				dev := ev.dev
				if dev.PeerIfindex == 0 {
					var err error
					dev, err = enrichNetkitDev(ev.dev, fetchPeerNetlinkInfo, resolvePodNetnsPath)
					if err != nil {
						logger.Warn("skipping RTM_NEWLINK: peer/netns resolution failed",
							"ifindex", ev.dev.Ifindex, "name", ev.dev.Name, "err", err)
						continue
					}
				}
				reason, err := att.attachOne(dev, resolver, allowedNS)
				if err != nil {
					logger.Error("attach failed", "ifindex", dev.Ifindex, "name", dev.Name, "err", err)
					continue
				}
				logger.Info("netlink attach", "ifindex", dev.Ifindex, "name", dev.Name, "result", reason)
			} else {
				if err := att.detachOne(ev.dev.Ifindex); err != nil {
					logger.Error("detach failed", "ifindex", ev.dev.Ifindex, "name", ev.dev.Name, "err", err)
				}
				logger.Info("netlink detach", "ifindex", ev.dev.Ifindex, "name", ev.dev.Name)
			}
		}
	}()

	// Feed the startup snapshot through the same channel so everything is
	// serialized through the worker; idempotent attachOne deduplicates any
	// overlap with events that arrived between subscribe and enumerate.
	// discoverNetkitDevices already enriches each dev (peer ifindex + netns
	// path), so the worker skips re-enrichment when PeerIfindex is non-zero.
	peers, err := discoverNetkitDevices()
	if err != nil {
		cancel()
		nlConn.Close()
		return fmt.Errorf("discovering netkit devices: %w", err)
	}
	for _, dev := range peers {
		select {
		case events <- linkEvent{dev: dev, add: true}:
		case <-ctx.Done():
			nlConn.Close()
			return ctx.Err()
		}
	}

	// Ordered shutdown: cancel()/stop() → nlConn.Close() → wg.Wait() → att.Close().
	// cancel() cancels ctx so receiver goroutine sees ctx.Err() != nil before
	// the socket error; stop() releases the OS signal subscription;
	// nlConn.Close() unblocks the receiver goroutine; wg.Wait() drains the
	// event channel before att.Close() tears down BPF objects and the fd table.
	// The deferred closure above handles wg.Wait() + att.Close().
	<-ctx.Done()
	stop()
	nlConn.Close()
	return nil
}
