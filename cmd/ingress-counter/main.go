// Command ingress-counter is the userspace driver for Layer 1's data-path
// byte counter. It attaches a netkit-primary BPF program to every pod's netkit
// primary device in the specified Kubernetes namespaces. Pod lifecycle is tracked
// via a RTNLGRP_LINK netlink subscription so the daemon reacts to creations
// and deletions without polling. The daemon is silent after attach/detach log
// lines — byte-per-window analysis is delegated to cusum-detector
// --sample-windows.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

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
// the slow Cilium HTTP + attach/detach work without blocking the socket buffer.
//
// For RTM_NEWLINK (add=true), dev carries the enriched netkitDev (with
// PeerIfindex and PodNetnsPath) if enrichment succeeded; on enrichment failure
// the worker skips the event. For RTM_DELLINK (add=false), only dev.Ifindex
// and dev.Name are meaningful.
type linkEvent struct {
	dev netkitDev
	add bool // true = RTM_NEWLINK, false = RTM_DELLINK
}

func run(logger *slog.Logger) error {
	namespacesFlag := flag.String("namespaces", "default", "comma-separated allow-list of Kubernetes namespaces to attach to")
	ciliumSocket := flag.String("cilium-socket", "/var/run/cilium/cilium.sock", "path to Cilium agent unix socket")
	flag.Parse()

	allowedNS := make(map[string]struct{})
	for _, ns := range strings.Split(*namespacesFlag, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			allowedNS[ns] = struct{}{}
		}
	}

	att, err := initAttachment()
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// Buffered channel keeps the kernel netlink socket drained; backpressure
	// moves to the Go channel rather than the fixed kernel socket buffer.
	events := make(chan linkEvent, 256)

	var wg sync.WaitGroup

	// Receiver goroutine: drain the netlink socket and push small linkEvents.
	// Never calls Cilium or link.AttachNetkit — no slow work here.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(events) // signals worker to drain and exit
		for {
			msgs, rawMsgs, err := nlConn.Receive()
			if err != nil {
				// ctx.Err() is set before nlConn.Close() fires, so this
				// distinguishes a clean shutdown from an unexpected socket error.
				if ctx.Err() != nil {
					return
				}
				logger.Error("netlink receive error", "err", err)
				return
			}
			for i, msg := range msgs {
				linkMsg, ok := msg.(*rtnetlink.LinkMessage)
				if !ok {
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
				switch rawMsgs[i].Header.Type {
				case unix.RTM_NEWLINK:
					enriched, err := enrichNetkitDev(base, fetchPeerNetlinkInfo, resolvePodNetnsPath)
					if err != nil {
						logger.Warn("skipping RTM_NEWLINK: peer/netns resolution failed",
							"ifindex", base.Ifindex, "name", base.Name, "err", err)
						continue
					}
					events <- linkEvent{dev: enriched, add: true}
				case unix.RTM_DELLINK:
					events <- linkEvent{dev: base, add: false}
				default:
					continue
				}
			}
		}
	}()

	// Worker goroutine: the sole consumer of events and the only caller of
	// attachOne/detachOne. Single consumer means the resolver has exactly one
	// accessor at runtime, removing the need for external synchronisation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range events {
			if ev.add {
				reason, err := att.attachOne(ev.dev, resolver, allowedNS)
				if err != nil {
					logger.Error("attach failed", "ifindex", ev.dev.Ifindex, "name", ev.dev.Name, "err", err)
					continue
				}
				logger.Info("netlink attach", "ifindex", ev.dev.Ifindex, "name", ev.dev.Name, "result", reason)
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
	peers, err := discoverNetkitDevices()
	if err != nil {
		stop()
		nlConn.Close()
		wg.Wait()
		att.Close()
		return fmt.Errorf("discovering netkit devices: %w", err)
	}
	for _, dev := range peers {
		events <- linkEvent{dev: dev, add: true}
	}

	// TODO(human): Block until the process receives a shutdown signal, then
	// run the ordered shutdown sequence so all netkit links are detached
	// cleanly before the process exits. Return nil on a clean shutdown.
	//
	// Ordered shutdown:  stop() → nlConn.Close() → wg.Wait() → att.Close()
	//
	// Hint: stop() releases the OS signal subscription (so a second Ctrl-C
	// can force-exit the process); nlConn.Close() unblocks the receiver
	// goroutine that is parked on nlConn.Receive(); wg.Wait() ensures the
	// worker goroutine fully drains the event channel before att.Close() tears
	// down the BPF objects and fd table.
	<-ctx.Done()
	stop()
	nlConn.Close()
	wg.Wait()
	att.Close()
	return nil
}
