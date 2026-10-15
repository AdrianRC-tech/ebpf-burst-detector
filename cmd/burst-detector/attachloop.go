package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

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

// runAttachLoop keeps the data-path programs attached to every allowed pod's
// netkit peer device. It subscribes to RTNLGRP_LINK, attaches the startup
// snapshot of existing devices, then reacts to link creations and deletions
// until ctx is cancelled. It blocks until both internal goroutines have
// drained, so the caller may safely close att afterwards. A non-nil error means
// the attach path died on its own (not via ctx) and the daemon should stop.
func runAttachLoop(parent context.Context, logger *slog.Logger, att *attachment, resolver nsResolver, allowedNS map[string]struct{}) error {
	// Subscribe FIRST, before enumeration, to close the enumerate→subscribe
	// window. attachOne's "already attached" guard absorbs any duplicate
	// RTM_NEWLINK events that arrive between subscribe and snapshot delivery.
	// RTNLGRP_LINK delivers RTM_NEWLINK / RTM_DELLINK for every interface in
	// the current netns; we filter to netkit devices in the receiver goroutine.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	nlConn, err := rtnetlink.Dial(&netlink.Config{Groups: unix.RTMGRP_LINK})
	if err != nil {
		return fmt.Errorf("subscribing to netlink link events: %w", err)
	}

	// Buffered channel keeps the kernel netlink socket drained; backpressure
	// moves to the Go channel rather than the fixed kernel socket buffer.
	events := make(chan linkEvent, 256)

	var recvWG, workWG sync.WaitGroup
	var recvErr error // written by the receiver goroutine, read after recvWG.Wait

	// Receiver goroutine: drain the netlink socket and push small linkEvents.
	// Never calls enrichNetkitDev, Cilium, or link.AttachNetkit — no slow work
	// here. Enrichment is deferred to the worker goroutine so this loop can
	// keep the kernel RTNL socket buffer empty during pod-creation bursts.
	//
	// The loop iterates rawMsgs directly and decodes each message inline to
	// avoid the parallel-index hazard: rtnetlink's decoder silently drops
	// unrecognised message types, which would misalign a separate decoded slice.
	recvWG.Add(1)
	go func() {
		defer recvWG.Done()
		for {
			_, rawMsgs, err := nlConn.Receive()
			if err != nil {
				// ctx.Err() is set before nlConn.Close() fires, so this
				// distinguishes a clean shutdown from an unexpected socket error.
				if ctx.Err() != nil {
					return
				}
				recvErr = fmt.Errorf("netlink receive: %w", err)
				cancel() // wake the main goroutine below so the daemon stops
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
				// Push only the lightweight base dev; the worker enriches adds.
				select {
				case events <- linkEvent{dev: base, add: raw.Header.Type == unix.RTM_NEWLINK}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Worker goroutine: the sole consumer of events and the only caller of
	// enrichNetkitDev, attachOne, and detachOne. Single consumer means the
	// resolver has exactly one accessor at runtime, removing the need for
	// external synchronisation. Enrichment (slow netlink + /proc walk) runs
	// here so the receiver goroutine is never blocked.
	workWG.Add(1)
	go func() {
		defer workWG.Done()
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

	// stopAndWait cancels ctx first so the receiver sees ctx.Err() before the
	// socket error, then unblocks it (closing the socket), waits for the
	// receiver, and only then closes events: the snapshot feeder below also
	// sends on it, so the receiver must never be the one to close it.
	stopAndWait := func() {
		cancel()
		nlConn.Close()
		recvWG.Wait()
		close(events) // signals worker to drain and exit
		workWG.Wait()
	}

	// Feed the startup snapshot through the same channel so everything is
	// serialized through the worker; idempotent attachOne deduplicates any
	// overlap with events that arrived between subscribe and enumerate.
	// discoverNetkitDevices already enriches each dev (peer ifindex + netns
	// path), so the worker skips re-enrichment when PeerIfindex is non-zero.
	peers, err := discoverNetkitDevices()
	if err != nil {
		stopAndWait()
		return fmt.Errorf("discovering netkit devices: %w", err)
	}
	for _, dev := range peers {
		select {
		case events <- linkEvent{dev: dev, add: true}:
		case <-ctx.Done():
			stopAndWait()
			return recvErr // nil when the parent ctx was cancelled
		}
	}

	// Block until shutdown (parent cancelled) or until the receiver dies
	// (it cancels ctx); stopAndWait then collects recvErr.
	<-ctx.Done()
	stopAndWait()
	return recvErr
}
