package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// attachment owns the live BPF objects and the TCX link that holds the
// data-path program attached to a single host-side veth's egress hook.
// Close in reverse order of acquisition: link first, then objects.
type attachment struct {
	objs    bpfObjects
	link    link.Link
	counter *ebpf.Map
}

// attachIngressCounter loads the data-path program and attaches it to the
// egress hook of the named interface via TCX. The egress hook on a host-side
// veth observes ingress-to-pod traffic; see the 2026-05-19 attach-and-signal
// design spec for the full reasoning.
func attachIngressCounter(ifname string) (*attachment, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("resolving interface %q: %w", ifname, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressCounter,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tcx to %s (ifindex %d): %w", ifname, iface.Index, err)
	}

	return &attachment{
		objs:    objs,
		link:    l,
		counter: objs.NodeIngressBytes,
	}, nil
}

// Close detaches the program and releases all BPF resources. Safe to call on
// a partially-initialised attachment.
func (a *attachment) Close() error {
	var errs []error
	if a.link != nil {
		if err := a.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing tcx link: %w", err))
		}
	}
	if err := a.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing bpf objects: %w", err))
	}
	return errors.Join(errs...)
}
