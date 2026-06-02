/* SPDX-License-Identifier: GPL-2.0 */
/*
 * shared_maps.h — single source of truth for BPF maps shared across multiple
 * BPF objects in this project. Both ingress_counter.bpf.c (data path) and
 * cusum_detector.bpf.c (timer-driven detector) include this header so the
 * map schema cannot drift between them.
 *
 * node_ingress_bytes uses LIBBPF_PIN_BY_NAME so the kernel-side map object is
 * pinned to the BPF filesystem at <PinPath>/node_ingress_bytes. cilium/ebpf
 * sees the pinning attribute in the ELF and at load time either creates the
 * map and pins it (first loader) or opens the existing pin (subsequent
 * loaders), giving every BPF object the same underlying kernel map fd.
 */
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} node_ingress_bytes SEC(".maps");
