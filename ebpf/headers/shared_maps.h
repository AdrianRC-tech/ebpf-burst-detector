/* SPDX-License-Identifier: GPL-2.0 */
/*
 * shared_maps.h — single source of truth for BPF maps shared across multiple
 * BPF objects in this project. Both ingress_counter.bpf.c (data path) and
 * cusum_detector.bpf.c (timer-driven detector) include this header so the
 * map schema cannot drift between them.
 *
 * node_ingr_bytes uses LIBBPF_PIN_BY_NAME so the kernel-side map object is
 * pinned to the BPF filesystem at <PinPath>/node_ingr_bytes. cilium/ebpf
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
} node_ingr_bytes SEC(".maps");

/*
 * Layer 2 (burst attribution) per-flow maps. flow_stats.bpf.c is the only
 * writer, but every BPF object that includes this header (ingress_counter,
 * cusum_detector) gets these map definitions compiled in — LIBBPF_PIN_BY_NAME
 * ensures that the same kernel map is used across all objects.
 * The map consumes ~3.9 MB (8192 entries x 24 B x PossibleCPU()).
 */
struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   proto;
	__u8   _pad[3];
}; /* 16 B */

struct flow_stat {
	__u64 bytes;
	__u64 skbs;
	__u64 first_seen_ns;
}; /* 24 B */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_stat);
	__uint(max_entries, 8192);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_stats SEC(".maps");

