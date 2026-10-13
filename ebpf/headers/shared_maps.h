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

/* idx 0 = parse_anomaly (unparseable header), idx 1 = lru_saturated
 * (flow_stats insert failed — bpf_map_update_elem returned neither 0 nor
 * -EEXIST). Per-CPU; cusum-detector sums both across CPUs and across
 * snapshot boundaries when building an attribution record.
 *
 * lru_saturated is near-useless as an occupancy signal on its own: an
 * LRU_PERCPU_HASH insert past capacity evicts an existing entry rather than
 * failing, so this counter stays 0 under exactly the connection-churn
 * conditions an operator would want a saturation warning for. Treat a
 * nonzero value as evidence of real trouble (e.g. per-CPU free-list
 * exhaustion), but do not read a 0 here as "the table isn't thrashing" —
 * flow_anomalies[1] is a narrower signal than its name suggests. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_anomalies SEC(".maps");
