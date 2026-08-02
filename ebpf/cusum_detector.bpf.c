// SPDX-License-Identifier: GPL-2.0
//
// cusum_detector.bpf.c — Two-sided CUSUM burst detector.
//
// Architecture:
//   - A bpf_timer embedded in timer_map fires every window_ns nanoseconds
//     and calls cusum_tick(). The timer re-arms itself at the top of every
//     invocation so the window is as regular as possible.
//   - cusum_tick() sums every CPU's slot of node_ingr_bytes (shared with
//     the data-path program via LIBBPF_PIN_BY_NAME), computes the per-window
//     byte delta against the previous reading stored in cusum_state, then
//     advances the two-sided CUSUM finite state machine.
//   - The FSM has two states stored in the burst_flag map (single source of
//     truth — Layer 1's architectural output per CLAUDE.md §2 point 7):
//       0 = quiescent — running upper CUSUM upper_sum to detect burst onset
//       1 = burst     — running lower CUSUM lower_sum to detect burst drain
//   - cusum_state holds only the CUSUM accumulators (upper_sum, lower_sum)
//     and prev_total — no duplicated flag field.
//   - h_drain is derived at the onset transition as h_slack_mult * k_drain
//     (both arms expressed in the same "slack units" currency — see
//     docs/design-decisions-cusum-calibration.md §5-6), unless the static
//     h_drain override is non-zero, in which case that value wins.
//   - Onset and drain transitions are emitted to burst_events (RINGBUF) for
//     userspace logging.
//   - arm_timer is a SEC("syscall") entry program called once from userspace
//     via Program.Run() to initialise and start the timer.
//
// Kernel requirements:
//   bpf_loop                    ≥ 5.17  (verifier-friendly bounded iteration)
//   bpf_map_lookup_percpu_elem  ≥ 5.13  (read other CPUs' slots)
//   bpf_timer_*                 ≥ 5.15
//   BPF_PROG_TYPE_SYSCALL       ≥ 5.18
//   BPF_MAP_TYPE_RINGBUF        ≥ 5.8
// All satisfied by host kernel 6.17.

#include "shared_maps.h"

// ---------------------------------------------------------------------------
// Tunable parameters — set at load time via .rodata constant replacement.
// Most values are in bytes (mu_0, k, h_onset, h_drain) or nanoseconds
// (window_ns); h_slack_mult is dimensionless (a threshold expressed in
// slack units, applied to the drain arm — see docs/design-decisions-
// cusum-calibration.md §5-6).
// ---------------------------------------------------------------------------

volatile const __u64 mu_0          = 1000000;  // baseline bytes per window
volatile const __u64 k             = 500000;   // slack factor (half the expected step)
volatile const __u64 h_onset       = 5000000;  // onset threshold
volatile const __u64 h_drain       = 0;        // static drain threshold override; 0 = derive from h_slack_mult * k_drain
volatile const __u64 h_slack_mult  = 6;       // drain threshold in slack units (h_drain = h_slack_mult * k_drain); loader always injects a computed value in practice
volatile const __u64 window_ns     = 100000000; // 100 ms default window
volatile const __u8  sample_windows = 0;  // 1 = emit per-window byte sample for offline CUSUM tuning

// ---------------------------------------------------------------------------
// Event types and structs
// ---------------------------------------------------------------------------

#define EVENT_ONSET 0
#define EVENT_DRAIN 1

struct burst_event {
	__u64 timestamp_ns;
	__u32 type;          // EVENT_ONSET or EVENT_DRAIN
	__u32 _pad;
	__u64 cusum_value;   // upper_sum at onset, lower_sum at drain
	__u64 window_bytes;  // delta bytes in the triggering window
};

struct window_sample {
	__u64 timestamp_ns;
	__u64 total;   // cumulative bytes since program load
	__u64 delta;   // bytes in this window
};

// FSM accumulator storage only — current state (quiescent / burst) lives in
// the separate burst_flag map (Layer 1's architectural output per CLAUDE.md
// §2 point 7). Keeping the flag in only one place avoids consistency bugs.
struct cusum_state_t {
	__s64 upper_sum;    // CUSUM+ accumulator (clamped >= 0)
	__s64 lower_sum;    // CUSUM- accumulator (clamped >= 0)
	__u64 prev_total;   // total bytes at end of previous window
	__u64 mu_burst;     // burst-level estimate; seeded at onset, used as drain reference
	__u64 k_drain;      // drain slack; computed at onset = (mu_burst - mu_0) / 2 (design-decisions §4)
	__u64 h_drain;      // per-burst effective drain threshold; computed at onset = h_drain (static) or h_slack_mult * k_drain (design-decisions §5-6)
};

struct timer_val {
	struct bpf_timer timer;
};

// ---------------------------------------------------------------------------
// Maps (node_ingr_bytes is declared in shared_maps.h)
// ---------------------------------------------------------------------------

// Timer storage. The bpf_timer must live in an ARRAY or HASH map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct timer_val);
	__uint(max_entries, 1);
} timer_map SEC(".maps");

// CUSUM FSM state — single entry.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cusum_state_t);
	__uint(max_entries, 1);
} cusum_state SEC(".maps");

// Burst flag — single-entry array for fast downstream consumption.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} burst_flag SEC(".maps");

// Ring buffer for onset/drain events to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16); // 64 KiB — power-of-two required
} burst_events SEC(".maps");

// Separate from burst_events so the high-rate tuning stream never mixes with onset/drain events.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB — power-of-two required
} window_samples SEC(".maps");

// ---------------------------------------------------------------------------
// Per-CPU counter sum via bpf_loop
// ---------------------------------------------------------------------------
//
// Why not bpf_map_lookup_elem? On a PERCPU_ARRAY, the kernel-side helper
// returns a pointer to the CURRENT CPU's slot only. To sum all CPUs from a
// timer callback (which runs on some arbitrary CPU), we must enumerate them
// with bpf_map_lookup_percpu_elem. bpf_loop bounds the iteration for the
// verifier; lookups past nr_possible_cpus return NULL and contribute zero.

#define MAX_CPUS 256

struct sum_ctx {
	__u64 total;
};

static long sum_cb(__u32 cpu, struct sum_ctx *ctx)
{
	__u32 zero = 0;
	__u64 *slot = bpf_map_lookup_percpu_elem(&node_ingr_bytes, &zero, cpu);
	if (slot)
		ctx->total += *slot;
	return 0;
}

// ---------------------------------------------------------------------------
// Helper: emit an event to the ring buffer
// ---------------------------------------------------------------------------

static __always_inline void emit_event(__u32 type, __u64 cusum_value, __u64 window_bytes)
{
	struct burst_event *ev = bpf_ringbuf_reserve(&burst_events, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->type         = type;
	ev->_pad         = 0;
	ev->cusum_value  = cusum_value;
	ev->window_bytes = window_bytes;
	bpf_ringbuf_submit(ev, 0);
}

// ---------------------------------------------------------------------------
// Helper: mirror the FSM flag to burst_flag for downstream consumers
// ---------------------------------------------------------------------------

static __always_inline void set_burst_flag(__u32 value)
{
	__u32 key = 0;
	bpf_map_update_elem(&burst_flag, &key, &value, BPF_ANY);
}

// ---------------------------------------------------------------------------
// Timer callback — the hot path, runs every window_ns
// ---------------------------------------------------------------------------

static int cusum_tick(void *map, int *key, struct timer_val *val)
{
	// Re-arm immediately so the window is as regular as possible even if
	// the FSM body is expensive.
	bpf_timer_start(&val->timer, window_ns, 0);

	// Sum every CPU's slot of node_ingress_bytes.
	struct sum_ctx sctx = {};
	bpf_loop(MAX_CPUS, sum_cb, &sctx, 0);
	__u64 total = sctx.total;

	// Look up the FSM state. cusum_state is an ARRAY map with one entry, so
	// this lookup always succeeds in practice; the verifier still requires
	// the NULL check.
	__u32 zero = 0;
	struct cusum_state_t *st = bpf_map_lookup_elem(&cusum_state, &zero);
	if (!st)
		return 0;

	// Per-window byte delta. Guard against the (extremely unlikely) wrap
	// where total < prev_total — could only happen if the counter map was
	// reset between ticks. Treat that case as a zero-delta window.
	__u64 delta = (total >= st->prev_total) ? (total - st->prev_total) : 0;
	st->prev_total = total;

	// Emit a per-window sample to allow CUSUM tuning if requested (parameter specified at program load).
	if (sample_windows) {
		struct window_sample *s = bpf_ringbuf_reserve(&window_samples, sizeof(*s), 0);
		if (s) {
			s->timestamp_ns = bpf_ktime_get_ns();
			s->total        = total;
			s->delta        = delta;
			bpf_ringbuf_submit(s, 0);
		}
	}

	// Read the FSM's current state from burst_flag — the single source of
	// truth. burst_flag is also Layer 1's architectural output, so reading
	// it here avoids any duplicated-state-consistency concerns.
	__u32 *flag = bpf_map_lookup_elem(&burst_flag, &zero);
	if (!flag)
		return 0;

	if (*flag == 0) {
		// Upper CUSUM, detecting burst onset.
		// CUSUM+ Formula: upper_sum = max(0, upper_sum + (delta - mu_0 - k))
		st->upper_sum += (__s64)delta - (__s64)mu_0 - (__s64)k;
		if (st->upper_sum < 0)
			st->upper_sum = 0;
		if (st->upper_sum >= h_onset) {
			emit_event(EVENT_ONSET, st->upper_sum, delta);
			set_burst_flag(1);
			st->upper_sum = 0;
			st->lower_sum = 0;
			st->mu_burst =  delta;
			st->k_drain  = (delta > mu_0) ? (delta - mu_0) / 2 : 0;
			// h_drain (the static override) wins if set; otherwise derive the
			// drain threshold in the same slack-unit currency as h_onset.
			st->h_drain  = h_drain ? h_drain : h_slack_mult * st->k_drain;
		}
	} else {
		// Lower CUSUM, detecting burst drain.
		// CUSUM- Formula: lower_sum = max(0, lower_sum + (mu_burst - k_drain - delta))
		st->lower_sum += (__s64)st->mu_burst - (__s64)st->k_drain - (__s64)delta;
		if (st->lower_sum < 0)
			st->lower_sum = 0;
		if (st->lower_sum >= (__s64)st->h_drain) {
			emit_event(EVENT_DRAIN, st->lower_sum, delta);
			set_burst_flag(0);
			st->upper_sum = 0;
			st->lower_sum = 0;
			st->mu_burst  = 0;
			st->k_drain   = 0;
			st->h_drain   = 0;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------
// SEC("syscall") entry point — called once from userspace via Program.Run()
// ---------------------------------------------------------------------------

SEC("syscall")
int arm_timer(void *ctx)
{
	__u32 zero = 0;
	struct timer_val *val = bpf_map_lookup_elem(&timer_map, &zero);
	if (!val)
		return 1;

	// CLOCK_MONOTONIC = 1. The low 4 bits of flags select the clock.
	bpf_timer_init(&val->timer, &timer_map, 1 /* CLOCK_MONOTONIC */);
	bpf_timer_set_callback(&val->timer, cusum_tick);
	bpf_timer_start(&val->timer, window_ns, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
