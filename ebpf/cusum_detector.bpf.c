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
//   - cusum_state holds the CUSUM accumulators, prev_total and the learned
//     baseline (n, mu, var) — no duplicated flag field.
//   - The baseline is learned online (docs/design-decisions-cusum-
//     calibration.md §7): mu/var via Welford (alpha = 1/n, n <= n_welford)
//     then EWMA (alpha = 1/ewma_div = W/tau). Onset uses k = sigma and
//     h_onset = 6 sigma. A window is learned only while quiescent and when
//     x - mu <= 3 sigma (one-sided gate). A burst held longer than t_max_ns
//     (= tau) is force-drained (reason = TIMEOUT) and setup re-runs.
//   - h_drain is derived at the onset transition as h_slack_mult * k_drain
//     (both arms in the same "slack units" currency — §5-6).
//   - Onset and drain transitions are emitted to burst_events (RINGBUF) for
//     userspace logging, each carrying a change_point_ns backdated to the
//     start of the window in which the active arm (upper_sum or lower_sum)
//     last left zero — an estimate of when the shift actually began, rather
//     than the later tick where the threshold was finally crossed.
//   - arm_timer is a SEC("syscall") entry program called once from userspace
//     via Program.Run() to initialise and start the timer.
//
// Kernel requirements:
//   bpf_loop                    ≥ 5.17  (per-CPU sum, isqrt)
//   bpf_map_lookup_percpu_elem  ≥ 5.13  (read other CPUs' slots)
//   bpf_timer_*                 ≥ 5.15
//   BPF_PROG_TYPE_SYSCALL       ≥ 5.18
//   BPF_MAP_TYPE_RINGBUF        ≥ 5.8
// All satisfied by host kernel 6.17.

#include "shared_maps.h"

// ---------------------------------------------------------------------------
// Parameters — set at load time via .rodata constant replacement.
// Only window_ns is user-facing; the loader derives ewma_div and t_max_ns
// from it (tau = max(10 s, 300 * W)). The rest are fixed algorithm constants,
// volatile const only so tests can override them.
// ---------------------------------------------------------------------------

volatile const __u64 window_ns       = 100000000;   // 100 ms default window
volatile const __u64 ewma_div        = 300;         // round(tau / W): EWMA alpha = 1/ewma_div once n > n_welford
volatile const __u64 t_max_ns        = 30000000000; // stuck-burst timeout (= tau)
volatile const __u64 n_setup         = 30;          // learned windows before detection arms
volatile const __u64 n_welford       = 300;         // exact Welford (alpha = 1/n) up to here, EWMA after
volatile const __u64 k_sigma_mult    = 1;           // k = k_sigma_mult * sigma
volatile const __u64 h_sigma_mult    = 6;           // h_onset = h_sigma_mult * sigma
volatile const __u64 gate_sigma_mult = 3;           // learn only if x - mu <= gate_sigma_mult * sigma
volatile const __u64 sigma_floor     = 1500;        // bytes; keeps k/h non-zero on silent traffic
volatile const __u64 h_slack_mult    = 6;           // drain threshold in slack units (h_drain = h_slack_mult * k_drain)
volatile const __u8  sample_windows  = 0;           // 1 = emit per-window byte sample for offline analysis

// ---------------------------------------------------------------------------
// Event types and structs
// ---------------------------------------------------------------------------

#define EVENT_ONSET 0
#define EVENT_DRAIN 1

#define REASON_THRESHOLD 0
#define REASON_TIMEOUT   1

struct burst_event {
	__u32 type;          // EVENT_ONSET or EVENT_DRAIN
	__u32 reason;        // REASON_THRESHOLD or REASON_TIMEOUT (drain only)
	__u64 cusum_value;   // upper_sum at onset, lower_sum at drain
	__u64 window_bytes;  // delta bytes in the triggering window
	__u64 change_point_ns; // estimated ktime of the traffic shift that produced this burst
	__u64 mu;            // learned baseline the window was judged against
	__u64 sigma;         // learned (floored) std-dev the window was judged against
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
	__u64 accum_start_ns; // ktime of the start of the window in which the active arm (upper_sum pre-onset, lower_sum during a burst) last left zero
	__u64 n;              // windows learned into the baseline (0 = setup restarts)
	__u64 mu;             // learned baseline, bytes per window
	__u64 var;            // learned variance, bytes^2
	__u64 burst_start_ns; // ktime of the onset tick, for the t_max_ns timeout
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

static __always_inline void emit_event(__u32 type, __u32 reason, __u64 cusum_value,
                                       __u64 window_bytes, __u64 change_point_ns,
                                       __u64 mu, __u64 sigma)
{
	struct burst_event *ev = bpf_ringbuf_reserve(&burst_events, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->type            = type;
	ev->reason          = reason;
	ev->cusum_value     = cusum_value;
	ev->window_bytes    = window_bytes;
	ev->change_point_ns = change_point_ns;
	ev->mu              = mu;
	ev->sigma           = sigma;
	bpf_ringbuf_submit(ev, 0);
}

// ---------------------------------------------------------------------------
// Online baseline helpers (integer only: no floats, no signed division)
// ---------------------------------------------------------------------------

// Digit-by-digit integer square root, 32 rounds via bpf_loop. An inline
// bounded for-loop branches on runtime values every round, so the verifier
// walks 2^32 paths; a bpf_loop callback is verified once.
struct isqrt_ctx {
	__u64 v, r, bit;
};

static long isqrt_cb(__u32 i, struct isqrt_ctx *c)
{
	if (c->v >= c->r + c->bit) {
		c->v -= c->r + c->bit;
		c->r = (c->r >> 1) + c->bit;
	} else {
		c->r >>= 1;
	}
	c->bit >>= 2;
	return 0;
}

static __always_inline __u64 isqrt(__u64 v)
{
	struct isqrt_ctx c = { .v = v, .r = 0, .bit = 1ULL << 62 };
	bpf_loop(32, isqrt_cb, &c, 0);
	return c.r;
}

// Finch (2009) incremental mean/variance with alpha = 1/D:
//   mu += d/D;  var = (1 - 1/D) * (var + d^2/D)
// D = n (exact population Welford) while n <= n_welford, ewma_div after.
static __always_inline void learn(struct cusum_state_t *st, __u64 x)
{
	st->n++;
	__u64 D = st->n <= n_welford ? st->n : ewma_div;
	if (D == 0)
		D = 1;
	__u64 d;
	if (x >= st->mu) {
		d = x - st->mu;
		st->mu += d / D;
	} else {
		d = st->mu - x;
		st->mu -= d / D;
	}
	if (d > (1ULL << 31))
		d = 1ULL << 31; // d^2 < 2^62
	__u64 t = st->var + d * d / D;
	st->var = t - t / D;
}

static __always_inline void reset_sums(struct cusum_state_t *st)
{
	st->upper_sum = 0;
	st->lower_sum = 0;
	st->mu_burst  = 0;
	st->k_drain   = 0;
	st->h_drain   = 0;
}

// ---------------------------------------------------------------------------
// FSM step — shared by the timer callback and the cusum_test_step entry
// ---------------------------------------------------------------------------

static __always_inline void cusum_step(struct cusum_state_t *st, __u32 *flag,
                                       __u64 delta, __u64 now)
{
	// Pre-update baseline: detection and the learning gate both judge this
	// window against what was learned before it.
	__u64 mu    = st->mu;
	__u64 sigma = isqrt(st->var);
	if (sigma < sigma_floor)
		sigma = sigma_floor;
	int was_quiet = *flag == 0;

	if (was_quiet) {
		if (st->n >= n_setup) {
			// The tick at T covers [T - window_ns, T]. If upper_sum was zero
			// entering this tick and positive leaving it, the shift began
			// inside that window, so T - window_ns is the earliest defensible
			// estimate. Re-arms on every zero window and freezes on first
			// accumulation.
			if (st->upper_sum == 0)
				st->accum_start_ns = now - window_ns;

			// CUSUM+: upper_sum = max(0, upper_sum + (delta - mu - k)), k = sigma
			st->upper_sum += (__s64)delta - (__s64)mu - (__s64)(k_sigma_mult * sigma);
			if (st->upper_sum < 0)
				st->upper_sum = 0;
			if (st->upper_sum >= (__s64)(h_sigma_mult * sigma)) {
				emit_event(EVENT_ONSET, REASON_THRESHOLD, st->upper_sum, delta,
				           st->accum_start_ns, mu, sigma);
				*flag = 1;
				st->upper_sum      = 0;
				st->lower_sum      = 0;
				st->mu_burst       = delta;
				st->k_drain        = (delta > mu) ? (delta - mu) / 2 : 0;
				st->h_drain        = h_slack_mult * st->k_drain;
				st->burst_start_ns = now;
			}
		}
		// One-sided gate: windows below mu are always learned (a downward
		// step must be tracked, the flag never rises to time it out). The
		// onset window itself is not learned (flag already 1).
		if (st->n < n_setup ||
		    (*flag == 0 && (delta <= mu || delta - mu <= gate_sigma_mult * sigma)))
			learn(st, delta);
		return;
	}

	// Burst state: nothing is learned. A burst outliving the baseline's own
	// memory (tau) is, by the EWMA's definition, the new level: force-drain
	// and re-run setup from scratch.
	if (now - st->burst_start_ns > t_max_ns) {
		emit_event(EVENT_DRAIN, REASON_TIMEOUT, st->lower_sum, delta, now, mu, sigma);
		*flag = 0;
		reset_sums(st);
		st->n = 0;
		return;
	}

	// Same backdating trick as the onset arm, mirrored onto lower_sum.
	if (st->lower_sum == 0)
		st->accum_start_ns = now - window_ns;

	// CUSUM-: lower_sum = max(0, lower_sum + (mu_burst - k_drain - delta))
	st->lower_sum += (__s64)st->mu_burst - (__s64)st->k_drain - (__s64)delta;
	if (st->lower_sum < 0)
		st->lower_sum = 0;
	if (st->lower_sum >= (__s64)st->h_drain) {
		emit_event(EVENT_DRAIN, REASON_THRESHOLD, st->lower_sum, delta,
		           st->accum_start_ns, mu, sigma);
		*flag = 0;
		reset_sums(st);
	}
}

// ---------------------------------------------------------------------------
// Timer callback — the hot path, runs every window_ns
// ---------------------------------------------------------------------------

static int cusum_tick(void *map, int *key, struct timer_val *val)
{
	// Re-arm immediately so the window is as regular as possible.
	bpf_timer_start(&val->timer, window_ns, 0);

	__u64 now = bpf_ktime_get_ns();

	struct sum_ctx sctx = {};
	bpf_loop(MAX_CPUS, sum_cb, &sctx, 0);
	__u64 total = sctx.total;

	__u32 zero = 0;
	struct cusum_state_t *st = bpf_map_lookup_elem(&cusum_state, &zero);
	if (!st)
		return 0;

	// Guard the (unlikely) wrap where the counter map was reset between ticks.
	__u64 delta = (total >= st->prev_total) ? (total - st->prev_total) : 0;
	st->prev_total = total;

	if (sample_windows) {
		struct window_sample *s = bpf_ringbuf_reserve(&window_samples, sizeof(*s), 0);
		if (s) {
			s->timestamp_ns = now;
			s->total        = total;
			s->delta        = delta;
			bpf_ringbuf_submit(s, 0);
		}
	}

	// burst_flag is the FSM state's single source of truth and Layer 1's
	// architectural output; cusum_step writes it in place.
	__u32 *flag = bpf_map_lookup_elem(&burst_flag, &zero);
	if (!flag)
		return 0;

	cusum_step(st, flag, delta, now);
	return 0;
}

// Test-only entry: drives cusum_step with a scripted (delta, now) via
// BPF_PROG_TEST_RUN, since the timer callback cannot be. Never run in
// production.
struct step_ctx {
	__u64 delta;
	__u64 now;
};

SEC("syscall")
int cusum_test_step(struct step_ctx *ctx)
{
	__u32 zero = 0;
	struct cusum_state_t *st = bpf_map_lookup_elem(&cusum_state, &zero);
	__u32 *flag = bpf_map_lookup_elem(&burst_flag, &zero);
	if (!st || !flag)
		return 1;
	cusum_step(st, flag, ctx->delta, ctx->now);
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
