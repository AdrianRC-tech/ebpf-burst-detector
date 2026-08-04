## Design Decisions — The Layer 1 → Layer 2 Interface

> **Scope.** This document records design decisions concerning what Layer 1 must expose so that
> Layer 2 (burst characterization / heavy hitters) can answer the question it exists to answer:
> **"which pods received more load while the burst happened?"** It complements `CLAUDE.md` §2 and
> `docs/design-decisions-cusum-calibration.md`, and it supersedes two recommendations recorded
> during analysis but never committed (§8). Each decision is stated with its justification so
> downstream contributors do not re-litigate it without cause.
>
> **Evidence basis.** Measurements come from `tmp/3.experiments_second_iterations/` (30-minute
> baseline captures at 50/100/200 ms, and burst runs), and from
> `tmp/1.general_validations/delay_burst_start_and_receival_in_cluster/` (cluster propagation
> delay and the first per-window capture of burst traffic). Where a number is *simulated* rather
> than measured, it is labelled as such — several load-bearing numbers still are, and §9 lists the
> experiments that would replace them.

---

### 0. Terminology

- **Burst interval** — the true `[start, end]` of the offered burst load, as driven by `wrk2`.
- **Flag interval** — `[onset detection, drain detection]`, i.e. the period during which
  `burst_flag == 1`. This is Layer 1's current sole output.
- **Change point** — the CUSUM estimate of when the upward shift began: the last window at which
  `upper_sum` was zero. In CUSUM theory this is the maximum-likelihood estimator of the change
  time, and it is already implicit in the algorithm — it is simply not recorded today.
- **Coverage** — the fraction of the burst interval that is inside the interval Layer 2 counts over.
- **Burst fraction** — of the bytes Layer 2 counts, the fraction actually attributable to the
  burst rather than to concurrent baseline traffic. Coverage and burst fraction are independent;
  see §5.

---

### 1. Problem statement — `burst_flag` alone is not a sufficient interface

**The flag interval is not the burst interval.** It is a *lagged, partially overlapping* interval.
Measured on the burst runs (`tmp/3.experiments_second_iterations/*/​*latencies_differences.txt`,
reconstructed against the `wrk2` execution logs):

| config | 1 burst → 1 flag | split | missed | burst covered | overhang past burst end |
|---|---|---|---|---|---|
| 50 ms / 3 min calib | 9 | 1 | 0 | 72% | 0.29 s |
| 50 ms / 30 min calib | 8 | 1 | 1 | 39% | 0.20 s |
| 100 ms / 3 min calib | 9 | 0 | 1 | 54% | 0.65 s |
| **100 ms / 30 min calib** | **10** | **0** | **0** | 39% | 0.67 s |
| 200 ms / 3 min calib | 8 | 0 | 2 | 25% | 1.22 s |
| 200 ms / 30 min calib | 5 | 0 | **5** | **10%** | 1.07 s |

Two things follow. First, **burst splitting is not a window-size argument** — 100 ms and 200 ms
both produce zero splits; the only splits in the sweep are at 50 ms. Second, and decisively,
**detection latency is the dominant coverage loss.** The cluster propagation delay is bounded at
≤ 25 ms (`tmp/1.general_validations/…/10ms_delays_collection.txt`: onset delays 9–16 ms, drain
delays 5–25 ms), so essentially all of the measured 0.5–0.8 s onset latency is detection delay
occurring *while the burst is already in progress*. Every millisecond of it is burst that a
flag-gated Layer 2 never observes.

---

### 2. Decision — Layer 1 records the CUSUM change point and emits it with the onset event

**Decision.** `cusum_state_t` gains `accum_start_ns`, updated in the quiescent branch:

```c
__u64 now = bpf_ktime_get_ns();
if (st->upper_sum == 0)
        st->accum_start_ns = now - window_ns;  /* slides while quiescent, freezes on first accumulation */
st->upper_sum += (__s64)delta - (__s64)mu_0 - (__s64)k;
```

`struct burst_event` gains `change_point_ns` (32 → 40 bytes). The symmetric construction on
`lower_sum` yields a corrected burst *end*.

**Why `now - window_ns` and not `now`.** The tick at time `T` processes bytes accumulated over
`[T − window_ns, T]`. If `upper_sum` was zero entering the tick and positive leaving it, the shift
began somewhere inside that window; the earliest defensible estimate is `T − window_ns`. At 100 ms
this is a full window of coverage that would otherwise be discarded.

**Why it is nearly free.** No new map, no new helper, no extra branch on the packet path — the
field re-arms on every zero-valued window, so "last zero" is maintained without a comparison. It
runs in the 10 Hz timer, never in the ≥ 1 Mpps data path.

**Cost.** The ring buffer event layout changes, which is a lockstep change with
`cmd/cusum-detector/events.go` (`burstEventSize`), `events_test.go` (asserts byte offsets),
`eventlog.go` (CSV column), and regenerated `bpf_bpfel.go`. The offset assertions in
`events_test.go` are the designed guard for exactly this class of change.

**Simulated effect** (see §9 — depends on the burst-amplitude estimate): coverage rises from 42%
to 88% at 100 ms / `h = 6σ̂`.

---

### 3. Decision — `burst_flag` remains the real-time signal; the ring buffer carries the corrected interval

**Decision.** The change point does **not** alter when `burst_flag` is asserted, and does not
change the FSM. It is an annotation on the onset event. Layer 1 therefore has two consumers with
different contracts:

| consumer | reads | semantics | latency |
|---|---|---|---|
| real-time reaction | `burst_flag` map | "a burst is happening now" | detection-limited |
| characterization | `burst_events` ring | "a burst occurred over `[change_point, drain_point]`" | retrospective |

**Why separate them rather than delay the flag.** Any attempt to make the flag itself
retroactive is incoherent — the flag is a present-tense signal. Splitting the contract keeps
`CLAUDE.md` §2.7's real-time output intact for any future control-plane consumer while giving
characterization the interval it actually needs. Consumers reading only `burst_flag` are
unaffected by this change.

**Corollary — this is what makes §4 possible.** An architecture in which detection *turns
collection on* structurally loses the leading edge of every event, with the detection lag as a
hard floor on what is missed. An architecture in which collection runs continuously and detection
*selects what to retain* has no such floor. Layer 1's output contract determines which of these
Layer 2 is able to choose.

---

### 4. Decision — Layer 2 counts continuously and retains selectively; it is not flag-gated

**Decision.** Layer 2's data path maintains a per-pod cumulative byte counter at all times. A
timer snapshots that counter array into a small circular buffer once per window. Top-k over
`[change_point, now]` is an elementwise **subtraction between two snapshots**, computed once per
burst.

**What this is not.** It is not continuous top-k computation. No sorting, no sketch maintenance,
and no heavy-hitter algorithm runs in steady state. It is also not a retention/eviction problem:
counters are cumulative and monotonic (as `node_ingress_bytes` already is), the ring overwrites
itself by construction, and nothing is ever deleted.

**Cost.**

| stage | frequency | work |
|---|---|---|
| data path | per packet (≥ 1 Mpps) | `bytes[pod] += skb->len` — one map operation |
| snapshot | 10 Hz | copy per-pod array into ring slot — ~500 map ops/s at 50 pods |
| top-k | once per burst | two reads, a subtraction, a selection |

Memory at 50 pods × 32 windows × 8 B = **12.5 KiB per CPU**. Ring depth is set by the lookback
from detection to change point — *simulated* at 100 ms / `h = 6σ̂` as p99 = 9 windows, max = 15;
32 windows (3.2 s) is comfortable. Note that 200 ms requires a **deeper wall-clock** lookback than
100 ms, because slower detection puts the change point further behind.

**What is genuinely given up.** The property that Layer 2 costs nothing until a burst occurs.
This roughly doubles the data-path cost — from one per-CPU array increment to two map operations —
estimated at 2–5% → 4–10% of a core at 1 Mpps against `CLAUDE.md` §1's budget. **This is an
estimate, not a measurement, and should be benchmarked before committing.**

**Relation to `CLAUDE.md` §4.3 point 4.** That rule requires *Layer 1's* data-path program to be
identity-free so one object can attach everywhere. Layer 2 is per-pod attribution by definition,
so its program may carry identity (e.g. keyed on `skb->ifindex`, or a per-attachment `.rodata`
index). This is the layer boundary from §2.1 working as intended, not an exception to it.

**Cheaper variant, recorded for completeness.** Sample the continuous counting at 1-in-N and
switch to full rate once the flag rises. Top-k is a *ranking*, so a sampled pre-flag count still
orders heavy hitters correctly while cutting the always-on cost by N; in-burst totals stay exact.
Adopt if the benchmark in §9 shows the full-rate cost is unaffordable.

---

### 5. Decision — Layer 2 ranks by **excess over per-pod baseline**, not by absolute bytes

**Context.** Interval accuracy and attribution are independent problems, and fixing the first
does not fix the second. Using the measured baseline (1.36 MB/s) and measured burst increment
(1.76 MB/s over 1 s):

| interval Layer 2 counts over | length | burst bytes | baseline bytes | burst fraction |
|---|---|---|---|---|
| flag interval (today) | 1093 ms | 0.74 MB | 1.49 MB | **33%** |
| change-point start, flag drain end | 1550 ms | 1.55 MB | 2.11 MB | 42% |
| change-point + corrected drain end | 880 ms | 1.55 MB | 1.20 MB | 56% |
| **perfect interval (upper bound)** | 1000 ms | 1.76 MB | 1.36 MB | **56%** |

Today only **33%** of what a flag-gated Layer 2 would count is burst traffic — a top-k over that
ranks baseline load more than burst load. But note the last row: **even a perfect interval is only
56% burst traffic**, because the burst is 2.29× baseline and so baseline contributes 44% of the
bytes during the burst itself. This is a property of ranking by absolute bytes and no interval
correction can remove it.

**Decision.** Score pods by excess over their own pre-burst rate:

```
score[pod] = (counter_now[pod] − counter_at_changepoint[pod]) − baseline_rate[pod] × interval
```

| ranking basis | burst signal captured | burst-attributable |
|---|---|---|
| absolute bytes, flag interval | — | 33% |
| excess, flag interval | 42% | **100%** |
| excess, corrected interval | **88%** | **100%** |

**Why this is the same idea Layer 1 already uses.** `delta − mu_0` is exactly this subtraction at
node scope. Layer 2's top-k is the per-pod form of the CUSUM slack term.

**Ordering note.** Of the two fixes, excess-ranking matters more: it converts a fundamentally
wrong answer into a correct but under-powered one, whereas the change point converts an
under-powered answer into a well-powered one. Both are wanted; if only one ships, ship this.

---

### 6. Decision — the per-pod baseline reference comes from the snapshot ring, not from offline calibration

**Rejected alternative (A′).** Keep Layer 2 flag-gated and compute excess against an
*offline-calibrated* per-pod baseline. This is cheap (zero steady-state cost) and *correct*, just
under-powered (42% of the burst signal).

**Why rejected — the coverage argument, which stands alone.** A′ captures 42% of the burst signal
versus 88% for the ring-based reference (§5). That gap is a property of when collection starts and
is unaffected by how well the baseline is calibrated.

**A weaker secondary argument, stated at its true strength.** A′ needs 20–50 offline parameters
instead of one, and per-pod baselines carry higher relative variance than the node-wide baseline
(fewer bytes per pod ⇒ higher CV), so each is harder to pin down than `mu_0` is. Note this is
*not* backed by a large measured node-wide instability: at 100 ms the cross-capture spread of
`mu_0` is 3.3% (1.8 SE — not significant); see §8.3. Do not cite calibration fragility as the
primary reason to reject A′.

**Decision.** Take the baseline reference from a ring slot preceding the change point. It is
measured in the same run, seconds before the burst, per pod, and it needs no offline per-pod
capture step. The ring built for §4 serves both purposes.

---

### 7. Window size — 100 ms; 200 ms and 50 ms are rejected

**The noise is aggregation noise, not a load-generator pathology.** Re-binning the 50 ms baseline
stream ×4 reproduces the independently captured 200 ms distribution almost exactly
(`mu_0` 320,273 / CV 0.46 vs. measured 318,883 / CV 0.46). CV falls as 1/√n across the sweep
(1.06 → 0.65 → 0.46). Consequences: the variance is inherent to arrival and response-size
distribution, it is white (lag-1 autocorrelation 0.006), and **averaging is the only lever**.

**200 ms rejected.** It is worst on every axis including burst integrity, which was the reason to
consider it: 10% coverage, 5/10 bursts missed, 1.07 s overhang, and a deeper required lookback
than 100 ms. Coarser windows enlarge the retrospection problem rather than reducing it.

**50 ms rejected.** CV 1.06 (σ̂ ≈ `mu_0`) is an information floor, not a tuning failure. It is
also the only configuration in the sweep that split bursts.

---

### 8. Superseded recommendations

Recorded so they are not revived:

1. **`h = 8σ̂` — rejected.** Recommended during analysis on the basis of an *assumed* 3× burst
   amplitude. Against the measured 2.29× amplitude it costs ~23% missed bursts at 100 ms and
   ~56% at 200 ms. **Do not raise `h`.** `h = 6σ̂` stands.
2. **Online baseline tracking (frugal-median / EWMA `mu_0`) — deferred, not adopted.** It makes
   the false-alarm rate invariant to calibration error at ~zero latency cost, and out-of-sample it
   beats static calibration at 100 ms (0 vs 20 FP/hr). But it is *neutral* at 200 ms and *worse*
   at 50 ms, and it helps only where the baseline genuinely drifts. Per §8.3 the measured drift at
   100 ms is not significant. Do not implement without new evidence.

3. **The "19–50% cross-run baseline instability" claim — retracted; it was a data error.**
   It was computed from `tmp/2.experiments_first_iteration/exp1_finetunning_data_csv/offline_baseline_*.csv`,
   which are the *raw* captures with warm-up rows still present. The calibrations actually used the
   `exp1_modified_offline_baseline_*.csv` files (row counts 2085 / 1123 / 528 match the
   `*_finetunning_comp.md` records exactly). Corrected figures:

   | window | iter1 | iter2 3-min | iter2 30-min | spread | iter2 gap in SE(median) |
   |---|---|---|---|---|---|
   | 50 ms | 63,946 | 61,254 | 67,467 | 9.7% | 4.9 SE |
   | **100 ms** | **127,307** | **131,953** | **136,317** | **6.8%** | **1.8 SE — not significant** |
   | 200 ms | 284,925 | 260,143 | 318,883 | 20.4% | 12.7 SE |

   At 100 ms the spread is within sampling error of the median. The large figure came from 200 ms,
   a window size rejected on independent grounds (§7). Any argument in this repository that leans
   on baseline instability must cite these numbers, not the retracted ones.

---

### 9. Open questions — pre-registered experiments

Two numbers this document leans on are not yet measured. Both experiments are cheap and require
no code changes.

**E1 — How stable is `mu_0` between captures at 100 ms? (low priority)** Three back-to-back
30-minute baseline captures, same cluster, same load, same node. Note this is **no longer a
decisive experiment**: per §8.3 the existing 100 ms captures already agree to 3.3%, within the
sampling error of the median, so §8.2 is effectively closed. E1 now only replaces a two-point
comparison with a three-point estimate carrying proper error bars. Decision rule: spread ≤ 8%
confirms offline calibration is sound and §8.2 is closed permanently; ≥ 15% reopens it. Run this
only after E2, and only if the schedule allows.

**E2 — What is the true burst amplitude?** Re-run the delay validation *with the baseline load
running*. The existing capture has no background load and its client-side `Transfer/sec` is
33.84 KB/s versus 54.79 KB/s in the experiment runs, so the measured 2.29× may understate the
real amplitude by up to ~1.6×. Every latency, coverage and burst-fraction number in §1–§5 sits
somewhere in the 2.29×–3.0× range because of this. The same capture answers a second question:
**does the pod mix shift across a burst?** If it does not, leading-edge loss costs statistical
power but not ranking correctness, which would materially weaken the case for §4.

**Open design question — the change-point clamp.** If baseline noise holds `upper_sum` above zero
before the real burst, `accum_start_ns` reaches back too far and the reported start drifts into
baseline. Simulated lookbacks are p99 = 9, max = 15 windows at 100 ms / `h = 6σ̂`, so a clamp
around 16–20 windows bounds it. **Undecided:** whether a bound that binds should silently truncate
or mark the event as having an unreliable start estimate. This has real consequences for how much
Layer 2 should trust the interval and should be decided before implementation.

**Unbenchmarked.** The 2× data-path cost estimate in §4.
