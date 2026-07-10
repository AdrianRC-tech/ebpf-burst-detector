## Design Decisions — CUSUM Calibration & the Two-Sided Drain Reference

> **Scope.** This document records design decisions for Layer 1's CUSUM detector concerning
> (a) how the CUSUM parameters are calibrated, and (b) how the two sides of the CUSUM
> reference their baselines. Each decision is stated with its justification so downstream
> contributors do not re-litigate them without cause. It complements `CLAUDE.md` §2 and
> `docs/experiment-methodology.md` §5.

---

### 0. Terminology: the CUSUM input is a per-window statistic

The CUSUM consumes **one sample per window** (`delta_bytes` over a 100 ms window, tunable via
`window_ns`), produced by differencing the node-wide per-CPU byte counter between consecutive
timer ticks. Every statistic discussed below (median, mean/EWMA, variance) is computed **over
this per-window stream (~10 Hz)**, never over individual packets. The per-packet data path
remains a single `*bytes += skb->len` and is never touched by any calibration logic.

This distinction dissolves any "cost per packet" concern before it starts: calibration
statistics process ~10 numbers/second, not the ≥1 Mpps packet rate.

---

### 1. Decision — CUSUM parameters are calibrated **offline**, not computed online

**Decision.** `mu_0`, `k`, and `h_onset`/`h_drain` are derived offline by `cmd/baseline-stats`
from a captured, known-quiescent baseline (`mu_0 = median`, `k = k_mult · σ̂`,
`h = h_mult · σ̂`, with `σ̂ = 1.4826 · MAD`). They are baked into the BPF object at load time as
`volatile const` values (`.rodata`). No online/streaming estimation of these parameters is
performed in the kernel.

**Feasibility note (why not just do it online).** An *exact* streaming median is infeasible in
eBPF — it requires dynamically-sized structures (two-heaps) that the verifier rejects. Only
*approximate*, O(1)-state estimators (Frugal, P²) are feasible, and they run cheaply in the
timer tick. So the barrier to online calibration is **not** performance — it is statistical and
methodological:

1. **Bootstrap / cold-start.** Online baseline estimation must know *when it is not in a burst*
   to avoid absorbing burst traffic into the baseline. But that knowledge requires an
   already-calibrated detector — a circular dependency. Offline calibration breaks it using
   information an online estimator structurally cannot have: **we control the load generator, so
   we know the capture window is quiescent.**
2. **Reproducibility (decisive for this scenario).** Layer 1 is evaluated as a controlled
   experiment (detection latency, false-alarm rate, sensitivity vs. window size and burst
   profile). Online self-configuration makes parameters a function of each run's traffic
   history, so they differ per run and **confound** the measurement — a performance difference
   can no longer be attributed to the variable under test rather than to parameter drift.
   Offline calibration holds the parameters constant as a controlled independent variable.
3. **Inspectability.** Offline yields a fixed, documentable number (`mu_0 = median of N
   quiescent windows`) that a reviewer can check. An online value at time *T* is a function of
   the whole trace and cannot be justified in isolation.
4. **Warm-up correctness.** Streaming estimators converge slowly; during convergence the
   detector is mis-calibrated. Offline is correct from window 1.

**Where online would win.** For a shipped, long-lived production tool with a non-stationary
(diurnal) baseline, self-configuration is the correct end-state — nobody wants to re-capture a
baseline per node/workload manually. That is a production concern, not a measurement one.

**Reversibility / end-state.** Offline-first is also the correct *sequencing*: the offline
ground truth is what any future online estimator must be validated against. The mature end-state
is **offline cold-start seed + slow, `burst_flag`-gated online drift-tracking** — deterministic
and reproducible for experiments, adaptive for long production runs. Out of scope for Layer 1.

---

### 2. Decision — Online EWMA baseline adaptation is **deferred**; it is not a detection-speed mechanism

**Decision.** No online EWMA (or any adaptive) baseline is used in Layer 1. If adaptivity is
added later it is a robustness feature for baseline drift, explicitly **not** a latency feature.

**Why it cannot improve detection speed.** Onset detection latency for a step burst is
governed by two things, neither of which the baseline estimator enters at detection time:

- the **window size** (a hard quantization floor on reaction time), and
- the **accumulation dynamics**: onset fires after roughly
  `⌈ h_onset / (delta − mu_0 − k) ⌉` windows.

An EWMA changes only the *value* of `mu_0`; it does not enter the loop that crosses the
threshold. For a stationary baseline, a valid (slow) EWMA converges to the same value offline
calibration produces, so the accumulation rate — and thus the detection speed — is identical.

**Structural argument (why this is guaranteed, not incidental).** An adaptive baseline is only
*safe* if it adapts slowly: an EWMA fast enough to matter on burst timescales would track the
burst itself (contamination) and *delay or suppress* detection. So "fast enough to affect
detection speed" and "slow enough to be a valid baseline" are mutually exclusive by
construction. A safe EWMA cannot influence fast detection even in principle.

**Non-stationary nuance (state precisely, do not overclaim).** Under a drifting baseline, EWMA
does not *improve* peak detection speed — it *preserves* the speed a correctly-calibrated static
baseline would have had, in the case where a stale static `mu_0` would otherwise inflate the
accumulation denominator and slow onset. It is a consistency mechanism, not a speed mechanism.

**Why it complicates the experiment.** Beyond the speed argument, an online EWMA reintroduces
the reproducibility/confounding problem of §1: parameters would evolve during a run, and
detection-performance comparisons across scenarios would no longer isolate the variable under
test. For the measurement phase, a fixed baseline is a feature.

---

### 3. Decision — The drain (lower) CUSUM references the **burst level `mu_burst`**, not the baseline `mu_0`

**Context.** Textbook two-sided CUSUM references *both* sums to a single `mu_0`: the upper sum
detects a positive shift above baseline, the lower sum a negative shift below baseline. For a
*burst lifecycle* detector this is wrong.

**Why `mu_0` cannot detect drain.** A `mu_0`-referenced lower CUSUM accumulates only when
`delta < mu_0 − k`:

```
lower_sum += (mu_0 − k) − delta
```

- During a burst, `delta ≈ mu_burst ≫ mu_0` → increment strongly negative → stays clamped at 0.
- On return to baseline, `delta ≈ mu_0` → increment `= −k` → **still negative → never fires.**

So a symmetric `mu_0`-referenced detector catches `{burst above baseline, drop *below*
baseline}` — the latter being an under-load / traffic-loss event — **not** `{onset, drain}`.
A burst that returns *to* baseline (the good case) is not a drop below it, and is therefore
invisible to a `mu_0` lower sum.

**Why `mu_burst` works.** Referencing the captured burst level:

```
lower_sum += (mu_burst − k) − delta
```

- While `delta ≈ mu_burst`, increment `≈ −k` → stays at 0.
- When `delta` falls back toward `mu_0`, increment `≈ mu_burst − k − mu_0` (large positive) →
  fires. This is return-to-baseline detection.

**Decision:** the lower CUSUM references `mu_burst`, seeded at the onset transition
(`cusum_detector.bpf.c`: `st->mu_burst = delta` at onset).

**Options for estimating `mu_burst` (recorded for future tuning).**

| Option | Behavior | Trade-off |
|---|---|---|
| **Snapshot of onset window** (current) | `mu_burst = delta` at the triggering window | Hostage to *where on the burst trajectory* onset fired; an onset spike inflates the reference (premature drain), a mid-ramp onset deflates it (sluggish drain). |
| **EWMA over burst windows** | Track the *sustained* burst level | Smooths the onset spike; but re-introduces contamination on the drain side (EWMA chases a gradual ramp-down, so drain may never accumulate cleanly) and adds convergence lag right after onset. |

The current snapshot is adequate for initial evaluation; EWMA is the fallback if snapshot-driven
drain proves unstable on noisy or stepped bursts.

---

### 4. Decision — `k_drain` must be **recomputed at onset**; it is not the same as `k_onset`

**Rationale.** In CUSUM theory `k` is pinned to the shift being detected: `k = (shift
magnitude)/2`. This is what makes the detector optimal for that shift. The two sides detect
shifts of different magnitudes:

- **Onset** detects a shift *up* from `mu_0`. The burst size is unknown at onset, so `k_onset`
  is set from the *target sensitivity* ("detect bursts ≥ M×baseline" → `k_onset =
  (M−1)·mu_0 / 2`). A legitimate load-time constant.
- **Drain** detects a shift *down* of magnitude `(mu_burst − mu_0)` — a value known **only at
  runtime**. The matched slack is therefore `k_drain = (mu_burst − mu_0) / 2`, computed at the
  onset transition.

**Consequence of reusing `k_onset` on the drain side (the current oversimplification).** The
drain reference point is `mu_burst − k`:

- With correct `k_drain = (mu_burst − mu_0)/2` → reference `= (mu_burst + mu_0)/2`, the
  **midpoint**. Drain fires when traffic has fallen halfway back to baseline — sensible.
- With `k = k_onset` (sized to baseline, hence small) → reference `≈ mu_burst − small`, i.e.
  **just below the peak.** Any transient dip below the burst plateau triggers drain → premature
  drain and `burst_flag` oscillation on stepped/noisy bursts.

**Decision:** compute `k_drain = (mu_burst − mu_0) / 2` in-kernel at the onset transition
(alongside `mu_burst`), and use it in the lower-sum update instead of the shared `k`. This is a
correctness fix, not a tuning preference. It moves the drain slack from a load-time constant to
an onset-time-derived value.

> A more interpretable equivalent, if the statistical framing proves hard to reason about, is a
> **return-fraction hysteresis**: declare drain once `delta` stays below
> `mu_0 + ρ·(mu_burst − mu_0)` for a sustained window count. This is algebraically a
> `mu_burst`-referenced CUSUM with `k_drain = (1−ρ)(mu_burst − mu_0)`, but exposes `ρ`
> ("how close to baseline counts as drained") as an explicit knob.

---

### 5. Decision — `h_drain` is **left fixed** (not adapted per burst) for now

**Rationale.** `h` (the decision threshold) trades **detection delay against false-alarm rate**,
and that trade-off is governed by the signal's *noise*, not its mean — a different quantity from
what `k` matches. In principle `h_drain` *should* differ from `h_onset`, for two reasons:

1. **Latency scaling.** Post-return, the drain accumulates at mean rate `(mu_burst − mu_0)/2`
   (with correct `k_drain`), so drain delay `≈ h_drain / [(mu_burst − mu_0)/2]`. A fixed
   `h_drain` makes drain latency **burst-magnitude-dependent** (huge bursts drain in ~1 window;
   marginal bursts drain slowly). Uniform drain latency would require `h_drain` to scale with
   `(mu_burst − mu_0)`.
2. **False-drain robustness.** A false drain (declaring the burst over on a transient dip) is
   governed by `h_drain` relative to the **variance of burst-level traffic**, which is generally
   *not* the baseline variance (for byte-count signals, variance tends to grow with the mean).
   An `h_drain` calibrated to quiet-baseline `σ̂` is effectively too small against burst noise.

**Why we do not adapt it (the engineering call).** Doing `h_drain` "correctly" requires an
**online variance estimate over burst windows** — computed from very few, short samples, at
runtime, inside the kernel. This is fragile and adds state, branches, and verifier surface,
directly against Layer 1's "measure and detect only / identity-free" mandate (`CLAUDE.md` §2,
§6.5). The high-value correctness fix is `k_drain` (§4); adapting `h_drain` is a second-order
refinement.

**Decision:** keep `h_drain` a fixed `volatile const` (calibrated to baseline noise). Accept
that drain *latency* varies with burst magnitude and document it. Revisit only if a scenario
demonstrates that fixed-`h_drain` drain behavior (either sluggish drain on marginal bursts or
false drains on noisy bursts) is a measured problem — at which point burst-variance
normalization becomes justified.

---

### 6. Summary

| Parameter / mechanism | Decision | Why |
|---|---|---|
| `mu_0`, `k`, `h` calibration | **Offline** (`baseline-stats`), baked as `volatile const` | Bootstrap + reproducibility + inspectability; online is a production end-state, not a measurement one. |
| Online EWMA baseline | **Deferred** | Cannot improve detection speed (structural); confounds controlled experiments. |
| Drain reference | **`mu_burst`**, not `mu_0` | `mu_0` lower sum detects drop-*below*-baseline, not return-*to*-baseline. |
| `mu_burst` estimation | **Snapshot at onset** (EWMA as fallback) | Adequate for evaluation; EWMA trades spike-smoothing for drain-side contamination. |
| `k_drain` | **Recompute at onset** `= (mu_burst − mu_0)/2` | `k = shift/2`; drain shift is runtime-only. Reusing `k_onset` → drain fires just below the peak → oscillation. **Correctness fix.** |
| `h_drain` | **Fixed for now** | Correct adaptation needs online burst-variance estimation — fragile, against Layer 1 simplicity. Revisit if scenarios prove need. |

**Open question deferred to evaluation:** whether drain *latency* must be uniform across burst
magnitudes. If yes, `h_drain` must scale with `(mu_burst − mu_0)` (and ideally burst σ); if
variable drain latency is acceptable given tight onset latency, the fixed-`h_drain` decision in
§5 stands.
