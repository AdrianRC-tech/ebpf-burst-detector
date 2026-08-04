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

> **Resolved by evaluation — see `docs/conclusions_from_first_experiments.md` §3.** The first
> window-size sweep measured snapshot-driven drain as unstable: baseline CV is 1.00 at 50 ms, so
> the single onset sample carries ~±100% error, and the measured Spearman correlation between the
> onset window's byte count and the resulting drain latency is −0.63 / −0.60 / −0.79. The finding
> survived recalibration of the 100 ms configuration, confirming it is a design defect rather than
> a tuning artifact: with corrected parameters, nine bursts of nominally identical amplitude still
> produced a 2.6× spread in the triggering window, yielding both a premature drain (−53 ms) and a
> 2.6 s stuck flag within the same run. The
> fallback is adopted, in **bounded** form (EWMA over the first `n` burst windows, then frozen),
> which retains the spike-smoothing benefit without the drain-side ramp-chasing contamination
> that this table's EWMA row warns about.

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
> ("how close to baseline counts as drained") as an explicit knob. `dwell = m` windows
> (§5) holds *because* `ρ = 0.5`; in general `dwell = m(1−ρ)/ρ`. If `ρ` is ever exposed,
> `h_drain` must become `m · (mu_burst − k_drain − mu_0)` to keep `m` meaning "windows".

### Onset arm review — verified against the 30-min baseline, no change needed

The onset arm's own calibration rule (`k_onset = (M−1)·mu_0/2` for a target sensitivity of
detecting bursts ≥ `M`×baseline, from `docs/experiment-methodology.md` §5) looked, on paper, like
it could disagree with the noise-based rule actually implemented (`k = 1·σ̂`). Checked against
`tmp/3.experiments_second_iterations/exp2_finetunning_data_csv/30min_baseline_50ms_windows.csv`
(n = 36,143 quiescent windows): median 67,074, mean 83,542, `σ̂` 71,810, `σ̂/median` ≈ 1.07. This
corresponds to a baseline of 1.67 MB/s of pod ingress at 100 req/s (DeathStarBench's fan-out
amplifies each external request to ~16.7 KB of internal east-west traffic). The burst profile used
in evaluation adds another 100 req/s, so `Δ ≈ mu_0` and `δ = Δ/σ̂ ≈ 1.0` (a ~2× request-rate
burst, `M = 2`). The sensitivity-based form gives `k_onset = (M−1)·mu_0/2 = mu_0/2 ≈ 33.5k`; the
noise-based form gives `k = 0.5·σ̂ ≈ 35.9k` (at `k-mult = 1.0`, `k = σ̂`, i.e. `0.5σ̂` is the slack
half-width). **The two agree to within 7%** — a consequence of `Δ ≈ mu_0 ≈ σ̂` on this workload,
not a coincidence to be re-litigated. **No onset-side change needed**; the `k_onset` formula in
`experiment-methodology.md` §5 and the implemented `k = 1·σ̂` rule are the same rule in different
units for this specific baseline/burst combination.

The apparent mismatch between onset-triggering window sizes (155k–484k bytes, per
`docs/conclusions_from_first_experiments.md` §3) and the true burst level (~167k bytes) is
**selection bias, not miscalibration**: CUSUM can only fire on an upward excursion, and the
baseline is heavy-tailed (p75 124,397 / p90 184,864 / p99 314,032 / max 586,367 on the same
50 ms capture). **15.9% of pure-baseline windows already exceed 155,100 bytes** — the smallest
window that ever triggered onset in the first experiments — so onset-triggering windows are, by
construction, drawn from the upper tail of the baseline distribution rather than reflecting the
true burst mean. This is the source of the `a ≈ 2.68` overestimate discussed in §5-6 below, and it
is a property of tail-triggered sampling, not a defect in `mu_burst = delta` itself.

---

### 5. Decision — `h_drain = m · k_drain`, computed at onset (IMPLEMENTED)

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

**Original decision (superseded by evaluation):** keep `h_drain` a fixed `volatile const`
(calibrated to baseline noise). This was the initial engineering call — the paragraph above
motivated it, on the grounds that a correct fix would require an online burst-variance estimate.
It held only until evaluation, below, showed the fix is cheaper than that.

> **SUPERSEDED by evaluation — see `docs/conclusions_from_first_experiments.md` §2.** The
> revisit condition stated above has been met: the first window-size sweep measured *both*
> failure modes predicted in this section — false drains on noisy bursts (3 of 9 bursts
> fragmented at 50 ms, with premature drains 308 ms and 83 ms before burst end) and sluggish
> drain on a marginal burst (`burst_flag` stuck for 9.3 s at 100 ms). The mechanism is the ratio
> `h_drain / k_drain`, which is the flag's minimum dwell time in windows; it is currently an
> accident of calibration, landing at ≈3 windows in all three configurations (predicted dwell
> 148 / 318 / 621 ms vs observed minimum 150 / 600 / 600 ms).
>
> The finding survived recalibration of the 100 ms configuration. Its corrected run exhibits both
> failure modes within nine bursts — i=1 drained 53 ms *before* its burst ended, i=7 held the flag
> for 2600 ms (2.6× burst duration) — from a 2.1× spread in the onset window alone.

**IMPLEMENTED decision:** `h_drain = m · k_drain`, computed in-kernel at the onset transition
alongside `k_drain` (`cusum_detector.bpf.c`: `st->h_drain = h_drain ? h_drain : h_slack_mult *
st->k_drain;`, where the static `h_drain` override is `0` unless explicitly set). `m`
(`h_slack_mult`) is the explicit hysteresis knob, and drain latency becomes burst-magnitude-
independent (the `a`-cancels argument below is the reason why).

Note that the engineering objection in the original decision — that adapting `h_drain` requires an
online burst-variance estimate — does **not** apply to this formulation. `k_drain` is already
computed in-kernel at onset, so `h_drain = m · k_drain` is one multiply in the same branch: no new
state, no new verifier surface, no variance estimation. The objection was correct for
variance-normalized `h_drain`, which remains rejected.

#### `m` is not a drain-specific concept — it is the onset arm's own operating point

Verified from the experiment-1 armed logs (`docs/conclusions_from_first_experiments.md` §1):

```
  50ms  mu0= 63946  k= 63827  h_onset=382962  h_onset/k=6.000  h_onset/mu0=5.99
 100ms  mu0=127230  k= 84530  h_onset=507180  h_onset/k=6.000  h_onset/mu0=3.99
 200ms  mu0=284525  k=124291  h_onset=745746  h_onset/k=6.000  h_onset/mu0=2.62
```

`h_onset/k = 6.000` exactly in every configuration, because calibration used `k-mult = 1.0` and
`h-mult = 6.0`. So the detector already ran at "threshold = 6 slack-units" on the onset arm; the
drain arm simply failed to inherit it. Note `h_onset/mu_0` is **not** invariant across window
sizes — `k` is the correct denominator for `m`, `mu_0` would make `m` window-size-dependent (it
scales with the window's noise level, not its baseline mean). Both arms therefore unify as
`h = m·k`, with `m` reading identically on each: the number of windows of sustained
one-slack-unit drift required to fire. The loader derives `m` as `effective_h_onset /
effective_k` when `--h-slack-mult` is not passed explicitly, so a different `--h-mult` at
calibration time propagates to the drain side automatically — no separate drain-side calibration
step exists anymore.

#### Why `k_drain = Δ/2` is the right reference (reviewed, unchanged)

`mu_burst − k_drain = (mu_burst + mu_0)/2` — the drain increment is literally "likelihood-ratio
midpoint minus observed", the canonical CUSUM reference for testing "still at μ₁" vs "back at
μ₀". It is also the only workable choice: referencing the drain to noise instead (`k_drain =
0.5·σ̂`, mirroring the onset arm) would put the decision level at `mu_burst − 0.5σ̂`, so any small
dip inside a burst fires drain. Reviewed and kept as-is, including the implicit `ρ = 0.5` (see the
return-fraction hysteresis note in §4).

#### Consequence for `m`: it is the fragmentation guard, and why the `mu_burst` EWMA (§3 / conclusions §3) stays deferred

Write `mu_burst = mu_0 + aΔ`, so `k_drain = aΔ/2` and the drain reference level is
`L = mu_0 + aΔ/2`.

- **After return to baseline:** increment = `L − mu_0 = aΔ/2`, windows-to-fire =
  `m·(aΔ/2)/(aΔ/2) = m`. **`a` cancels exactly** — post-return drain latency is immune to
  `mu_burst` estimation error, regardless of how noisy the onset-window snapshot is. This is
  stronger than the original §3 write-up claimed, and it is why deferring the bounded-EWMA
  `mu_burst` estimator (conclusions §3, action item 2) is safe **for latency**: the EWMA would
  only reduce variance in `a`, and `a` doesn't matter once the burst has ended.
- **During the burst:** `delta ≈ mu_0 + Δ` (the sustained burst level), increment =
  `Δ(a/2 − 1)`, positive whenever `a > 2`. Windows-to-fire = `m·a/(a−2)`. Measured `a ≈ 2.68`
  (onset-window median ≈340k bytes vs true sustained burst level ≈167k bytes, on the corrected
  100 ms configuration) — inflated by the tail-selection-bias effect quantified in §4's onset-arm
  review (15.9% of baseline windows already exceed the smallest onset-triggering window), not by
  a byte-vs-request framing error. This gives `m·a/(a−2) ≈ 3.94·m`.

At `m = 6` that is 23.6 windows ≈ **1.18 s** against ~1.05 s bursts — holds with ~12% margin.
`m = 4` (0.79 s) would fragment. **Decision: keep `m = 6`** as the default, accepting the thin
mid-burst margin knowingly. `m` (`h_slack_mult`) is a load-time value, so if a future run shows
residual mid-burst fragmentation, the response is to raise it (e.g. `m = 8` → 1.58 s) via
`--h-slack-mult`, without a rebuild. The `mu_burst` EWMA stays deferred because it buys only
mid-burst margin — which a larger `m` buys more cheaply, with one fewer changed variable.

#### Why no degenerate-case floor is needed in-kernel

`k_drain = 0` is unreachable for any `h_onset > 0`: onset only fires when `upper_sum` *crosses*
`h_onset` (before the update `upper_sum < h_onset`, after it `upper_sum >= h_onset`), so the
increment `delta − mu_0 − k` was strictly positive and therefore `delta > mu_0 + k >= mu_0`. The
`(delta > mu_0)` ternary at the onset transition in `cusum_detector.bpf.c` is dead code for any
valid configuration. The only ways in are misconfiguration — `h_onset == 0`, or `k == 0` with
`delta == mu_0 + 1` where integer division floors to `0`. Both are rejected at load time in the Go
loader (`deriveHSlackMult` in `cmd/cusum-detector/loader.go`) rather than defended against on the
timer path.

---

### 6. Summary

| Parameter / mechanism | Decision | Why |
|---|---|---|
| `mu_0`, `k`, `h` calibration | **Offline** (`baseline-stats`), baked as `volatile const` | Bootstrap + reproducibility + inspectability; online is a production end-state, not a measurement one. |
| Online EWMA baseline | **Deferred** | Cannot improve detection speed (structural); confounds controlled experiments. |
| Drain reference | **`mu_burst`**, not `mu_0` | `mu_0` lower sum detects drop-*below*-baseline, not return-*to*-baseline. |
| `mu_burst` estimation | ~~Snapshot at onset~~ → **bounded EWMA over first `n` burst windows** | Snapshot measured unstable (§3 note); single sample carries ~±100% error at CV = 1.00. |
| `k_drain` | **Recompute at onset** `= (mu_burst − mu_0)/2` | `k = shift/2`; drain shift is runtime-only. Reusing `k_onset` → drain fires just below the peak → oscillation. **Correctness fix.** |
| `h_drain` | ~~Fixed~~ → **`m · k_drain`**, computed at onset (IMPLEMENTED, `m = 6` default) | Fixed `h_drain` made dwell time an accident of calibration (§5 note); measured as both premature and stuck drains. `m` unifies both arms onto one shared threshold currency, is already the onset arm's operating point (`h_onset/k = 6.000`), and needs no variance estimate. |

**Open question — RESOLVED by evaluation.** Whether drain *latency* must be uniform across burst
magnitudes: **yes.** `docs/conclusions_from_first_experiments.md` §2 measures drain latency
correlating with burst amplitude at Spearman −0.63 / −0.77 / −0.79, producing both premature
drains (fragmenting 3 of 9 bursts at 50 ms) and a 9.3 s stuck flag at 100 ms. `h_drain` now
scales with `(mu_burst − mu_0)` via `k_drain`, computed in-kernel at onset and exposed as the
`--h-slack-mult` load-time knob (default `m = 6`, derived from `h_onset/k` when not passed
explicitly). Burst-σ normalization remains rejected — it is not needed to fix this, and the
fragility objection in §5 still stands against it.
