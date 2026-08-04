# Conclusions from the First Window-Size Experiments

> **Scope.** This document reports the outcome of the first controlled evaluation of Layer 1's
> two-sided CUSUM detector, sweeping the window size across 50 ms / 100 ms / 200 ms against a
> fixed burst profile (10 × 1 s bursts at ~100 rps, 10 s apart, on top of a continuous
> HotelReservation baseline). It closes the two open questions that
> `docs/design-decisions-cusum-calibration.md` §3 and §5 explicitly deferred to evaluation, and
> it reports a methodological defect in the experiment design itself (§4).
>
> Raw data: `tmp/experiments1_results_{50,100,200}ms/`. Calibration inputs:
> `tmp/exp1_data_csv/`, `tmp/exp2_data_csv/`. Method: `docs/experiment-methodology.md`.
>

---

## 0. Headline outcomes

**Two design defects**, both on the drain side, both pre-registered as open questions rather than
new discoveries. Both were confirmed to persist after the 100 ms recalibration, which is what
establishes them as design defects rather than tuning artifacts:

1. **`h_drain` is misaligned with the rule used to set `h_onset`.** `h_onset` is a multiple of the
   *baseline* noise scale (`6·σ̂`), which is correct because the onset sum accumulates against
   baseline noise. `h_drain` was set to the same value — but the drain sum accumulates against
   `k_drain`, an **onset-time-derived, burst-magnitude-dependent** quantity

2. **`mu_burst` seeded from a single window is too noisy to be the drain reference.** Because
   `k_drain = (mu_burst − mu_0)/2` derives from one `delta` sample captured at the onset
   transition, that single sample randomises the whole drain trajectory. Spearman correlation
   between the onset window's byte count and the resulting drain latency is
   **−0.63 / −0.60 / −0.79** (50 / 100 / 200 ms). This closes the §3 open question:
   **snapshot-driven drain is unstable; move to a bounded EWMA.**

**One methodological defect in the experiment**, discovered only by re-running 100 ms:

3. **`h = 6·σ̂` is not an iso-false-alarm rule, so the three window sizes were never compared at
   matched false-alarm rate.** Measured false alarms at `h = 6·σ̂` over a common 1800 s baseline:
   **1.43/min at 50 ms, 1.80/min at 100 ms, 0.50/min at 200 ms** — a 3.6× spread. Detection
   latency and false-alarm rate are exchangeable via `h`, so a latency comparison across
   configurations running at different FP rates carries no information. **The window-size ranking
   is not yet established** and the sweep must be redone at a fixed FP budget. This invalidates a
   conclusion stated in the first revision of this document.

   Note the spread is not monotonic in window size — 100 ms is the worst, 200 ms the best by 2.9×.
   So this is not a simple "larger window is safer" effect that could be corrected by a scaling
   factor; `h = 6·σ̂` lands at an essentially arbitrary point on each configuration's ROC curve.

---

## 1. Measured results

All latencies recomputed from the raw ring-buffer events, independent of the hand-tallied
`latency_differences.txt` notes. Metric definitions in §1.1.

| Metric | 50 ms | 100 ms | 200 ms |
|---|---:|---:|---:|
| `mu_0` / `k` / `h` (bytes) | 63 946 / 63 827 / 382 962 | 127 230 / 84 530 / 507 180 | 284 525 / 124 291 / 745 746 |
| **Bursts detected** | 9 / 10 | 9 / 10 | **10 / 10** |
| Bursts split into >1 flag interval | 3 | **0** | **0** |
| Spurious flag intervals in burst run | 1 | **0** | **0** |
| **Onset latency**, median | **309 ms** | 498 ms | 726 ms |
| Onset latency, stdev | 268 ms | **150 ms** | 184 ms |
| **Drain latency**, median | **104 ms** | 327 ms | 694 ms |
| Drain latency, stdev | 351 ms | 649 ms | **217 ms** |
| Flag dwell, median | 700 ms | 900 ms | 1100 ms |
| Time-recall | 0.462 | **0.474** | 0.349 |
| Time-precision | **0.695** | 0.500 | 0.350 |
| Mean IoU | **0.42** | 0.36 | 0.21 |
| **False alarms**, baseline-only | 1.43 / min (43) | 1.80 / min (54) | **0.50 / min (15)** |

Bold marks the best value per row. No configuration wins on more than three rows, and — critically
— the false-alarm rates differ by 3.6×, so these columns are **not** directly comparable as a
ranking. See §4.

**Notes on the figures.**

- All false-alarm rates use a common **1800 s** denominator, the nominal baseline-load duration.
  The detectors were left running past the load in two cases (50 ms +777 s, 100 ms +9360 s) with
  zero events recorded after the load stopped, so the full detector span would understate the rate.
  Last onset occurred at t+1768 / 1754 / 1737 s respectively, confirming the load spanned ~1800 s
  in all three runs. Parenthesised values are raw onset counts.
- **50 ms figures are sensitive to fragmentation collapsing.** Three of its nine detected bursts
  produced multiple flag intervals. Onset latency is taken from the *first* matching interval and
  drain latency from the *last*; burst i=2's first overlapping interval is a false positive that
  opened before the burst, manually adjudicated to the following interval per
  `latency_differences.txt`. Using the automated matcher instead gives onset stdev 349 ms
  (median unchanged at 309 ms).
- 100 ms and 200 ms were run on different days against separately-captured baselines
  (§7 documents a +6.7% baseline drift between captures), so cross-column differences carry a
  traffic component as well as a configuration component.

### 1.1 How each metric is computed

Let a burst have ground-truth interval `[s, e]` from `run-burst-load.sh`, and let the detector
produce flag intervals `[a, b]` (onset → drain). A flag interval *matches* a burst when it overlaps
`[s, e]`, allowing onset up to 2 s after `e`. `A` denotes the set of matching intervals for a burst.

| Metric | Formula | What it represents |
|---|---|---|
| `mu_0`, `k`, `h` | `mu_0 = median(δ)`, `k = σ̂`, `h = 6·σ̂`, where `σ̂ = 1.4826·MAD(δ)` over baseline windows `δ` | The calibration the run was launched with. Reproduces the run. |
| Bursts detected (recall) | `#{bursts with A ≠ ∅} / #bursts` | Did the detector fire at all for each injected burst. Event-level recall. |
| Bursts split into >1 interval | `#{bursts with \|A\| > 1}` | Flag oscillation — one burst reported as several. Hysteresis failure (§2). |
| Spurious flag intervals | `#{intervals matching no burst}` during the burst run | False positives occurring *during* the burst experiment, distinct from the baseline-only run. |
| Onset latency | `min(a ∈ A) − s` | Reaction time. How long after the burst begins before the flag rises. Negative = fired early. |
| Onset latency stdev | `stdev` over detected bursts | Predictability of reaction time. A low median with high stdev is not a usable detector. |
| Drain latency | `max(b ∈ A) − e` | How long after the burst ends before the flag clears. Negative = cleared while the burst was still running. |
| Drain latency stdev | `stdev` over detected bursts | Predictability of clear-down. Directly exposes the `h_drain`/`k_drain` defect (§2). |
| Flag dwell | `Σ(b − a)` over `A` | Total time the flag was asserted for that burst. Compare against ~1050 ms true duration. |
| Time-recall | `Σ overlap / Σ (e − s)` | Fraction of real burst time the flag was up. Penalises late onset and early drain. |
| Time-precision | `Σ overlap / Σ (b − a)` | Fraction of flagged time that was really burst time. Penalises early onset and late drain. |
| Mean IoU | `mean( overlap / (max(b,e) − min(a,s)) )` per burst | Single-number temporal alignment of flag vs burst, penalising both error directions at once. Perfect = 1.0. |
| False alarms | `onsets during baseline-only run / 1800 s × 60` | Onsets per minute with no burst injected. The cost side of every latency figure. |

where `overlap = Σ max(0, min(b, e) − max(a, s))` over the matching intervals.

---

## 2. Main outcome — `h_drain` must be set by the same *rule* as `h_onset`, not the same *value*

### The misalignment

`h_onset` is sized against the quantity the onset sum accumulates in:

```
upper_sum += delta − mu_0 − k_onset          // increments scale with baseline noise σ̂
h_onset    = 6 · σ̂                           // ⇒ "6 noise units" — dimensionally coherent
```

`h_drain` was given the same numeric value, but the drain sum accumulates in a different currency:

```
lower_sum += mu_burst − k_drain − delta      // increments scale with k_drain, not σ̂
k_drain     = (mu_burst − mu_0) / 2          // onset-time-derived, per-burst
h_drain     = h_onset = 6 · σ̂                // ⇒ "6 baseline-noise units" — wrong currency
```

Substituting `k_drain = (mu_burst − mu_0)/2` and setting `delta = mu_0` — i.e. traffic has
returned exactly to baseline — the per-window drain increment collapses to an identity:

```
increment = mu_burst − (mu_burst − mu_0)/2 − mu_0 = (mu_burst − mu_0)/2 = k_drain
```

So the **nominal** number of windows the flag dwells before it can clear is:

```
nominal_dwell_windows = h_drain / k_drain = 12 · σ̂ / (mu_burst − mu_0)
```

This is the detector's **hysteresis**, and it is currently a ratio of two independently-chosen
constants rather than a designed parameter.

#### What this expression predicts — and what it does not

`h_drain / k_drain` is the count of windows of *drain accumulation*. It therefore predicts
**drain latency** — the interval from the traffic dropping (≈ `burst_end`) to the flag clearing.
It does **not** predict flag dwell, because dwell additionally contains the dead time between
onset firing and the traffic actually dropping, during which `delta ≈ mu_burst`, the increment is
≈ `−k_drain`, and the sum stays clamped at 0:

```
dwell ≈ (burst_end − onset_time)  +  h_drain / k_drain · W
        └── dead time, no accumulation ──┘   └── what the formula covers ──┘
```

Validated against the correct observable, the formula is accurate:

| configuration | median abs. error vs **drain latency** | vs **dwell** (wrong observable) |
|---|---|---|
| 200 ms | **92 ms** | 457 ms |
| 100 ms (corrected) | **152 ms** (106 ms excluding i=7) | 482 ms |

Three caveats remain on the residual, all pushing the true value above the nominal:

1. **`delta_post > mu_0` in practice.** The deployment baseline mean was 150 280 against a
   calibrated `mu_0` of 127 230 (+18%, see §7). True drift is `(mu_burst + mu_0)/2 − delta_post`,
   which is 20–26% *below* `k_drain` for the observed bursts.
2. **It ignores variance.** The drain sum is a random walk with a reflecting barrier at 0. Where
   the drift-to-noise ratio approaches 1 the hitting time becomes heavy-tailed and the mean-drift
   estimate breaks down. This is exactly burst i=7 below (ratio 0.98, error 1715 ms) — the single
   largest residual in the dataset, and the reason the 100 ms error is 152 ms rather than 106 ms.
3. **It is not a lower bound.** The strict minimum is `2·h_drain/(mu_burst + mu_0)` (traffic
   stopping dead, `delta = 0`), roughly half the nominal value — 116 ms vs 163 ms for the largest
   observed burst.

> An earlier revision of this document compared the formula against the *minimum observed dwell*
> and reported an apparently tight match (148/150, 621/600 ms). That conflated two observables and
> the agreement was coincidental. Corrected above: the formula tracks drain latency to within
> ~100 ms, and does not model dwell without the dead-time term.

### Evidence that this is the operative mechanism

The primary evidence is non-parametric and so independent of the constant: Spearman correlation
between the onset window's byte count (which fixes `k_drain`) and the resulting drain latency is
**−0.63 / −0.60 / −0.79** for 50 / 100 / 200 ms. Amplitude orders drain latency, as the scaling
law requires. At 200 ms the point predictions track directly:

```
predicted (ms):  832  798  440  375  592  914  653  488  401  736
observed  (ms):  695  803  460  388  694  995  645  775  514 1056
```

The ratio itself lands near 3 in every configuration, which is what makes the defect uniform
across the sweep rather than specific to one window size:

| W | `h/k_drain` at the median burst | nominal drain latency | observed drain latency (median) |
|---|---|---|---|
| 50 ms | 2.95 | 148 ms | 104 ms |
| 100 ms (corrected) | 3.18 | 318 ms | 327 ms |
| 200 ms | 3.10 | 621 ms | 694 ms |

**This reframes the fragmentation result.** Adding the dead-time term, the flag at 50 ms can clear
roughly 150 ms after traffic dips — against bursts of ~1050 ms that are internally lumpy (4 `wrk2`
threads, HTTP request/response pacing). An intra-burst lull of only three windows is enough to
clear it, and lulls that short are common. At 200 ms the same three windows spans 600 ms, and lulls
that long essentially never occur inside a 1 s burst. The mechanism is the *ratio of drain
accumulation time to burst duration*, which grows with the window.

> Fragmentation at 50 ms is a **dwell-time artifact, not a loss of statistical sensitivity.**
> It is therefore fixable without changing the window size.

### Second consequence: drain latency scales as 1/amplitude

`nominal_dwell_windows` is inversely proportional to `(mu_burst − mu_0)`, so small-amplitude bursts
drain slowly and large ones drain prematurely. Spearman correlation between the onset window's
byte count and the drain latency:

```
50 ms: −0.63        100 ms: −0.60        200 ms: −0.79
```

The corrected 100 ms run exhibits **both** failure modes within a single run of nine bursts,
which is the clearest single piece of evidence in the dataset:

| burst | onset window | `k_drain` | nominal dwell | observed dwell | observed drain latency |
|---|---|---|---|---|---|
| i=1 | 749 085 | 310 928 | 163 ms | 600 ms | **−53 ms** (premature — flag cleared before burst ended) |
| i=7 | 352 361 | 112 566 | 451 ms | **2600 ms** | **+2166 ms** (sluggish — flag stuck 2.6× burst duration) |

A 2.1× spread in the onset window produced a 41× spread in drain latency. Note that i=7 has the
worst drift-to-noise ratio of the run (0.98), placing it in the heavy-tailed hitting-time regime
described above — its 2166 ms drain latency is 4.8× the nominal 451 ms and is the single largest
residual in the dataset. So the *mechanism* is amplitude-driven, but the *magnitude* of the worst
case is variance-driven: low-amplitude bursts are doubly penalised, because a small `k_drain` both
lengthens the nominal accumulation and pushes the drift-to-noise ratio into the regime where the
mean-drift estimate no longer bounds the tail.

The 8.9 s stuck flag in the *contaminated* 100 ms run is the extreme case of the i=7 mode: that
burst had the run's smallest onset window (229 436 bytes), giving a drain-side drift-to-noise
ratio of `60866 / 105271 = 0.58`. A random walk with 0.58σ drift per step has a heavy-tailed
hitting time, so 93 windows is unremarkable. No `wrk2` warm-up hypothesis is needed.

### Decision

**Supersedes `design-decisions-cusum-calibration.md` §5.** Set `h_drain` proportional to
`k_drain` rather than to `σ̂`:

```
h_drain = m · k_drain          // computed at the onset transition, alongside k_drain
```

`m` becomes the explicit hysteresis knob: "how many consecutive windows of return-to-midpoint
traffic constitute a drain." Dwell time becomes ≈ `m` windows **independently of burst
amplitude**. Suggested starting point `m ≈ 6–8`.

Note the engineering objection in §5 — that adapting `h_drain` requires an online burst-variance
estimate — does **not** apply to this formulation. `k_drain` is already computed in-kernel at
onset ([cusum_detector.bpf.c:234](ebpf/cusum_detector.bpf.c:234)), so `h_drain = m · k_drain` is
one multiply in the same branch: no new state, no new verifier surface. The objection was correct
for variance-normalized `h_drain`, which remains rejected.

---

## 3. Main outcome — `mu_burst` should become a bounded EWMA over the first burst windows

### The problem

`mu_burst` is currently snapshotted from a single window at the onset transition
([cusum_detector.bpf.c:233](ebpf/cusum_detector.bpf.c:233)):

```c
st->mu_burst = delta;
st->k_drain  = (delta > mu_0) ? (delta - mu_0) / 2 : 0;
```

Measured baseline coefficient of variation is **1.00 at 50 ms, 0.65 at 100 ms, 0.44 at 200 ms**.
At the shorter windows a single `delta` carries error on the order of its own magnitude. Since
`k_drain` derives from it, and `h_drain/k_drain` sets the dwell time (§2), **one noisy sample
determines the entire drain trajectory of that burst.**

The observed spread confirms how wide this is. In the corrected 100 ms run the triggering windows
ranged 288 945 → 749 085 bytes (2.6×) across nine bursts of nominally identical amplitude, giving
`min_dwell_windows` from 1.63 to 6.27. At 50 ms the spread was 155 100 → 484 448 (3.1×).

This is precisely the failure mode §3 anticipated: *"hostage to where on the burst trajectory
onset fired; an onset spike inflates the reference (premature drain), a mid-ramp onset deflates
it (sluggish drain)."* Both halves are present in the corrected 100 ms run (i=1 and i=7 in §2).

### Decision

**Closes the `mu_burst` open question in `design-decisions-cusum-calibration.md` §3.** Replace
the single-sample snapshot with an EWMA accumulated over the first few burst windows:

```
at onset:            mu_burst = delta                    // seed
for the next n win:  mu_burst += (delta − mu_burst) >> s  // EWMA, integer shift
then freeze mu_burst and derive k_drain (and h_drain, per §2)
```

Freezing after `n` windows is deliberate and answers the objection §3 raised against EWMA
("re-introduces contamination on the drain side — EWMA chases a gradual ramp-down, so drain may
never accumulate cleanly"). A **bounded** EWMA that stops updating once the burst level is
established gets the spike-smoothing benefit without ever chasing the ramp-down. The §3
trade-off was stated for an unbounded EWMA and does not apply to the bounded form.

Cost: one `u32` counter in the per-CPU state struct and a shift-add in the burst branch.
Integer-shift EWMA (`s = 2` or `3`) avoids division and keeps verifier surface flat.

Sequencing note: `n` must be small enough that `k_drain` is fixed well before the burst ends.
With `n ≈ 3` and `s = 2`, `mu_burst` is established within 150 ms at 50 ms windows — comfortably
inside a 1 s burst, and deliberately spanning the front-loaded `wrk2` spike rather than being
captured by it.

---

## 4. Methodological defect — the window sizes were never compared at matched false-alarm rate

This finding emerged only from re-running 100 ms, and it invalidates the window-size ranking
asserted in the first revision of this document.

### The rule `h = 6·σ̂` does not hold the false-alarm rate constant

| W | `h = 6·σ̂` | measured FP, baseline only |
|---|---|---|
| 50 ms | 382 962 | 1.43/min (43 onsets) |
| 100 ms | 507 180 | **1.80/min (54 onsets)** |
| 200 ms | 745 746 | **0.50/min (15 onsets)** |

Detection latency and false-alarm rate are exchangeable through `h`. Comparing latency across
configurations at different FP rates therefore measures nothing about the configurations — any
apparent latency advantage can be manufactured by moving along the same detector's own ROC curve.
**A window-size comparison is only meaningful at a fixed FP budget.**

### The recalibration demonstrates the exchange directly

Replaying the CUSUM offline on a common 1800 s baseline sample
(`tmp/exp2_data_csv/30min_baseline_100ms_windows.csv`, n = 17 999) isolates `h` from the traffic:

| `h` (in corrected σ̂ units) | FP/min | note |
|---|---|---|
| 6 σ̂ = 507 180 | 0.53 | the corrected, deployed config |
| 7.5 σ̂ = 631 626 | 0.20 | **what the contaminated config accidentally implemented** |
| 8 σ̂ = 676 240 | 0.17 | |
| 10 σ̂ = 845 300 | 0.03 | |
| 12 σ̂ = 1 014 360 | 0.00 | |

The contaminated calibration inflated `σ̂` by ~21%, which in correct units meant it was running
`h ≈ 7.5·σ̂` — a **more conservative operating point than intended**. That is the whole story of
the 100 ms configuration's earlier apparent quality.

### What the correction actually did to 100 ms

The initial hypothesis was that the contaminated tuning flattered 100 ms. The measurement shows
something more specific — it flattered its *accuracy* while penalising its *latency*:

| | contaminated (≈7.5σ̂) | corrected (6σ̂) | direction |
|---|---|---|---|
| Onset latency, median | 571 ms | **498 ms** | improved 73 ms |
| Drain latency, median | 668 ms | **327 ms** | improved 341 ms |
| Drain latency, stdev | 2620 ms | **649 ms** | improved 4× |
| Flag dwell, median | 1150 ms | **900 ms** | tighter |
| Time-precision | 0.249 | **0.500** | improved 2× |
| Mean IoU | 0.23 | **0.36** | improved 57% |
| Bursts detected | 10/10 | **9/10** | degraded |
| False alarms | 0.93/min | **1.80/min** | degraded 1.9× |

So the corrected 100 ms detector is **faster and shape-accurate but noisier** — exactly the
signature of moving down the ROC curve to a more sensitive operating point. The user's hypothesis
that "100 ms was not as performative as it seemed" is correct in outcome but not in mechanism:
100 ms is not intrinsically slower or sloppier than it appeared, it was simply being run at a
false-alarm rate that no other configuration was matched to.

**Consequence for §5 of this document and for the sweep:** the correct experiment is to fix a
false-alarm budget (e.g. 0.2/min), solve for `h` per window size on a long baseline capture, and
only then compare detection latency. Until that is done, no window size can be declared best.

---

## 5. New trend — a detectability floor, and it collides with the false-alarm budget

The corrected 100 ms run surfaced a boundary case the contaminated run had hidden. Two of the ten
bursts under-delivered: `wrk2` produced **85 requests instead of 115** (74% amplitude) for i=4
and i=5. Those two are exactly the failures:

| burst | requests | onset window | per-window excess | windows to fire | predicted | observed |
|---|---|---|---|---|---|---|
| i=4 | 85 | — | — | — | — | **MISSED** |
| i=5 | 85 | 288 945 | 77 185 (0.91 σ̂) | 6.6 | 657 ms | 707 ms (worst of run; IoU 0.21) |
| typical | 111–113 | 450 077 | 238 317 (2.82 σ̂) | 2.1 | 213 ms | 459 ms |

The `windows_to_fire = h / excess` model predicts i=5 within 50 ms. A 26% amplitude reduction
pushes required detection time to ~63% of the burst duration, and i=4 fell just the wrong side of
that. This is not noise — it locates the detector's operating limit.

**At 100 ms with `h = 6·σ̂`, the detectable floor for a 1 s burst is ≈ 85 rps over a ≈100 rps
baseline** — roughly a 1.8× rate step sustained for ≥650 ms.

### The floor and the false-alarm budget are in direct tension

Raising `h` to 8σ̂ to fix the FP rate would push required detection time for a weak burst to
879 ms, leaving essentially no margin inside a 1 s burst. The two objectives cannot both be met at
100 ms with this burst profile:

```
h = 6σ̂  → FP 0.53/min, weak burst detectable in 660 ms   (FP too high)
h = 8σ̂  → FP 0.17/min, weak burst needs 879 ms           (marginal)
h = 10σ̂ → FP 0.03/min, weak burst needs 1099 ms          (undetectable)
```

This envelope must be stated explicitly in any evaluation. Reporting "9/10 detected" without it
hides the fact that recall is a function of where on this curve the detector sits.

### Tested and refuted: raising `k` instead of `h`

Because the false alarms accumulate over multiple windows (§6), raising `k` — which drains the
sum every window — looked like a more targeted suppressant than raising `h`, which only moves the
finish line. Swept jointly against the 1800 s baseline at matched FP ≈ 0.17/min:

| config | FP/min | strong burst | weak burst |
|---|---|---|---|
| `k = 1.0σ̂, h = 8σ̂` | 0.17 | 284 ms | 879 ms |
| `k = 1.5σ̂, h = 6σ̂` | 0.07 | 259 ms | **1465 ms** |
| `k = 2.0σ̂, h = 5σ̂` | 0.03 | 276 ms | **never fires** |

Raising `k` buys ~25 ms on strong bursts and destroys weak-burst detection outright. The reason is
structural: **`k` is an amplitude gate, `h` is a persistence/latency knob.** A burst whose
per-window excess is below `k` can never accumulate at all, regardless of duration — and the weak
burst's excess is 0.91σ̂, so `k = 1.5σ̂` gates it out by construction. They are not interchangeable
for FP control. `k = 1·σ̂` should be held and `h` used as the sole FP knob.

---

## 6. Supporting finding — window size is a resolution knob, not a sensitivity knob

Subject to the §4 caveat that this is not yet established at matched FP, the mechanism is
nonetheless informative.

Because `k = σ̂(W)` and `h_onset = 6·σ̂(W)`, both threshold and slack rescale with the window, so
the sample count to fire is roughly window-invariant:

| W | `mu_0` | `σ̂` | burst window bytes (median) | SNR | windows to fire |
|---|---|---|---|---|---|
| 50 ms | 63 946 | 63 827 | 323 539 | 3.07 | **1.96** |
| 100 ms (corrected) | 127 230 | 84 530 | 450 077 | 2.82 | **2.13** |
| 200 ms | 284 525 | 124 291 | 764 930 | 2.87 | **2.09** |

The recalibration made this *sharper*: windows-to-fire is now 1.96 / 2.13 / 2.09 — essentially
constant. (The contaminated 100 ms row read 2.87, which was the only thing breaking the pattern.)
**Onset latency is therefore linear in window size while statistical confidence is unchanged.**

### Why the two effects cancel

**Noise falls as √W.** Recomputed from the calibration CSVs with zero windows excluded:

| W | median | `σ̂` | CV = `σ̂`/median | lag-1 autocorr |
|---|---|---|---|---|
| 50 ms | 64 006 | 63 851 | **1.00** | +0.02 |
| 100 ms | 127 268 | 84 662 | **0.67** | +0.06 |
| 200 ms | 284 925 | 124 884 | **0.44** | +0.02 |

Observed 1.00 / 0.67 / 0.44 against the i.i.d. prediction 1.00 / 0.707 / 0.50. Near-zero
autocorrelation explains why the law holds so cleanly: **the HotelReservation baseline has no
meaningful temporal dependence at 50–200 ms timescales**, so there is no self-similarity to defeat
window aggregation. This is a reportable calibration result in its own right.

**But burst amplitude attenuates at the same rate.** The 1 s `wrk2` burst is front-loaded
(connection establishment, then a response flood), so a larger window low-passes the peak away:
the measured amplitude ratio falls 4.25× → 3.54× → 2.54× across 50/100/200 ms. Signal and noise
both fall ~√W, SNR is conserved, latency grows linearly.

### Correcting the ground truth: ~200 ms of measured onset latency is not the detector

Fitting the residual between observed onset latency and predicted `(h/excess)·W`:

```
observed_onset_median ≈ 200 ms + 0.58·W + (h/excess)·W
```

The 200 ms intercept is **window-size-independent**, so it cannot be detector latency. It is the
harness: `run-burst-load.sh` records `date +%s%N` *before* `fork`+`exec` of `wrk`, followed by
LuaJIT script load and 20 TCP connection establishments before the first response byte reaches a
pod. The corrected 100 ms run confirms the floor — its fastest burst (i=1, onset window 749 085
bytes, predicted 94 ms) still took 498 ms, because the traffic simply had not arrived yet.

Detector-attributable onset latency is therefore closer to **~110 / ~300 / ~525 ms**, and the
`latency_differences.txt` figures are ~200 ms pessimistic across the board.

---

## 7. Supporting finding — false alarms accumulate over ~5 windows, and are hypersensitive to baseline drift

### Correction: the mechanism is not single-window spikes

The first revision of this document claimed false alarms were single-window heavy-tail spikes that
clear `h` in one step, inferred from an exponential-tail rate calculation that matched the
observed rates. **Direct instrumentation of the replay refutes this.** Accumulation length of each
false onset:

```
50 ms  (1 false onset):  [5]
100 ms (16 false onsets): [2,2,2,3,3,5,5,5,5,6,6,7,8,8,11,12]   median 5
```

**Zero of 17 false onsets fired in a single window.** The peak window within each accumulation run
was only 3.1–5.4 × `mu_0`, never enough to clear `h` alone. The tail calculation got the right
rate by coincidence — the exponential tail probability happens to approximate the multi-window run
probability at these parameters — but the mechanism was wrong. False alarms are runs of
**moderately** elevated windows, not isolated spikes.

This matters because it determined which fix to test: §5's `k`-versus-`h` sweep was motivated by
this correction, and it refuted the `k` option on separate grounds.

### False-alarm rate is hypersensitive to calibration/deployment baseline drift

Two 100 ms baseline captures taken ~30 minutes apart on the same idle cluster:

| | 112 s capture (used for calibration) | 1800 s capture |
|---|---|---|
| mean | 140 899 | 150 280 (**+6.7%**) |
| median | 127 268 | 136 317 (**+7.1%**) |
| p99 | 369 365 | 415 787 |
| max | 468 072 | 683 141 |

Replaying `h = 6σ̂` on the 1800 s sample: calibrated on the 112 s capture → **0.53 FP/min**;
calibrated on the 1800 s capture itself → **0.27 FP/min**. **A 7% baseline drift doubles the
false-alarm rate.** The live measurement (1.80/min) is higher still than either replay, implying
the baseline during the burst run was hotter again.

This is the practical reason offline replay under-predicts live FP by ~3× in both the contaminated
and corrected runs (0.20 vs 0.93, 0.53 vs 1.80). Calibration capture is not deployment traffic,
even on an idle lab cluster.

### Calibration captures were also far too short

The `exp1` captures cover only **104–136 s** of traffic. Replaying the deployed parameters over
that data yields 1, 0 and 0 false alarms — versus 1.43/min and 1.80/min measured live. A threshold
cannot be fitted to a false-alarm budget from ~1 event, and the cliff is steep (at 50 ms:
`h=3σ̂` → 12.66/min, `4σ̂` → 5.75, `6σ̂` → 0.58, `8σ̂` → 0.00).

The 1800 s `exp2` capture is the right instrument and should become the standard. Combined with
the drift finding above, the baseline capture should ideally be **contemporaneous with** the burst
run, not taken 30 minutes earlier.

Reporting note: quote a tail quantile alongside `σ̂`. Measured `p99/median` is **4.50 / 3.05 /
2.18** for 50/100/200 ms. MAD deliberately discounts the tail, and although the tail is not the
FP mechanism (see above), it is what makes `σ̂` an incomplete descriptor of this signal.

---

## 8. Actions, ranked by leverage

| # | Action | Closes / supersedes |
|---|---|---|
| 1 | `h_drain = m · k_drain`, computed at onset. Expose `m` as the hysteresis knob. | §2 — supersedes calibration doc §5 |
| 2 | `mu_burst` as a bounded EWMA over the first `n` burst windows, then frozen. | §3 — closes calibration doc §3 |
| 3 | **Redo the window sweep at a fixed false-alarm budget** (solve `h` per window from a long baseline; hold `k = 1σ̂`). Without this there is no window-size conclusion. | §4, §5 |
| 4 | Run the missing 200 ms baseline-only experiment (≥1800 s). | §4 |
| 5 | Standardise on ≥1800 s baseline captures, taken contemporaneously with the burst run. | §7 |
| 6 | Make `cmd/baseline-stats` reject or explicitly report zero-delta windows. | §4 |
| 7 | Report the detectability floor alongside recall; sweep burst amplitude deliberately rather than relying on `wrk2` under-delivery. | §5 |
| 8 | Measure the harness ramp directly instead of inferring it from a three-point fit. | §6 |

Items 1 and 2 are in-kernel changes of a few lines each in the onset branch of
[cusum_detector.bpf.c](ebpf/cusum_detector.bpf.c), add no per-packet cost, and neither requires
the online burst-variance estimation that the calibration doc correctly rejected.

**Current state of the window-size question.** Not answered. The mechanism is understood — window
size trades resolution for latency at roughly constant per-window confidence (§6) — but the three
configurations ran at false-alarm rates differing by at least 1.8×, so their latencies are not
comparable (§4). What the corrected 100 ms run did establish is more useful than a ranking: the
detector has a **quantified operating envelope** (§5) in which false-alarm rate and minimum
detectable burst amplitude trade against each other, and the previously-reported 100 ms result sat
at an accidentally conservative point on it.
