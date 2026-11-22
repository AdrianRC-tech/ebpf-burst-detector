# Experiments

Two stages: collect raw artifacts, then score offline.

```bash
./experiments/run.sh experiments/configs/w100.conf --campaign gapped-bursts --reps 5 [--score]
BURSTY_WINDOW_SIZE_MS=300 ./experiments/run.sh experiments/configs/w100.conf --campaign gapped-bursts   # override a knob
python3 experiments/analysis/score_run.py tmp/runs/gapped-bursts/*/rep*      # writes results.csv + run.csv per rep
python3 -m unittest discover -s experiments/analysis/tests -t experiments
```

Layout: `tmp/runs/<campaign>/w<window_ms>_bl<baseline_rps>_p<peak_rps>_b<burst_ms>/rep<NN>/`
holding `k6.log attribution.ndjson meta.env results.csv run.csv`. `analysis/load.py` (pandas) globs a
campaign and derives `config_id`, `window_ms`, `burst_ms`, `rep`, `burst_idx` from the path.

Read `onset_latency_ms` + `drain_latency_ms` (signed) as the headline. `coverage_pct` = recall (share of the real
burst covered); `iou_pct` = overlap/union of detected vs real interval (edge accuracy, penalises early/late on
both edges). Coverage 100 with a low IoU means over-extended.

A burst's *pieces* are the detections (onset/drain records) with onset in [start − tol, end] that overlap it;
`n_pieces > 1` means a premature drain split it, `pieces` lists them (`on:dr;...`, ms from the real start).
Onset = first piece, drain = last piece; `det_len_ms`, `coverage_pct` and `iou_pct` use the **union** of the
pieces, so the gaps between them count as undetected. `run.csv` splits the false detections by cause:
`n_split` (extra pieces inside a burst, drain logic), `n_early` (overlaps a burst but its change point is
backdated past tol, warm-up), `n_outside` (no burst overlap, a real false alarm). `fp_events` keeps its old
meaning: onset/drain events that are not a burst's first onset or final drain.

`configs/w<ms>.conf` holds the detector `WINDOW` plus k6 knobs.
`BURSTY_WINDOW_RPS` is the *extra* rate (peak = baseline + extra). `run.sh` runs `bursts.js` unless
`K6_SCRIPT` says otherwise; `drift.js` (burst-free drifting baseline, `run_stable_baselines.sh`) is
scored by the same baseline-only path as `N_BURSTS=0`.

## Baseline

There is no calibration step: the detector learns mu/sigma online in kernel (30-window setup, then
Welford→EWMA with tau = max(10 s, 300·W)). Each onset/drain event and attribution record carries the
`mu`/`sigma` it was judged against. `run.sh` therefore starts k6 first and the detector once traffic flows, so setup learns
the steady `SETTLE_S` baseline (4 s, flat). At w100 that leaves only ~5 detection windows before burst 000,
which exposes the warm-up limitation (design doc §7) rather than an idle cluster. `--sample-windows` + `cmd/baseline-stats` remain for offline analysis.
