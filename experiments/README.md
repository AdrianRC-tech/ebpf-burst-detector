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

`configs/w<ms>.conf` holds the calibrated `MU0 K H_ONSET H_SLACK_MULT` (from `baseline-stats`) plus k6 knobs.
`BURSTY_WINDOW_RPS` is the *extra* rate (peak = baseline + extra). Scoring covers `bursts.js` only;
`staircase.js` is collected the same way but has no scorer yet.

## Calibrating a new window

```bash
./experiments/calibrate.sh --window 100ms   # ~70 s; needs bin/baseline-stats and the detector in the node
```
Runs the detector in sampling mode under steady k6 load (`BASELINE_RATE`, `SETTLE_S`, ... overridable via env),
then prints the `baseline-stats` report on stdout (progress goes to stderr). Copy `MU0 K H_ONSET` into
`configs/w<ms>.conf`. Samples land in `tmp/calibration/w<ms>_windows.csv`.
