# plots/

One script per scenario figure set. Each reads its CSVs from `../data/` and writes SVG + PDF into its own folder under `../figures/`.
Works from any directory; deterministic (re-runs give identical files).

```
pip install -r plots/requirements.txt
python plots/detection_latency.py   # figures/detection_latency/: one per window + medians.tex (needs booktabs)
python plots/detection_fidelity_heatmaps.py  # figures/detection_fidelity_heatmaps/: one heatmap per metric (IoU, Coverage, Precision)
python plots/detection_fidelity_per_burst.py       # figures/detection_fidelity_per_burst/: raw endpoints, one per window and burst length
python plots/TPR.py                 # figures/TPR/: one per window
python plots/shortly_gapped_burst_resolution_heatmaps.py  # figures/shortly_gapped_burst_resolution_heatmaps/: one heatmap per gap (100/250/400 ms)
python plots/FPR.py                 # figures/FPR/: one per window (data/stable-baselines)
```

`utils.py` holds the shared style, nested burst-length axis and `with_precision`.

## Input
`data/<campaign>/results.csv`: one row per burst; `runs.csv`: one row per run. Rows are self-describing:
`campaign, config_id, cusum_window_size, baseline_rps, peak_rps, burst_window_size, rep, burst_idx` (results only),
then the scored columns (`detected`, `onset_latency_ms`, `drain_latency_ms`, `real_len_ms`, `det_len_ms`, `coverage_pct`, `iou_pct`, ...).
`runs.csv` adds `fp_events` and `duration_s`. Empty latency/IoU cells are missed bursts. Latencies are signed
(negative = fired before the nominal ground-truth edge). Burst campaigns hold the 2500/5000 rps shape only.

The CSVs were produced once from the raw runs (`tmp/runs`, not shipped) with
`python -m experiments.analysis.export_plot_data` (repo root); readers never need it.
