#!/usr/bin/env python3
"""One-off: copy the scored results the paper figures use from tmp/runs into data/<campaign>/{results,runs}.csv.

Only the b2500/p5000 burst shape is kept for burst campaigns; baseline-only campaigns are kept whole.
Plot scripts never run this; they read data/ directly. Run from the repo root:
    python3 -m experiments.analysis.export_plot_data
"""
import glob
import json
from pathlib import Path

from .load import load, load_runs

BURST = ["1s-gapped-bursts", "50ms-gapped-bursts","100ms-gapped-bursts", "250ms-gapped-bursts", "400ms-gapped-bursts", "staircase_campaign"]
BASELINE = ["flat-baseline", "drift-baseline"]
OUT = Path("data")


def export_attribution(root="tmp/runs", campaign="1s-gapped-bursts", config="w10_bl2500_p5000_b500"):
    """Sankey input: the complete (not truncated/unpaired) attribution records of one config, one NDJSON line each."""
    out = OUT / campaign / f"attribution_{config}.ndjson"
    n = 0
    with open(out, "w") as fh:
        for f in sorted(glob.glob(f"{root}/{campaign}/{config}/rep*/attribution.ndjson")):
            rep = int(f.split("/rep")[1].split("/")[0])
            for i, line in enumerate(l for l in open(f) if l.strip()):
                r = json.loads(line)
                if r.get("truncated") or r.get("unpaired"):
                    continue
                fh.write(json.dumps({"rep": rep, "burst_idx": i, **r}) + "\n")
                n += 1
    print(out, n, "records")


def main(root="tmp/runs"):
    for c in BURST + BASELINE:
        out = OUT / c
        out.mkdir(parents=True, exist_ok=True)
        res, runs = load(c, root), load_runs(c, root)
        if c in BURST:
            res = res[(res.baseline_rps == 2500) & (res.peak_rps == 5000)]
            runs = runs[(runs.baseline_rps == 2500) & (runs.peak_rps == 5000)]
        if not res.empty:  # baseline-only campaigns have no bursts
            res.to_csv(out / "results.csv", index=False)
        runs.to_csv(out / "runs.csv", index=False)
        print(c, len(res), "bursts", len(runs), "runs")
    export_attribution(root)


if __name__ == "__main__":
    main()
