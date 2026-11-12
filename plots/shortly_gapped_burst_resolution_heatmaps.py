"""Burst resolution: bursts resolved as their own event per 5-burst train, one heatmap per short inter-burst gap (100/250/400 ms).
The gap is only in the file name; add it to the caption by hand.

    python plots/shortly_gapped_burst_resolution_heatmaps.py
      ->  figures/shortly_gapped_burst_resolution_heatmaps/shortly_gapped_burst_resolution_heatmaps_gap_<G>ms.{svg,pdf}
"""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import utils

NAME = "shortly_gapped_burst_resolution_heatmaps"
OUT = utils.OUT / NAME
GAPS = (100, 250, 400)  # inter-burst gap (ms); one input file and one panel each
TRAIN = 5


def resolved_per_run(df):
    """Detected bursts summed per (CUSUM window, burst length, rep)."""
    return df.groupby(["cusum_window_size", "burst_window_size", "rep"]).detected.sum().astype(int)


def gapped_heatmap(df, ws, bs):
    """Mean bursts resolved per run (text: min-max over reps) per (CUSUM window, burst length), for one inter-burst gap.
    ws, bs: the rows / columns, shared by all gaps so the figures line up."""
    utils.apply()
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    agg = resolved_per_run(df).groupby(["cusum_window_size", "burst_window_size"]).agg(["mean", "min", "max"])
    grid = np.full((len(ws), len(bs)), np.nan)
    for i, w in enumerate(ws):
        for j, b in enumerate(bs):
            if (w, b) not in agg.index:
                continue
            r = agg.loc[(w, b)]
            grid[i, j] = r["mean"]
            label = f"{r['min']:.0f}" if r["min"] == r["max"] else f"{r['min']:.0f}\u2013{r['max']:.0f}"
            ax.text(j + 0.5, i + 0.5, label, ha="center", va="center", fontsize=7,
                    color="white" if r["mean"] > 3.5 else "black")
    mesh = ax.pcolormesh(grid, vmin=1, vmax=TRAIN, cmap="Blues", edgecolors="white", linewidth=0.5)
    ax.invert_yaxis()
    ax.set_xticks(np.arange(len(bs)) + 0.5, [str(b) for b in bs])
    ax.set_yticks(np.arange(len(ws)) + 0.5, [str(w) for w in ws])
    ax.tick_params(labelsize=7.5)
    ax.set_xlabel("Burst length (ms)")
    ax.set_ylabel("CUSUM window (ms)")
    ax.grid(False)
    cbar = fig.colorbar(mesh, ax=ax, ticks=range(1, TRAIN + 1), pad=0.03)  # colour scale: 1 to 5 bursts
    cbar.ax.tick_params(labelsize=7)
    cbar.set_label("Mean bursts resolved", fontsize=7.5)
    fig.tight_layout()
    return fig


def main():
    frames = {g: pd.read_csv(utils.DATA / f"{g}ms-gapped-bursts" / "results.csv") for g in GAPS}
    ws = sorted({w for df in frames.values() for w in df.cusum_window_size.unique()})
    bs = sorted({b for df in frames.values() for b in df.burst_window_size.unique()})
    for g, df in frames.items():
        utils.save(gapped_heatmap(df, ws, bs), f"{NAME}_gap_{g}ms", OUT)


if __name__ == "__main__":
    main()
