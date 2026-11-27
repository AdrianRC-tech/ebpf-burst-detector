"""Detection fidelity heatmaps: mean IoU, coverage and precision of the detected [onset, drain] interval vs the real burst (1 s gap).

    python plots/detection_fidelity_heatmaps.py
      ->  figures/detection_fidelity_heatmaps/detection_fidelity_heatmaps_{IoU,Coverage,Precision}.{svg,pdf}
"""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import utils
from utils import with_precision

NAME = "detection_fidelity_heatmaps"
OUT = utils.OUT / NAME
INPUT = utils.DATA / "1s-gapped-bursts" / "results.csv"
METRICS = (("IoU", "iou_pct"), ("Coverage", "coverage_pct"), ("Precision", "precision_pct"))


def overlap_heatmap(df, label, col):
    """Mean of one metric (%) per (CUSUM window, burst length); missed bursts count as 0. One figure per metric."""
    utils.apply()
    df = with_precision(df)
    ws = sorted(df.cusum_window_size.unique())
    bs = sorted(df.burst_window_size.unique())
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    grid = df.pivot_table(index="cusum_window_size", columns="burst_window_size", values=col,
                          aggfunc="mean").reindex(index=ws, columns=bs)
    im = ax.imshow(grid.to_numpy(dtype=float), vmin=0, vmax=100, cmap="Blues", aspect="auto")
    for i, w in enumerate(ws):
        for j, b in enumerate(bs):
            v = grid.loc[w, b]
            if np.isnan(v):
                continue
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8.5,
                    color="white" if v > 60 else "black")
    ax.set_xticks(range(len(bs)), [str(b) for b in bs])
    ax.set_yticks(range(len(ws)), [str(w) for w in ws])
    ax.tick_params(labelsize=8)
    ax.set_xlabel("Burst length (ms)")
    ax.set_ylabel("CUSUM window (ms)")
    ax.set_title(f"{label} (%)", fontsize=9)
    ax.grid(False)
    cbar = fig.colorbar(im, ax=ax, ticks=[0, 50, 100], pad=0.03)  # colour scale: 0-100 %
    cbar.ax.tick_params(labelsize=8)
    cbar.set_label("Mean (%)", fontsize=8)
    fig.tight_layout()
    return fig


def main():
    df = pd.read_csv(INPUT)
    for label, col in METRICS:
        utils.save(overlap_heatmap(df, label, col), f"{NAME}_{label}", OUT)


if __name__ == "__main__":
    main()
