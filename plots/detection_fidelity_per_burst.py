"""Per-burst detection fidelity: detected [onset, drain] of every burst over the real burst span, one figure per (CUSUM window, burst length) (1 s gap).
The window and burst length are only in the file name; add them to the caption by hand.

    python plots/detection_fidelity_per_burst.py
      ->  figures/detection_fidelity_per_burst/detection_fidelity_per_burst_legend.{svg,pdf} (shared legend, include once)
          figures/detection_fidelity_per_burst/detection_fidelity_per_burst_cusum_window_<N>ms_burst_<B>ms.{svg,pdf}
"""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

import utils

NAME = "detection_fidelity_per_burst"
OUT = utils.OUT / NAME
INPUT = utils.DATA / "1s-gapped-bursts" / "results.csv"
ENDPOINT_BURSTS = (50, 200, 500)  # burst lengths (ms), one figure each


def overlap_endpoints(df, window, burst):
    """Raw detected [onset, drain] per burst (blue) over the shaded real-burst span (grey), t=0 at the real burst start.
    One figure per (CUSUM window, burst length); the top-right label counts missed bursts.
    No in-plot labels: the shared legend figure explains the marks, and the caption says 0 = real burst start."""
    utils.apply()
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    sub = df[(df.cusum_window_size == window) & (df.burst_window_size == burst)].copy()
    sub["start"] = sub.onset_latency_ms
    sub["end"] = sub.real_len_ms + sub.drain_latency_ms
    sub = sub.sort_values("start", na_position="first").reset_index(drop=True)
    ax.axvspan(0, burst, color="0.8", zorder=1)
    for y, r in sub.iterrows():
        if np.isnan(r.start):
            continue
        if np.isnan(r.end):
            ax.plot(r.start, y, marker="o", ms=3, color=utils.ONSET, mfc="white", zorder=3)
            continue
        ax.plot([r.start, r.end], [y, y], color=utils.ONSET, lw=1, zorder=2)
        ax.plot([r.start, r.end], [y, y], ls="", marker="o", ms=2.5, color=utils.ONSET, zorder=3)
    ax.set_ylim(-1, len(sub))
    ax.set_yticks([])
    ax.grid(axis="y", visible=False)
    ax.set_title(f"Missed {int(sub.end.isna().sum())}/{len(sub)}", loc="right", fontsize=7, pad=3, color="0.35")
    lo, hi = ax.get_xlim()
    ticks = [t for t in ax.get_xticks() if lo <= t <= hi and abs(t) > 0.1 * (hi - lo) and abs(t - burst) > 0.1 * (hi - lo)]
    ax.set_xticks(sorted(ticks + [0, burst]))  # the real burst's two edges are always labelled
    ax.set_xlim(lo, hi)
    ax.tick_params(axis="x", labelsize=7.5)
    ax.set_xlabel("Time (ms)")
    ax.set_ylabel("Bursts")
    fig.tight_layout()
    return fig


def legend_figure():
    """One legend for all the figures, saved on its own so it is included once in the paper."""
    utils.apply()
    fig = plt.figure(figsize=(utils.FIG_W, 0.35))
    fig.legend(handles=[Patch(color="0.8", label="Real burst"),
                        Line2D([0], [0], color=utils.ONSET, lw=1, marker="o", ms=3, label="Detected (onset to drain)")],
               loc="center", ncol=2, frameon=False, fontsize=8)
    return fig


def main():
    df = pd.read_csv(INPUT)
    utils.save(legend_figure(), f"{NAME}_legend", OUT)
    for w in sorted(df.cusum_window_size.unique()):
        for b in ENDPOINT_BURSTS:
            utils.save(overlap_endpoints(df, w, b), f"{NAME}_cusum_window_{w}ms_burst_{b}ms", OUT)


if __name__ == "__main__":
    main()
