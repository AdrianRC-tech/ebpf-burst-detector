"""Per-burst detection fidelity: every detected [onset, drain] piece of each burst over the real burst span, one figure per (CUSUM window, burst length) (1 s gap).
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
ENDPOINT_BURSTS = (25, 50, 100, 200, 300, 400, 500)  # burst lengths (ms), one figure each


def parse_pieces(s):
    """'on:dr;on:dr' (ms from the real burst start, dr empty if it never drained) -> [(on, dr|nan)]."""
    if not isinstance(s, str) or not s:
        return []
    return [(float(on), float(dr) if dr else np.nan) for on, dr in (p.split(":") for p in s.split(";"))]


def overlap_endpoints(df, window, burst):
    """Every detected [onset, drain] piece of each burst over the shaded real-burst span (grey), t=0 at the real burst
    start; one row per burst, each piece a segment with tick ends. A burst split by a premature drain shows several
    pieces on its row joined by a faint dotted line across the undetected gaps. Rows are chronological, top to bottom:
    rep by rep, bursts in run order (explained in the caption). One figure per (CUSUM window, burst length);
    the top-right label counts missed and split bursts. No in-plot labels: the shared legend explains the marks, the
    caption says 0 = real start."""
    utils.apply()
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    sub = df[(df.cusum_window_size == window) & (df.burst_window_size == burst)].copy()
    sub["p"] = sub.pieces.map(parse_pieces)
    sub = sub.sort_values(["rep", "burst_idx"]).reset_index(drop=True)
    ax.axvspan(0, burst, color="0.8", zorder=1)
    for y, r in sub.iterrows():
        for (_, dr), (on, _) in zip(r.p, r.p[1:]):  # gap: one piece's drain to the next re-onset
            ax.plot([dr, on], [y, y], color=utils.ONSET, lw=0.6, ls=(0, (1, 1.5)), alpha=0.6, zorder=2)
        for on, dr in r.p:
            if np.isnan(dr):
                ax.plot(on, y, marker="o", ms=3, color=utils.ONSET, mfc="white", zorder=3)
                continue
            ax.plot([on, dr], [y, y], color=utils.ONSET, lw=1.2, solid_capstyle="butt", zorder=2)
            ax.plot([on, dr], [y, y], ls="", marker="|", ms=4, mew=0.8, color=utils.ONSET, zorder=3)
    ax.set_ylim(len(sub), -1)  # first burst of rep 1 at the top
    ax.set_yticks([])  # run order is explained in the caption
    ax.grid(axis="y", visible=False)
    n = len(sub)
    ax.set_title(f"Missed {int((sub.detected == 0).sum())}/{n} · Split {int((sub.n_pieces > 1).sum())}/{n}",
                 loc="right", fontsize=7, pad=3, color="0.35")
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
                        Line2D([0], [0], color=utils.ONSET, lw=1.2, marker="|", ms=5, mew=0.8,
                               label="Detected (onset to drain)"),
                        Line2D([0], [0], color=utils.ONSET, lw=0.8, ls=(0, (1, 1.5)), alpha=0.6,
                               label="Gap in a split burst (premature drain to re-onset)")],
               loc="center", ncol=3, frameon=False, fontsize=8, numpoints=2)  # ticks at both ends
    return fig


def main():
    df = pd.read_csv(INPUT)
    utils.save(legend_figure(), f"{NAME}_legend", OUT)
    for w in sorted(df.cusum_window_size.unique()):
        for b in ENDPOINT_BURSTS:
            utils.save(overlap_endpoints(df, w, b), f"{NAME}_cusum_window_{w}ms_burst_{b}ms", OUT)


if __name__ == "__main__":
    main()
