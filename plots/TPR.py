"""Fig 4a: TPR (detected / ground-truth bursts) per burst length, one figure per CUSUM window (1 s gap).
The window is only in the file name; add it to the caption by hand.

    python plots/TPR.py   ->  figures/TPR/TPR_cusum_window_<N>ms.{svg,pdf}
"""
import matplotlib.pyplot as plt
import pandas as pd

import utils

INPUT = utils.DATA / "1s-gapped-bursts" / "results.csv"


def tpr_cell_table(df):
    """{(cusum_w, burst_w): (k, n, tpr)} with n = ground-truth bursts."""
    out = {}
    for (w, b), sub in df.groupby(["cusum_window_size", "burst_window_size"]):
        k, n = int(sub.detected.sum()), len(sub)
        out[(int(w), int(b))] = (k, n, k / n)
    return out


def tpr_figure(df, window):
    """df: per-burst frame; window: the CUSUM window (ms) to plot."""
    utils.apply()
    df = df[df.cusum_window_size == window]
    fig, ax = plt.subplots(1, 1, figsize=utils.PAPER_FIGSIZE)
    pos, _ = utils.decorate(ax, df, group_labels=False)
    for key, (k, n, tpr) in tpr_cell_table(df).items():
        x = pos[key]
        ax.bar(x, tpr, 0.7, color=utils.ONSET, alpha=0.6, zorder=2)
        ax.annotate(f"{k}/{n}", (x, 1.0), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom",
                    rotation=90, fontsize=6.5)
    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylabel("TPR (detected / real bursts)")
    fig.tight_layout()
    return fig


def main():
    df = pd.read_csv(INPUT)
    for w in sorted(df.cusum_window_size.unique()):
        utils.save(tpr_figure(df, w), f"TPR_cusum_window_{w}ms", utils.OUT / "TPR")


if __name__ == "__main__":
    main()
