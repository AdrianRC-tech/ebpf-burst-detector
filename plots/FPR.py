"""False alarms per minute on burst-free load, per CUSUM window: flat 2500 rps vs drifting 2500 -> 3000 -> 2500 rps (+-8% wander).
One 15 min rep per bar, annotated with its rate; a 0 means < ~0.2/min (95 %), not a proven zero.

    python plots/FPR.py   ->  figures/FPR/FPR.{svg,pdf}
"""
import matplotlib.pyplot as plt
import pandas as pd

import utils

SCENARIOS = (("flat-baseline", "Flat 2500 rps", utils.ONSET), ("drift-baseline", "Drift 2500-3000 rps", utils.DRAIN))


def fp_per_min(runs):
    """{cusum_w: (onsets, per_min)} pooled over reps. One false alarm = one onset/drain pair = one onset."""
    out = {}
    for w, sub in runs.groupby("cusum_window_size"):
        n = int(sub.n_onset_events.sum())
        out[int(w)] = (n, n / sub.duration_s.sum() * 60)
    return out


def fpr_figure(tables):
    utils.apply()
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    windows = sorted({w for t in tables.values() for w in t})
    for k, (camp, label, color) in enumerate(SCENARIOS):
        for i, w in enumerate(windows):
            if w not in tables[camp]:
                continue
            n, rate = tables[camp][w]
            x = i + (k - 0.5) * utils.BAR_W
            ax.bar(x, rate, utils.BAR_W, color=color, alpha=0.7, zorder=2, label=label if i == 0 else None)
            ax.annotate(f"{rate:.2g}", (x, rate), xytext=(0, 2), textcoords="offset points",
                        ha="center", va="bottom", rotation=90, fontsize=6.5)
    ax.set_xticks(range(len(windows)), [str(w) for w in windows])
    ax.set_xlabel("CUSUM window (ms)")
    ax.set_ylabel("False alarms per minute")
    ax.set_ylim(0, max(r for t in tables.values() for _, r in t.values()) * 1.3)
    ax.grid(axis="x", visible=False)
    ax.legend(fontsize=7, frameon=False)
    fig.tight_layout()
    return fig


def main():
    tables = {c: fp_per_min(pd.read_csv(utils.DATA / c / "runs.csv")) for c, _, _ in SCENARIOS}
    utils.save(fpr_figure(tables), "FPR", utils.OUT / "FPR")


if __name__ == "__main__":
    main()
