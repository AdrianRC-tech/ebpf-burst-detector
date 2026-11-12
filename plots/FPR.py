"""Scenario C: False alarms per second from baseline-only runs, one figure per CUSUM window, one bar per baseline rate.
The window is only in the file name; add it to the caption by hand. All figures share the y scale.

    python plots/FPR.py   ->  figures/FPR/FPR_cusum_window_<N>ms.{svg,pdf}
"""
import matplotlib.pyplot as plt
import pandas as pd

import utils

INPUT = utils.DATA / "stable-baselines" / "runs.csv"


def fpr_per_s(fp_events, duration_s):
    return fp_events / duration_s if duration_s else float("nan")


def fpr_table(runs):
    """[(cusum_w, fp_events, duration_s, fp_per_s)] pooled over reps."""
    out = []
    if runs.empty or "duration_s" not in runs:
        return out
    for w, sub in runs.groupby("cusum_window_size"):
        fp, dur = int(sub.fp_events.sum()), float(sub.duration_s.sum())
        out.append((int(w), fp, dur, fpr_per_s(fp, dur)))
    return out


def rate_of(runs, window, baseline_rps):
    """Pooled false alarms per second for one (CUSUM window, baseline rate); None if there are no runs."""
    t = fpr_table(runs[(runs.cusum_window_size == window) & (runs.baseline_rps == baseline_rps)])
    return t[0][3] if t else None


def fpr_figure(runs, window, ymax):
    """False alarms per second for one CUSUM window: one bar per baseline rate. ymax is shared by all windows."""
    utils.apply()
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    rates = sorted(runs.baseline_rps.unique())
    for i, r in enumerate(rates):
        rate = rate_of(runs, window, r)
        if rate is None:
            continue
        ax.bar(i, rate, 0.7, color=utils.ONSET, alpha=0.6, zorder=2)
        ax.annotate(f"{rate:.2g}", (i, rate), xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", rotation=90, fontsize=6.5)
    ax.set_xticks(range(len(rates)), [str(r) for r in rates])
    ax.set_xlabel("Baseline rate (rps)")
    ax.set_ylabel("False alarms per second")
    ax.set_ylim(0, ymax)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    return fig


def main():
    runs = pd.read_csv(INPUT)
    runs = runs[runs.burst_window_size == 0].dropna(subset=["duration_s"])
    windows = sorted(runs.cusum_window_size.unique())
    top = max(v for w in windows for r in runs.baseline_rps.unique() if (v := rate_of(runs, w, r)) is not None)
    for w in windows:  # same y scale in all four, so the figures stay comparable
        utils.save(fpr_figure(runs, w, top * 1.3), f"FPR_cusum_window_{w}ms", utils.OUT / "FPR")


if __name__ == "__main__":
    main()
