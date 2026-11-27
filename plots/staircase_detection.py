"""Staircase bursts (3 equal abrupt steps up 2500 -> 5000 rps, abrupt drop) vs flat bursts of the same length (1 s gap).

    python plots/staircase_detection.py
      ->  figures/staircase_detection/staircase_detection_cp_step_cusum_window_<N>ms.{svg,pdf}  which step the onset
                                                                                        change point fell in, one per window
          figures/staircase_detection/staircase_detection_iou_delta.{svg,pdf} mean IoU, staircase - flat
          figures/staircase_detection/staircase_detection_iou.tex             mean IoU, staircase / flat (booktabs)

IoU is the mean per cell with missed bursts counted as 0, as in detection_fidelity_heatmaps.py. Caption reference:
missing step 1 caps IoU near 67 %, missing steps 1-2 near 33 %. A staircase carries 2/3 of a flat burst's excess bytes.
"""
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import utils
from utils import with_precision

NAME = "staircase_detection"
OUT = utils.OUT / NAME
STAIR = utils.DATA / "staircase_campaign" / "results.csv"
FLAT = utils.DATA / "1s-gapped-bursts" / "results.csv"
# onset_cp_step: 0 = before step 1, 1..3 = step, empty = missed burst.
CATEGORIES = (("missed", "Missed", "0.8"), (0, "Before step 1", "#c6dbef"), (1, "Step 1", "#6baed6"),
              (2, "Step 2", "#2171b5"), (3, "Step 3", "#08306b"))


def step_figure(df, window):
    """100 % stacked bar per burst length for one CUSUM window: share of bursts per change-point step, missed included."""
    utils.apply()
    df = df[df.cusum_window_size == window]
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    step = df.onset_cp_step.astype("Int64").astype(object).where(df.onset_cp_step.notna(), "missed")
    share = pd.crosstab(df.burst_window_size, step, normalize="index") * 100
    xs = np.arange(len(share))
    bottom = np.zeros(len(share))
    for key, label, color in CATEGORIES:
        v = share[key].to_numpy() if key in share else np.zeros(len(share))
        ax.bar(xs, v, bottom=bottom, width=0.75, color=color, label=label, edgecolor="white", linewidth=0.3)
        bottom += v
    ax.set_xticks(xs, [str(b) for b in share.index])
    ax.tick_params(labelsize=7.5)
    ax.grid(axis="x", visible=False)
    ax.set_ylim(0, 100)
    ax.set_xlabel("Burst length (ms)")
    ax.set_ylabel("Bursts (%)")
    ax.legend(ncol=3, fontsize=6.5, loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False,
              handlelength=1, columnspacing=1)
    fig.tight_layout()
    return fig


def iou_grid(stair, flat):
    """(ws, bs, stair mean IoU, flat mean IoU) on the staircase's (window, length) grid; flat cells absent -> NaN."""
    ws = sorted(stair.cusum_window_size.unique())
    bs = sorted(stair.burst_window_size.unique())
    g = lambda d: with_precision(d).pivot_table(index="cusum_window_size", columns="burst_window_size",
                                                values="iou_pct", aggfunc="mean").reindex(index=ws, columns=bs)
    return ws, bs, g(stair), g(flat)


def delta_heatmap(stair, flat):
    """Mean IoU difference (staircase - flat, percentage points) per (CUSUM window, burst length)."""
    utils.apply()
    ws, bs, s, f = iou_grid(stair, flat)
    d = (s - f).to_numpy(dtype=float)
    fig, ax = plt.subplots(figsize=utils.PAPER_FIGSIZE)
    im = ax.imshow(d, vmin=-50, vmax=50, cmap="RdBu", aspect="auto")
    for i in range(len(ws)):
        for j in range(len(bs)):
            if not np.isnan(d[i, j]):
                ax.text(j, i, f"{d[i, j]:+.0f}", ha="center", va="center", fontsize=7,
                        color="white" if abs(d[i, j]) > 30 else "black")
    ax.set_xticks(range(len(bs)), [str(b) for b in bs])
    ax.set_yticks(range(len(ws)), [str(w) for w in ws])
    ax.tick_params(labelsize=7.5)
    ax.set_xlabel("Burst length (ms)")
    ax.set_ylabel("CUSUM window (ms)")
    ax.grid(False)
    cbar = fig.colorbar(im, ax=ax, ticks=[-50, 0, 50], pad=0.03)
    cbar.ax.tick_params(labelsize=7)
    cbar.set_label(r"$\Delta$ IoU (pp)", fontsize=7.5)
    fig.tight_layout()
    return fig


def latex_table(stair, flat):
    r"""Booktabs table, rows burst lengths, columns CUSUM windows, each cell `staircase / flat` mean IoU (%).
    '--' = no runs for that cell. Needs \usepackage{booktabs}."""
    ws, bs, s, f = iou_grid(stair, flat)
    k = len(ws)
    num = lambda v: "--" if pd.isna(v) else f"{v:.0f}"
    lines = [rf"\begin{{tabular}}{{r{'r' * k}}}", r"\toprule",
             rf" & \multicolumn{{{k}}}{{c}}{{Mean IoU, staircase / flat (\%)}} \\", rf"\cmidrule(lr){{2-{k + 1}}}",
             "Burst length (ms) & " + " & ".join(f"$w={w}$" for w in ws) + r" \\", r"\midrule"]
    lines += [f"{b} & " + " & ".join(f"{num(s.loc[w, b])} / {num(f.loc[w, b])}" for w in ws) + r" \\" for b in bs]
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main():
    stair = pd.read_csv(STAIR)
    flat = pd.read_csv(FLAT)
    for w in sorted(stair.cusum_window_size.unique()):
        utils.save(step_figure(stair, w), f"{NAME}_cp_step_cusum_window_{w}ms", OUT)
    utils.save(delta_heatmap(stair, flat), f"{NAME}_iou_delta", OUT)
    path = OUT / f"{NAME}_iou.tex"
    path.write_text(latex_table(stair, flat))
    print(path)


if __name__ == "__main__":
    main()
