"""Scenario A, detection latency: signed onset / drain latency of every burst, one figure per CUSUM window (1 s gap).

Rows are burst lengths; each row has the onset panel on the left and the drain panel on the right. The x axis (burst sequence,
ordered by rep, burst_idx) is shared, so burst i sits at the same x in both columns, which maps an onset point to its drain point.
y is scaled per panel (outliers elsewhere would flatten it). Each panel joins the bursts in run order with the median and IQR
band; missed bursts are marked on the zero line.

    python plots/detection_latency.py
      ->  figures/detection_latency/detection_latency_cusum_window_<N>ms.{svg,pdf}, ..._medians.tex
"""
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.lines import Line2D

import utils

NAME = "detection_latency"
OUT = utils.OUT / NAME
INPUT = utils.DATA / "1s-gapped-bursts" / "results.csv"
PANEL_W, PANEL_H = 3.3, 1.05
MISS = "#c0392b"


def draw_panel(ax, cell, col, w, color, marker, xmax):
    """Latencies are signed (negative = fired before the nominal GT edge)."""
    y = cell[col].to_numpy()
    x = list(range(1, len(y) + 1))
    hit = ~cell[col].isna().to_numpy()
    ax.axhline(0, color="k", lw=0.8)
    for ref in (w / 2, w):
        ax.axhline(ref, color="0.4", ls="--", lw=0.6, zorder=1)
    if hit.any():
        q1, med, q3 = cell[col].quantile([0.25, 0.5, 0.75])
        ax.axhspan(q1, q3, color=color, alpha=0.15, lw=0)
        ax.axhline(med, color=color, lw=1)
        ax.plot(x, y, color=color, lw=0.6, alpha=0.6, zorder=2)  # NaN (missed) breaks the line
        ax.scatter([xi for xi, h in zip(x, hit) if h], y[hit], s=8, marker=marker, color=color, zorder=3)
    if (~hit).any():
        ax.scatter([xi for xi, h in zip(x, hit) if not h], [0] * int((~hit).sum()),
                   marker="x", s=10, color=MISS, lw=0.8, zorder=3)
    ax.tick_params(labelsize=6.5)
    lo, hi = (min(0, y[hit].min()), max(0, y[hit].max())) if hit.any() else (-w / 2, w)
    pad = 0.15 * (hi - lo or 1)
    ax.set_ylim(lo - pad, hi + pad)  # set explicitly so the w, w/2 references never stretch the scale
    ax.set_xlim(0, xmax + 1)


def counts(onset, drain, n):
    text = f"{onset}/{n} detected" if onset == drain else f"onset {onset}/{n} · drain {drain}/{n}"
    return text, onset < n or drain < n


def latency_figure(df, window):
    """df: per-burst frame; window: the CUSUM window (ms) to plot."""
    utils.apply()
    df = df[df.cusum_window_size == window]
    lengths = sorted(df.burst_window_size.unique())
    color = utils.ONSET  # same blue as Fig 4a; one window per figure
    xmax = df.groupby("burst_window_size").size().max()
    fig, axes = plt.subplots(len(lengths), 2, sharex=True, squeeze=False,
                             figsize=(PANEL_W * 2 + 0.6, (PANEL_H + 0.2) * len(lengths) + 0.8))
    for i, b in enumerate(lengths):
        cell = df[df.burst_window_size == b].sort_values(["rep", "burst_idx"])
        for j, (col, marker) in enumerate((("onset_latency_ms", "o"), ("drain_latency_ms", "s"))):
            draw_panel(axes[i, j], cell, col, window, color, marker, xmax)
        text, missed = counts(int(cell.onset_latency_ms.notna().sum()), int(cell.drain_latency_ms.notna().sum()), len(cell))
        axes[i, 1].set_title(text, loc="right", fontsize=6.5, pad=3, color=MISS if missed else "0.35")
    fig.supylabel("signed latency (ms)", fontsize=8)
    fig.subplots_adjust(left=0.1, right=0.95, top=0.93, bottom=0.04, wspace=0.18, hspace=0.6)  # fixed, so both columns stay equally wide
    pad = 3 / 72 / fig.get_figheight()
    for i, b in enumerate(lengths):  # row title centred over the onset + drain pair
        l, r = axes[i, 0].get_position(), axes[i, 1].get_position()
        fig.text((l.x0 + r.x1) / 2, l.y1 + pad, f"burst length = {b} ms", ha="center", va="bottom", fontsize=7.5, fontweight="bold")
    for j, head in enumerate(("onset", "drain")):  # column headers sit above the first row's titles
        bb = axes[0, j].get_position()
        fig.text((bb.x0 + bb.x1) / 2, bb.y1 + 0.026, head, ha="center", va="bottom", fontsize=8, fontweight="bold", color="k")
    for i in range(len(lengths) - 1):  # separator between rows, just under row i, clear of row i+1's title
        gap_top, gap_bot = axes[i, 0].get_position().y0, axes[i + 1, 0].get_position().y1
        y = gap_top - 0.3 * (gap_top - gap_bot)
        fig.add_artist(Line2D([0.02, 0.99], [y, y], color="0.75", lw=0.6, transform=fig.transFigure))
    return fig


def median_table(df):
    """Per (CUSUM window, burst length): detected count and median / IQR of the signed latency, onset and drain side by side."""
    rows = []
    for (w, b), cell in df.groupby(["cusum_window_size", "burst_window_size"]):
        row = {"cusum_window_ms": w, "burst_length_ms": b, "n": len(cell)}
        for side, col in (("onset", "onset_latency_ms"), ("drain", "drain_latency_ms")):
            q1, med, q3 = cell[col].quantile([0.25, 0.5, 0.75])
            row |= {f"{side}_detected": int(cell[col].notna().sum()), f"{side}_median_ms": med,
                    f"{side}_q1_ms": q1, f"{side}_q3_ms": q3}
        rows.append(row)
    return pd.DataFrame(rows).round(1)


def latex_table(df):
    r"""Booktabs table of median signed latency (ms): rows are burst lengths, columns CUSUM windows, each cell `onset / drain`.
    '--' marks a side with no detected burst. Needs \usepackage{booktabs}."""
    t = median_table(df)
    windows = sorted(t.cusum_window_ms.unique())
    lengths = sorted(t.burst_length_ms.unique())
    k = len(windows)

    def num(v):
        return "--" if pd.isna(v) else f"{round(v, 1) + 0.0:.1f}".replace("-", "$-$")  # + 0.0 turns -0.0 into 0.0

    def cell(w, b):
        r = t[(t.cusum_window_ms == w) & (t.burst_length_ms == b)]
        return " / ".join(num(r[c].iloc[0]) for c in ("onset_median_ms", "drain_median_ms")) if not r.empty else "-- / --"

    lines = [rf"\begin{{tabular}}{{r{'r' * k}}}", r"\toprule",
             rf" & \multicolumn{{{k}}}{{c}}{{Median onset / drain latency (ms)}} \\", rf"\cmidrule(lr){{2-{k + 1}}}",
             "Burst length (ms) & " + " & ".join(f"$w={w}$" for w in windows) + r" \\", r"\midrule"]
    lines += [f"{b} & " + " & ".join(cell(w, b) for w in windows) + r" \\" for b in lengths]
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main():
    df = pd.read_csv(INPUT)
    for w in sorted(df.cusum_window_size.unique()):
        utils.save(latency_figure(df, w), f"{NAME}_cusum_window_{w}ms", OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{NAME}_medians.tex"
    path.write_text(latex_table(df))
    print(path)


if __name__ == "__main__":
    main()
