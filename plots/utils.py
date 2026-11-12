"""Shared by every fig*.py: look (rcParams, colours), nested burst-length axis, IQR, output."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "figures"

ONSET = "#1f77b4"
DRAIN = "#d95f02"
RATE_COLORS = ["#009E73", "#CC79A7", ONSET]  # Fig 4b: one per baseline rate
PAPER_FIGSIZE = (3.33, 2.22)  # inches: one column of a two-column paper, 3:2; for single-axis figures
FIG_W = 7.0
NESTED_W = FIG_W * 1.5  # nested burst-length axes (Figs 2-4a) need the room for 28 tick labels
BAR_W = 0.38


def apply():
    matplotlib.rcParams.update({
        "svg.fonttype": "none",  # text stays editable in SVG ...
        "pdf.fonttype": 42,  # ... and selectable in PDF
        "svg.hashsalt": "burst-detector",  # deterministic SVG ids: reruns are byte-identical
        "font.size": 9,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.alpha": 0.25,
        "figure.dpi": 100,
    })


def save(fig, name, out=OUT, **kw):
    """Write <name>.svg and <name>.pdf into out, without timestamps. kw goes to savefig (e.g. bbox_inches="tight")."""
    out.mkdir(parents=True, exist_ok=True)
    for fmt, meta in (("svg", {"Date": None}), ("pdf", {"CreationDate": None})):
        path = out / f"{name}.{fmt}"
        fig.savefig(path, format=fmt, metadata=meta, **kw)
        print(path)


def with_precision(df):
    """Add precision_pct (overlap / detected length) and `missed`; missed bursts (no onset/drain pair) score 0."""
    df = df.copy()
    overlap_ms = df.coverage_pct / 100 * df.real_len_ms
    df["precision_pct"] = (100 * overlap_ms / df.det_len_ms).where(df.det_len_ms > 0)
    df["missed"] = df.iou_pct.isna()
    for col in ("iou_pct", "coverage_pct", "precision_pct"):
        df[col] = df[col].mask(df.missed, 0.0)
    return df


def cells(df):
    """Sorted [(cusum_w, [burst_w, ...])] present in df."""
    out = []
    for w in sorted(df.cusum_window_size.unique()):
        out.append((int(w), sorted(int(b) for b in df[df.cusum_window_size == w].burst_window_size.unique())))
    return out


def layout(df):
    """Return (positions {(w, b): x}, group spans [(w, x0, x1)])."""
    pos, spans, x = {}, [], 0.0
    for w, bs in cells(df):
        x0 = x
        for b in bs:
            pos[(w, b)] = x
            x += 1
        spans.append((w, x0, x - 1))
        x += 0.8  # gap between groups
    return pos, spans


def decorate(ax, df, xlabel_inner="burst length (ms)", group_labels=True):
    """Nested x axis: inner ticks = burst length, group labels + separators (CUSUM window) below the axis."""
    pos, spans = layout(df)
    ax.set_xticks(list(pos.values()), [str(b) for (_, b) in pos])
    ax.tick_params(axis="x", labelsize=7.5)
    ax.set_xlabel(xlabel_inner)
    ax.grid(axis="x", visible=False)
    for i, (w, x0, x1) in enumerate(spans):
        if group_labels:
            ax.annotate(f"CUSUM w = {w} ms", xy=((x0 + x1) / 2, 0), xycoords=("data", "axes fraction"),
                        xytext=(0, -34), textcoords="offset points", ha="center", va="top", fontsize=9)
        if i:
            ax.axvline(x0 - 0.4, color="0.7", lw=0.8, ls="-")
    if pos:
        ax.set_xlim(min(pos.values()) - 0.7, max(pos.values()) + 0.7)
    return pos, spans


def iqr(v):
    v = np.asarray(v, dtype=float)
    v = v[~np.isnan(v)]
    if not len(v):
        return np.nan, np.nan, np.nan
    return float(np.median(v)), float(np.percentile(v, 25)), float(np.percentile(v, 75))


apply()
