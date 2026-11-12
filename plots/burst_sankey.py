"""Characterization figure: how one burst's ingress bytes split into service pairs and then into flows (5-tuples).
Config w10 / 500 ms burst / 1 s gap. Bytes are measured at the receiver's ingress, so ribbons follow the data direction.
The drawn burst is the median-total-bytes record of the 25 (a stated rule, not a pick by eye); the pooled mean share
per service pair over all 25 bursts is printed for the caption.

    python plots/burst_sankey.py   ->  figures/burst_sankey/burst_sankey.{svg,pdf}
"""
import json
import statistics
from collections import defaultdict

import matplotlib.pyplot as plt
from matplotlib.patches import PathPatch, Rectangle
from matplotlib.path import Path

import utils

INPUT = utils.DATA / "1s-gapped-bursts" / "attribution_w10_bl2500_p5000_b500.ndjson"
GAP = 0.012  # vertical gap between service pairs
GAP_IN = 0.004  # vertical gap between flows of one pair
BIG = 0.03  # flow nodes at least this tall (fraction of the figure) get their share printed
GRAY = "#999999"


def short(svc):
    return svc.split("/", 1)[-1]


PALETTE = ["#D55E00", "#0072B2", "#009E73", "#CC79A7", "#E69F00", "#56B4E9", "#7A5195", "#8C564B", "#17BECF"]  # one per pair


def pair_of(c):
    return short(c["src_service"]), short(c["dst_service"])


def pooled_pair_shares(records):
    """{(src, dst): mean share of burst bytes over records}; contributors cover >99% of bytes (top-N cap)."""
    acc = defaultdict(list)
    keys = {pair_of(c) for r in records for c in r["contributors"]}
    for r in records:
        by = defaultdict(int)
        for c in r["contributors"]:
            by[pair_of(c)] += c["bytes"]
        for k in keys:
            acc[k].append(by[k] / r["total_bytes"])
    return {k: statistics.mean(v) for k, v in acc.items()}


def median_record(records):
    return sorted(records, key=lambda r: r["total_bytes"])[len(records) // 2]


def build(rec):
    """Return pairs = [{label, colour, flows: [bytes, ...], note}] largest pair first, flows largest first.
    note says how a multi-flow pair's flows differ (they usually differ only in dst port)."""
    total = rec["total_bytes"]
    by = defaultdict(list)
    for c in rec["contributors"]:
        by[pair_of(c)].append(c)
    pairs = []
    for k, cs in sorted(by.items(), key=lambda kv: -sum(c["bytes"] for c in kv[1])):
        note = ""
        if len(cs) > 1:
            varying = [n for n, f in (("src IP", lambda c: c["src"].rsplit(":", 1)[0]), ("src port", lambda c: c["src"].rsplit(":", 1)[1]),
                                      ("dst IP", lambda c: c["dst"].rsplit(":", 1)[0]), ("dst port", lambda c: c["dst"].rsplit(":", 1)[1]))
                       if len({f(c) for c in cs}) > 1]
            note = f"{varying[0]} varies" if len(varying) == 1 else ""
        pairs.append(dict(label=f"{k[0]} → {k[1]}", colour=PALETTE[len(pairs) % len(PALETTE)],
                          flows=sorted((c["bytes"] for c in cs), reverse=True), note=note))
    other = total - sum(c["bytes"] for cs in by.values() for c in cs)  # flows hidden by the top-N cap
    if other > 0:
        pairs.append(dict(label=f"other flows (beyond top-{len(rec['contributors'])})", colour=GRAY, flows=[other], note=""))
    return pairs


def stack(pairs, total):
    """Top-down y span per flow, per pair [[(y0, y1), ...], ...]; GAP_IN inside a pair, GAP between pairs."""
    n = sum(len(p["flows"]) for p in pairs)
    gaps = GAP * (len(pairs) - 1) + GAP_IN * (n - len(pairs))
    scale = (1 - gaps) / total
    y, out = 0.0, []
    for p in pairs:
        spans = []
        for b in p["flows"]:
            spans.append((y, y + b * scale))
            y += b * scale + GAP_IN
        y += GAP - GAP_IN
        out.append(spans)
    return out


def spread_labels(centres, heights):
    """Label y per item: its centre, pushed down where a neighbour's label would collide (top-down greedy)."""
    ys, prev = [], None
    for c, h in zip(centres, heights):
        y = c if prev is None else max(c, prev[0] + (prev[1] + h) / 2)
        ys.append(y)
        prev = (y, h)
    return ys


def ribbon(ax, x0, x1, a, b, color):
    """Filled Bezier band from span a at x0 to span b at x1."""
    xm = (x0 + x1) / 2
    verts = [(x0, a[0]), (xm, a[0]), (xm, b[0]), (x1, b[0]), (x1, b[1]), (xm, b[1]), (xm, a[1]), (x0, a[1]), (x0, a[0])]
    codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4, Path.LINETO, Path.CURVE4, Path.CURVE4, Path.CURVE4, Path.CLOSEPOLY]
    ax.add_patch(PathPatch(Path(verts, codes), facecolor=color, edgecolor="none", alpha=0.45))


def sankey_figure(rec):
    utils.apply()
    total = rec["total_bytes"]
    pairs = build(rec)
    fig, ax = plt.subplots(figsize=(utils.FIG_W, 5.4))
    X0, X1, X2, W = 0.0, 0.25, 0.64, 0.02  # burst node, service-pair nodes, flow nodes, node width
    XB = X2 + W + 0.085  # whisker x
    ax.set_xlim(-0.02, 1.02)
    ax.axis("off")
    ax.grid(False)

    spans = stack(pairs, total)
    tops, bots = [sp[0][0] for sp in spans], [sp[-1][1] for sp in spans]  # a pair node covers its flows' span
    mids = [(t + b) / 2 for t, b in zip(tops, bots)]
    ax.add_patch(Rectangle((X0, 0), W, 1, color="#444444"))
    ax.text(X0 - 0.01, 0.5, f"burst\n{total / 1e6:.1f} MB\n{rec['flows']} flows", ha="right", va="center", fontsize=9)

    y = 0.0
    for p, sp, t, b in zip(pairs, spans, tops, bots):
        pb = sum(p["flows"])
        ribbon(ax, X0 + W, X1, (y, y + pb / total), (t, b), p["colour"])  # burst -> service pair
        y += pb / total
        ax.add_patch(Rectangle((X1, t), W, b - t, color=p["colour"]))
        used = t
        for fb, s in zip(p["flows"], sp):  # service pair -> its flows
            h = fb / pb * (b - t)
            ribbon(ax, X1 + W, X2, (used, used + h), s, p["colour"])
            used += h
            ax.add_patch(Rectangle((X2, s[0]), W, s[1] - s[0], color=p["colour"]))
            if len(p["flows"]) > 1 and s[1] - s[0] >= BIG:  # tail end: the flow's share of the whole burst
                ax.text(X2 + W + 0.008, (s[0] + s[1]) / 2, f"{100 * fb / total:.1f}%", va="center", fontsize=7)

    white = dict(facecolor="white", edgecolor="none", alpha=0.8, pad=0.6)
    for p, m, ly in zip(pairs, mids, spread_labels(mids, [0.032] * len(pairs))):  # middle column: src -> dst only
        ax.plot([X1 + W, X1 + W + 0.008], [m, ly], color="#666666", lw=0.4)
        ax.text(X1 + W + 0.01, ly, p["label"], va="center", fontsize=7, bbox=white, zorder=5)

    lines = [1] * len(pairs)  # whiskers: total share + flow count (+ which field varies), one line each
    ys = spread_labels(mids, [0.034 * n for n in lines])
    for p, t, b, m, ly in zip(pairs, tops, bots, mids, ys):
        ax.plot([XB - 0.008, XB, XB, XB - 0.008], [t, t, b, b], color=p["colour"], lw=1.3, solid_capstyle="butt")
        ax.plot([XB, XB + 0.012], [m, ly], color="#666666", lw=0.4)
        n = len(p["flows"])
        text = f"{100 * sum(p['flows']) / total:.1f}%  ·  {n} flow{'s' * (n > 1)}" + (f" ({p['note']})" if p["note"] else "")
        ax.text(XB + 0.016, ly, text, va="center", fontsize=7.5, linespacing=1.1)
    ax.set_ylim(max(1.0, ys[-1] + 0.03), 0.0)
    return fig


def main():
    records = [json.loads(l) for l in open(INPUT) if l.strip()]
    rec = median_record(records)
    print(f"{len(records)} bursts; drawn: rep{rec['rep']:02d} burst {rec['burst_idx']} ({rec['total_bytes'] / 1e6:.1f} MB)")
    for k, v in sorted(pooled_pair_shares(records).items(), key=lambda kv: -kv[1])[:6]:
        print(f"  pooled {k[0]} -> {k[1]}: {100 * v:.1f}%")
    # tight crop: content is asymmetric (burst label left, whiskers right), so crop to it for an even margin in LaTeX
    utils.save(sankey_figure(rec), "burst_sankey", utils.OUT / "burst_sankey", bbox_inches="tight", pad_inches=0.03)


if __name__ == "__main__":
    main()
