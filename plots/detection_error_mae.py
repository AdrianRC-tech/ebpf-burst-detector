"""Scenario A, detection error: mean absolute onset / drain latency per (CUSUM window, burst length), 1 s gap.

Replaces the median table as the headline: |latency| stops early and late errors cancelling, and the mean keeps
every outlier (e.g. an onset backdated several windows) in the number. The signed mean keeps the direction (negative = fired before the GT edge). Latency stats cover detected
bursts only, so read them next to the Det column.

    python plots/detection_error_mae.py   ->  figures/detection_latency/detection_error_mae.tex             full table
                                              figures/detection_latency/detection_error_mae_compressed.tex  onset / drain MAE grid
    Both need booktabs.
"""
import pandas as pd

import utils

OUT = utils.OUT / "detection_latency"
INPUT = utils.DATA / "1s-gapped-bursts" / "results.csv"
LOW_DET = 1.0  # compressed table: dagger on cells that missed any burst (their MAE skips the misses, so it flatters them)


def stats(s):
    """(MAE, signed mean) over the non-NaN values; None when there are none."""
    s = s.dropna()
    return (s.abs().mean(), s.mean()) if len(s) else None


def latex_table(df):
    fmt = lambda t: " & ".join(f"{v:.1f}" for v in t) if t else "-- & --"
    lines = [r"\begin{tabular}{rrr rr rr}", r"\toprule",
             r" & & & \multicolumn{2}{c}{Onset (ms)} & \multicolumn{2}{c}{Drain (ms)} \\",
             r"\cmidrule(lr){4-5}\cmidrule(lr){6-7}",
             r"$w$ (ms) & Burst (ms) & Det & MAE & mean (signed) & MAE & mean (signed) \\"]
    for w, bs in utils.cells(df):
        lines.append(r"\midrule")
        for b in bs:
            c = df[(df.cusum_window_size == w) & (df.burst_window_size == b)]
            det = f"{int(c.detected.sum())}/{len(c)}"
            lines.append(f"{w} & {b} & {det} & {fmt(stats(c.onset_latency_ms))} & {fmt(stats(c.drain_latency_ms))} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def compressed_table(df):
    r"""Grid like detection_latency_medians.tex: rows burst lengths, columns CUSUM windows, cell `onset / drain` MAE.
    '--' = no detected burst on that side; $^\dagger$ = fewer than LOW_DET of the cell's bursts detected (caption it)."""
    ws = sorted(df.cusum_window_size.unique())
    bs = sorted(df.burst_window_size.unique())
    k = len(ws)

    def cell(w, b):
        c = df[(df.cusum_window_size == w) & (df.burst_window_size == b)]
        s = " / ".join("--" if (t := stats(c[col])) is None else f"{t[0]:.1f}"
                       for col in ("onset_latency_ms", "drain_latency_ms"))
        return s + r"$^\dagger$" if 0 < c.detected.mean() < LOW_DET else s

    lines = [rf"\begin{{tabular}}{{r{'r' * k}}}", r"\toprule",
             rf" & \multicolumn{{{k}}}{{c}}{{Onset / drain MAE (ms)}} \\", rf"\cmidrule(lr){{2-{k + 1}}}",
             "Burst length (ms) & " + " & ".join(f"$w={w}$" for w in ws) + r" \\", r"\midrule"]
    lines += [f"{b} & " + " & ".join(cell(w, b) for w in ws) + r" \\" for b in bs]
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main():
    df = pd.read_csv(INPUT)
    OUT.mkdir(parents=True, exist_ok=True)
    for name, table in (("detection_error_mae", latex_table), ("detection_error_mae_compressed", compressed_table)):
        path = OUT / f"{name}.tex"
        path.write_text(table(df))
        print(path)


if __name__ == "__main__":
    main()
