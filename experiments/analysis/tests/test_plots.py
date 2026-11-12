import sys
import tempfile
import unittest
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "plots"))

from detection_latency import latency_figure, latex_table, median_table
from detection_fidelity_heatmaps import overlap_heatmap
from detection_fidelity_per_burst import overlap_endpoints
from TPR import tpr_cell_table, tpr_figure
from FPR import fpr_figure, fpr_per_s
from shortly_gapped_burst_resolution_heatmaps import gapped_heatmap, resolved_per_run
from utils import with_precision


def frame(campaign="c", windows=(25, 50), bursts=(200, 500), reps=3, n=4, base=1000, peak=2000, miss=True):
    rows = []
    rng = np.random.default_rng(1)
    for w in windows:
        for b in bursts:
            for r in range(reps):
                for i in range(n):
                    missed = miss and w == windows[0] and r == 0 and i == 0
                    rows.append({
                        "campaign": campaign, "config_id": f"w{w}", "cusum_window_size": w,
                        "burst_window_size": b, "baseline_rps": base, "peak_rps": peak, "rep": r + 1,
                        "burst_idx": i, "detected": int(not missed), "drain_detected": int(not missed),
                        "onset_latency_ms": np.nan if missed else rng.normal(0, w),
                        "drain_latency_ms": np.nan if missed else rng.normal(0, w),
                        "iou_pct": np.nan if missed else rng.uniform(50, 100),
                        "coverage_pct": np.nan if missed else rng.uniform(50, 100),
                        "real_len_ms": b, "det_len_ms": np.nan if missed else rng.uniform(0.5, 1.5) * b,
                    })
    return pd.DataFrame(rows)


def nbars(fig):
    return sum(len(ax.patches) for ax in fig.axes)


class TestStats(unittest.TestCase):
    def test_fpr(self):
        self.assertAlmostEqual(fpr_per_s(3, 120), 0.025)
        self.assertTrue(np.isnan(fpr_per_s(1, 0)))

    def test_tpr_counts_misses(self):
        t = tpr_cell_table(frame())
        self.assertEqual(t[(25, 200)][:2], (11, 12))  # 12 bursts, one miss in the first rep
        self.assertEqual(t[(50, 200)][0], t[(50, 200)][1])


class TestFigures(unittest.TestCase):
    def setUp(self):
        self.f = {"a": frame("a"), "b": frame("b")}

    def test_latency(self):
        for w in (25, 50):
            fig = latency_figure(self.f["a"], w)
            self.assertEqual(len(fig.axes), 2 * 2)  # burst lengths x (onset, drain)

    def test_latency_marks_misses(self):
        fig = latency_figure(self.f["a"], 25)
        first = fig.axes[0]  # w=25, b=200 has one miss: one x marker, the rest are dots
        sizes = sorted(len(c.get_offsets()) for c in first.collections)
        self.assertEqual(sizes, [1, 11])

    def test_row_label_differing_counts(self):
        df = frame(miss=False)
        df.loc[(df.cusum_window_size == 25) & (df.burst_window_size == 200) & (df.rep == 1) & (df.burst_idx == 0),
               "drain_latency_ms"] = np.nan
        fig = latency_figure(df, 25)
        self.assertEqual(fig.axes[1].get_title("right"), "onset 12/12 · drain 11/12")
        self.assertEqual([t.get_text() for t in fig.texts if t.get_text().startswith("burst length = 200")], ["burst length = 200 ms"])

    def test_median_table(self):
        t = median_table(frame(miss=True))
        self.assertEqual(len(t), 4)  # windows x burst lengths
        first = t[(t.cusum_window_ms == 25) & (t.burst_length_ms == 200)].iloc[0]
        self.assertEqual((first.onset_detected, first.n), (11, 12))

    def test_latex_table(self):
        tex = latex_table(frame(miss=True))
        self.assertIn("\\begin{tabular}{rrr}", tex)
        self.assertIn("\\bottomrule", tex)
        self.assertIn(" / ", tex)
        self.assertNotIn("textcolor", tex)
        self.assertEqual(tex.count("\\\\"), 2 + 2)  # two header rows + two burst lengths

    def test_overlap_heatmap_and_endpoints(self):
        df = self.f["a"]
        self.assertEqual(len(overlap_heatmap(df, "IoU", "iou_pct").axes), 2)  # heatmap + colour bar
        fig = overlap_endpoints(df, 25, 200)
        self.assertEqual(len(fig.axes), 1)
        self.assertEqual(fig.axes[0].get_title("right"), "Missed 1/12")

    def test_tpr_per_burst_length(self):
        fig = tpr_figure(self.f["a"], 25)
        self.assertEqual(len(fig.axes), 1)
        self.assertEqual(len(fig.axes[0].patches), 2)  # one bar per burst size of that window

    def test_fpr_figure(self):
        runs = pd.DataFrame({"cusum_window_size": [25, 25, 50], "baseline_rps": [1000, 2000, 1000],
                             "fp_events": [1, 0, 0], "duration_s": [300.0, 300.0, 300.0]})
        fig = fpr_figure(runs, 25, 0.1)
        self.assertEqual(len(fig.axes[0].patches), 2)  # one bar per baseline rate
        self.assertEqual(len(fpr_figure(runs, 50, 0.1).axes[0].patches), 1)  # 2000 rps has no w=50 run

    def test_with_precision(self):
        df = with_precision(frame())
        self.assertEqual(int(df.missed.sum()), 2)  # one miss in each cell of the first window's first rep... 
        self.assertTrue((df[df.missed].iou_pct == 0).all())
        self.assertTrue((df[~df.missed].precision_pct > 0).all())

    def test_resolved_per_run(self):
        r = resolved_per_run(frame())
        self.assertEqual(r[(25, 200, 1)], 3)  # 4 bursts, one missed
        self.assertEqual(r[(50, 200, 1)], 4)
        self.assertEqual(len(gapped_heatmap(frame(), [25, 50], [200, 500]).axes), 2)  # heatmap + colour bar

    def test_keeps_sign(self):
        df = frame(miss=False)
        df["onset_latency_ms"] = -10.0
        fig = latency_figure(df, 25)
        ys = [o[1] for c in fig.axes[0].collections for o in c.get_offsets()]
        self.assertTrue(all(y == -10.0 for y in ys))


class TestSave(unittest.TestCase):
    def test_smoke_svg(self):
        fig = latency_figure(frame("a"), 25)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.svg"
            fig.savefig(p, format="svg")
            self.assertIn("<svg", p.read_text()[:500])

    def test_smoke_pdf(self):
        fig = latency_figure(frame("a"), 25)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "f.pdf"
            fig.savefig(p, format="pdf")
            self.assertEqual(p.read_bytes()[:5], b"%PDF-")


if __name__ == "__main__":
    unittest.main()
