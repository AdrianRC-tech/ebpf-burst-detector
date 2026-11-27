import json
import tempfile
import unittest
from pathlib import Path

from analysis import score_run as sr

FIX = Path(__file__).parent / "fixtures" / "k6_example.txt"
K6 = FIX.read_text()
# burst starts 14:21:13.927, 19.427, 24.927, 30.427, 35.927 (500 ms long)
BURST_S = [13.927, 19.427, 24.927, 30.427, 35.927]


def tod(sec):
    return f"14:21:{int(sec):02d}.{int(round((sec % 1) * 1000)):03d}000000"


def rec(onset=None, drain=None, **extra):
    r = {"truncated": False, "unpaired": False}
    if onset is not None:
        r["onset_change_point_utc"] = onset
    if drain is not None:
        r["drain_change_point_utc"] = drain
    r.update(extra)
    return r


def events(recs):
    return "".join(json.dumps(r) + "\n" for r in recs)


def run(ev_text, k6=K6, **kw):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "attribution.ndjson"
        p.write_text(ev_text)
        return sr.score(k6, p, **kw)


def clean_events(onset_lat=0.1, drain_lat=0.1, skip=()):
    return events([rec(tod(s + onset_lat), tod(s + 0.5 + drain_lat))
                   for i, s in enumerate(BURST_S) if i not in skip])


class ScoreTests(unittest.TestCase):
    def test_parse_fixture(self):
        bursts, start, delivered = sr.parse_k6(K6)
        self.assertEqual(len(bursts), 5)
        self.assertEqual(bursts[0], (1792074073927000000, 1792074074427000000))
        self.assertEqual(start, 1792074063927000000)
        self.assertEqual(delivered, {0: 599, 1: 601, 2: 599, 3: 598, 4: 600})

    def test_all_matched(self):
        rows, r, _ = run(clean_events())
        self.assertEqual([x["detected"] for x in rows], [1] * 5)
        self.assertEqual([x["drain_detected"] for x in rows], [1] * 5)
        self.assertEqual(rows[0]["onset_latency_ms"], "100")
        self.assertEqual(rows[0]["drain_latency_ms"], "100")
        self.assertEqual(rows[0]["real_len_ms"], "500")
        self.assertEqual(rows[0]["det_len_ms"], "500")
        self.assertEqual(rows[0]["len_err_ms"], "0")
        self.assertEqual(rows[0]["coverage_pct"], "80")  # onset 100 ms late
        self.assertEqual(rows[0]["iou_pct"], "66.667")
        self.assertEqual(rows[0]["req_delivered"], 599)
        self.assertEqual(r["fp_events"], 0)
        self.assertEqual((r["n_onset_events"], r["n_drain_events"]), (5, 5))

    def test_missed_burst(self):
        rows, r, _ = run(clean_events(skip=(2,)))
        self.assertEqual([x["detected"] for x in rows], [1, 1, 0, 1, 1])
        self.assertEqual(rows[2]["onset_latency_ms"], "")
        self.assertEqual(rows[2]["coverage_pct"], "")

    def test_missed_drain(self):
        ev = events([rec(tod(13.927 + 0.1), unpaired=True)])
        rows, _r, _ = run(ev)
        self.assertEqual((rows[0]["detected"], rows[0]["drain_detected"]), (1, 0))
        self.assertEqual(rows[0]["coverage_pct"], "")
        self.assertEqual(rows[0]["len_err_ms"], "")
        self.assertEqual(rows[0]["iou_pct"], "")
        self.assertEqual(_r["n_unpaired"], 1)

    def test_false_positive(self):
        ev = clean_events() + events([rec("14:21:50.000000000", unpaired=True)])
        _, r, _ = run(ev)
        self.assertEqual(r["fp_events"], 1)

    def test_early_onset_late_drain_caps_coverage(self):
        rows, _, _ = run(events([rec(tod(13.927 - 0.2), tod(14.427 + 0.4))]))
        self.assertEqual(rows[0]["coverage_pct"], "100")
        self.assertEqual(rows[0]["iou_pct"], "45.455")  # 500 / 1100
        self.assertEqual(rows[0]["onset_latency_ms"], "-200")

    def test_tty_form_log(self):
        tty = "\n".join(
            l.replace('time="2026-10-15T16:21:03+02:00" level=info msg="', "INFO[0000] ")
             .replace('" source=console', "") for l in K6.splitlines())
        rows, _, _ = run(clean_events(), k6=tty)
        self.assertEqual(sum(x["detected"] for x in rows), 5)

    def test_no_table(self):
        k6 = K6.split("  burst   requests")[0]
        rows, _, _ = run(clean_events(), k6=k6)
        self.assertEqual(rows[0]["req_delivered"], "")

    def test_midnight_crossing(self):
        # shift the plan to 23:59:59.9 -> events after midnight lift to the next day
        base = 1792108799900000000  # 23:59:59.9 UTC
        k6 = f"plan: 000  {base}  {base + 500_000_000}  x  y\nscenario_start: {base - 10**10} ns\n"
        ev = events([rec("00:00:00.000000000", "00:00:00.400000000")])
        rows, _, _ = run(ev, k6=k6)
        self.assertEqual(rows[0]["onset_latency_ms"], "100")
        self.assertEqual(rows[0]["drain_latency_ms"], "0")

    def test_scenario_offset(self):
        _, r, _ = run(clean_events(), settle_s=10)
        self.assertEqual(r["scenario_offset_ms"], "0")

    def test_onset_cp_step(self):
        self.assertNotIn("onset_cp_step", run(clean_events())[0][0])  # flat bursts: no column
        # Burst 0 split into 3 steps ending at +167, +333, +500 ms.
        s0 = 1792074073927000000
        k6 = K6 + "".join(f"plan_step: 000 {j}  {r}rps  0  {s0 + e * 10**6}  x  y\n"
                          for j, (r, e) in enumerate([(3333, 167), (4167, 333), (5000, 500)]))
        for lat, want in ((-0.1, 0), (0.05, 1), (0.2, 2), (0.4, 3)):
            rows, _, _ = run(events([rec(tod(13.927 + lat), tod(14.5))]), k6=k6)
            self.assertEqual(rows[0]["onset_cp_step"], want, lat)

    def test_split_burst_scores_union_of_pieces(self):
        # Burst 0 (500 ms) detected as [0, 200] + [300, 500]: premature drain, re-onset 100 ms later.
        s = BURST_S[0]
        ev = events([rec(tod(s), tod(s + 0.2)), rec(tod(s + 0.3), tod(s + 0.5))])
        rows, r, _ = run(ev)
        self.assertEqual((rows[0]["n_pieces"], rows[0]["pieces"]), (2, "0:200;300:500"))
        self.assertEqual((rows[0]["onset_latency_ms"], rows[0]["drain_latency_ms"]), ("0", "0"))
        self.assertEqual(rows[0]["det_len_ms"], "400")  # the 100 ms gap is not detected time
        self.assertEqual((rows[0]["coverage_pct"], rows[0]["iou_pct"]), ("80", "80"))
        self.assertEqual((r["n_split"], r["n_early"], r["n_outside"]), (1, 0, 0))
        self.assertEqual(r["fp_events"], 2)  # the inner drain and re-onset

    def test_early_backdated_detection(self):
        # Onset 400 ms before the start (past the 300 ms tol): missed, drain kept, counted as early.
        rows, r, _ = run(events([rec(tod(BURST_S[0] - 0.4), tod(BURST_S[0] + 0.5))]))
        self.assertEqual((rows[0]["detected"], rows[0]["drain_detected"], rows[0]["n_pieces"]), (0, 1, 0))
        self.assertEqual((r["n_split"], r["n_early"], r["n_outside"]), (0, 1, 0))

    def test_early_drain_serves_one_burst(self):
        # One early detection spanning bursts 0 and 1: its drain may be claimed once, never negative fp.
        rows, r, _ = run(events([rec(tod(BURST_S[0] - 0.4), tod(BURST_S[0] + 0.6))]),
                         k6=K6, tol_drain_ms=10_000)
        self.assertEqual([x["drain_detected"] for x in rows], [1, 0, 0, 0, 0])
        self.assertEqual((r["fp_events"], r["n_early"]), (1, 1))

    def test_outside_and_pre_burst_blip(self):
        # A blip that drains before the burst starts is not a piece of it, even within tol.
        s = BURST_S[0]
        ev = clean_events() + events([rec(tod(s - 0.2), tod(s - 0.1)), rec("14:21:50.000000000", unpaired=True)])
        rows, r, _ = run(ev)
        self.assertEqual(rows[0]["n_pieces"], 1)
        self.assertEqual((r["n_split"], r["n_early"], r["n_outside"]), (0, 0, 2))

    def test_empty_utc_skipped(self):
        ev = clean_events() + events([rec("", unpaired=True)])
        _, r, _ = run(ev)
        self.assertEqual(r["n_onset_events"], 6)
        self.assertEqual(r["fp_events"], 0)


if __name__ == "__main__":
    unittest.main()
