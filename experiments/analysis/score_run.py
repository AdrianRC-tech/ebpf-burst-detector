#!/usr/bin/env python3
"""Score experiment run dirs: k6.log + attribution.ndjson -> results.csv (per burst) + run.csv (per run).

Offline analysis only (stdlib, no dependencies). Usage:
    python3 experiments/analysis/score_run.py tmp/runs/<campaign>/*/rep* [--tol-ms 300] [--tol-drain-ms 1000]
"""
import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

NS_MS = 1_000_000
DAY_NS = 86_400 * 1_000_000_000

PLAN_RE = re.compile(r"plan: (\d{3})\s+(\d+)\s+(\d+)\s")
RAMP_RE = re.compile(r"plan: baseline=.*? ramp=(\d+)ms")
STEP_RE = re.compile(r"plan_step: (\d{3}) \d+\s+\d+rps\s+\d+\s+(\d+)\s")
START_RE = re.compile(r"scenario_start: (\d+) ns")
HEADER_RE = re.compile(r"^\s+burst\s+requests\s+expected")
ROW_RE = re.compile(r"^\s+(\d{3})\s+(\d+)\s+(\d+)")
TOD_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$")

RESULT_FIELDS = [
    "gt_start_utc", "gt_end_utc", "onset_cp_utc", "drain_cp_utc",
    "detected", "drain_detected",
    "onset_latency_ms", "drain_latency_ms",
    "real_len_ms", "det_len_ms", "len_err_ms", "coverage_pct", "iou_pct",
    "req_delivered", "n_pieces", "pieces",
]
RUN_FIELDS = ["fp_events", "n_onset_events", "n_drain_events", "n_unpaired", "n_truncated",
              "scenario_offset_ms", "duration_s", "n_split", "n_early", "n_outside"]


def parse_k6(text):
    """Return (bursts [(start_ns, end_ns)], scenario_start_ns|None, {idx: delivered})."""
    plan, start, delivered, in_table = {}, None, {}, False
    for line in text.splitlines():
        m = PLAN_RE.search(line)
        if m:
            plan[int(m.group(1))] = (int(m.group(2)), int(m.group(3)))
            continue
        m = START_RE.search(line)
        if m:
            start = int(m.group(1))
            continue
        if HEADER_RE.match(line):
            in_table = True
            continue
        if in_table:
            m = ROW_RE.match(line)
            if m:
                delivered[int(m.group(1))] = int(m.group(2))
            elif line.strip():
                in_table = False
    return [plan[i] for i in sorted(plan)], start, delivered


def parse_steps(text):
    """{burst_idx: [step_end_ns, ...]} from bursts.js N_STEPS>1 runs; {} for flat bursts."""
    steps = {}
    for m in STEP_RE.finditer(text):
        steps.setdefault(int(m.group(1)), []).append(int(m.group(2)))
    return steps


def step_of(ns, start, ends):
    """1-based step containing ns; 0 = before step 1 (early, within --tol-ms)."""
    if ns < start:
        return 0
    return next((j + 1 for j, e in enumerate(ends) if ns < e), len(ends))


def tod_to_ns(tod, ref_ns):
    """Lift a UTC time-of-day to epoch ns, choosing the day nearest to ref_ns."""
    m = TOD_RE.match(tod.strip())
    if not m:
        return None
    h, mi, s, frac = m.groups()
    sod = ((int(h) * 60 + int(mi)) * 60 + int(s)) * 1_000_000_000 + int((frac or "0").ljust(9, "0"))
    day0 = ref_ns - ref_ns % DAY_NS
    return min((day0 + d * DAY_NS + sod for d in (-1, 0, 1)), key=lambda t: abs(t - ref_ns))


def parse_attribution(path, ref_ns):
    """Return ([(onset_ns, drain_ns|None)], totals) from attribution NDJSON, one detection per record.

    Drain is None for unpaired records (onset only). Records without a usable onset are dropped.
    Totals count every onset/drain present, even when its UTC field is missing and so unusable for scoring.
    """
    recs, totals = [], {"onset": 0, "drain": 0, "unpaired": 0, "truncated": 0}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            unpaired = bool(rec.get("unpaired"))
            totals["unpaired"] += unpaired
            totals["truncated"] += bool(rec.get("truncated"))
            totals["onset"] += 1
            on = tod_to_ns(rec.get("onset_change_point_utc") or "", ref_ns)
            dr = None
            if not unpaired:
                totals["drain"] += 1
                dr = tod_to_ns(rec.get("drain_change_point_utc") or "", ref_ns)
            if on is not None:
                recs.append((on, dr))
    recs.sort(key=lambda r: r[0])
    return recs, totals


def fmt_ts(ns):
    if ns is None:
        return ""
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return f"{dt:%H:%M:%S}.{ns % 1_000_000_000 // NS_MS:03d}"


def ms(x):
    return "" if x is None else f"{x:.3f}".rstrip("0").rstrip(".")


def match(bursts, recs, tol_ns, tol_drain_ns):
    """Assign detections (onset_ns, drain_ns|None) to bursts, greedy in burst order.

    A burst's pieces are the unused detections with onset in [start - tol, end] that overlap it
    (drain None counts as open-ended). More than one piece means the burst was split by a
    premature drain and a re-onset. A burst with no piece may still take its drain from a
    detection whose onset was backdated more than tol before the start (old drain-only match),
    if that drain lies in [end - tol, end + tol_drain].

    Returns (per_burst [(pieces, early_drain_ns|None)], kinds) where kinds counts the
    detections not assigned as pieces: early = overlaps some burst (onset backdated past tol),
    outside = overlaps none.
    """
    used, early_used, out = set(), set(), []
    for start, end in bursts:
        pieces = []
        for i, (on, dr) in enumerate(recs):
            if i not in used and start - tol_ns <= on <= end and (dr is None or dr >= start):
                used.add(i)
                pieces.append((on, dr))
        early = None
        if not pieces:
            j = next((i for i, (on, dr) in enumerate(recs)
                      if i not in used and on < start - tol_ns
                      and dr is not None and end - tol_ns <= dr <= end + tol_drain_ns), None)
            if j is not None:
                used.add(j)  # its drain serves this burst only; the detection still counts as early
                early_used.add(j)
                early = recs[j][1]
        out.append((pieces, early))
    kinds = {"early": len(early_used), "outside": 0}
    for i, (on, dr) in enumerate(recs):
        if i in used:
            continue
        hits = any(on <= e and (dr is None or dr >= s) for s, e in bursts)
        kinds["early" if hits else "outside"] += 1
    return out, kinds


def burst_scores(start, end, pieces, early, tol_drain_ns):
    """(onset, drain, det_ns, overlap_ns) for one burst. Onset = first piece, drain = last piece's
    drain (or the early drain-only match). det/overlap are the union of the pieces, so gaps between
    pieces count as undetected; None unless every piece has a drain and the last one is in time."""
    onset = pieces[0][0] if pieces else None
    drain = pieces[-1][1] if pieces else early
    if drain is not None and drain > end + tol_drain_ns:
        drain = None
    if not pieces or drain is None or any(dr is None for _, dr in pieces):
        return onset, drain, None, None
    det = sum(dr - on for on, dr in pieces)
    overlap = sum(max(0, min(dr, end) - max(on, start)) for on, dr in pieces)
    return onset, drain, det, overlap


def fmt_pieces(start, pieces):
    """'on:dr;on:dr' in ms relative to the burst start; dr empty when the piece never drained."""
    return ";".join(f"{ms((on - start) / NS_MS)}:{ms((dr - start) / NS_MS) if dr is not None else ''}"
                    for on, dr in pieces)


def score(k6_text, attribution_path, tol_ms=300, tol_drain_ms=1000, settle_s=None, quiescent_s=None):
    """quiescent_s: SETTLE_S + TAIL_S, only used for baseline-only runs (N_BURSTS=0, no plan lines)."""
    bursts, scen_start, delivered = parse_k6(k6_text)
    if not bursts:
        if scen_start is None or quiescent_s is None:
            raise ValueError("no 'plan: NNN start end' lines in k6 log")
        # Baseline-only run: every detection is a false positive, all of them outside any burst.
        recs, totals = parse_attribution(attribution_path, scen_start)
        run = {
            "fp_events": n_events(recs), "n_onset_events": totals["onset"], "n_drain_events": totals["drain"],
            "n_unpaired": totals["unpaired"], "n_truncated": totals["truncated"],
            "scenario_offset_ms": "", "duration_s": ms(quiescent_s),
            "n_split": 0, "n_early": 0, "n_outside": len(recs),
        }
        return [], run, scen_start
    steps = parse_steps(k6_text)
    recs, totals = parse_attribution(attribution_path, bursts[0][0])
    tol_drain_ns = int(tol_drain_ms * NS_MS)
    matched, kinds = match(bursts, recs, int(tol_ms * NS_MS), tol_drain_ns)
    rows, used_events = [], 0
    for i, ((gs, ge), (pieces, early)) in enumerate(zip(bursts, matched)):
        on, dr, det_ns, overlap_ns = burst_scores(gs, ge, pieces, early, tol_drain_ns)
        used_events += (on is not None) + (dr is not None)
        real = (ge - gs) / NS_MS
        lat_on = (on - gs) / NS_MS if on is not None else None
        lat_dr = (dr - ge) / NS_MS if dr is not None else None
        det = det_ns / NS_MS if det_ns is not None else None
        cov = iou = None
        if det is not None:
            cov = min(100.0, 100 * overlap_ns / (ge - gs))
            iou = 100 * overlap_ns / (det_ns + (ge - gs) - overlap_ns)
        rows.append({
            "gt_start_utc": fmt_ts(gs), "gt_end_utc": fmt_ts(ge),
            "onset_cp_utc": fmt_ts(on), "drain_cp_utc": fmt_ts(dr),
            "detected": int(on is not None), "drain_detected": int(dr is not None),
            "onset_latency_ms": ms(lat_on), "drain_latency_ms": ms(lat_dr),
            "real_len_ms": ms(real), "det_len_ms": ms(det),
            "len_err_ms": ms(det - real if det is not None else None),
            "coverage_pct": ms(cov), "iou_pct": ms(iou),
            "req_delivered": delivered.get(i, ""),
            "n_pieces": len(pieces), "pieces": fmt_pieces(gs, pieces),
        })
        if steps:  # staircase runs only: which step the onset change point fell in
            rows[-1]["onset_cp_step"] = step_of(on, gs, steps[i]) if on is not None else ""
    # Plan is anchored at setup(): t0 = burst0_start - settle - ramp. Offset = actual scenario start - t0.
    offset = None
    if scen_start is not None and settle_s is not None:
        m = RAMP_RE.search(k6_text)
        ramp_ns = int(m.group(1)) * NS_MS if m else 0
        offset = (scen_start - (bursts[0][0] - int(settle_s * 1e9) - ramp_ns)) / NS_MS
    run = {
        # fp_events: onset/drain events that are not a burst's first onset or final drain (unchanged meaning).
        "fp_events": n_events(recs) - used_events, "n_onset_events": totals["onset"],
        "n_drain_events": totals["drain"], "n_unpaired": totals["unpaired"], "n_truncated": totals["truncated"],
        "scenario_offset_ms": ms(offset), "duration_s": "",
        # The same false detections by cause, counted in detections (onset/drain records), not events.
        "n_split": sum(max(0, len(p) - 1) for p, _ in matched), **{f"n_{k}": v for k, v in kinds.items()},
    }
    return rows, run, scen_start


def n_events(recs):
    """Usable onset + drain timestamps."""
    return sum(1 + (dr is not None) for _, dr in recs)


def write_csv(path, fields, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def score_dir(d, tol_ms, tol_drain_ms):
    d = Path(d)
    settle_s = tail_s = None
    meta = d / "meta.env"
    if meta.exists():
        text = meta.read_text()
        m = re.search(r"^SETTLE_S=(\S+)", text, re.M)
        settle_s = float(m.group(1)) if m else None
        m = re.search(r"^TAIL_S=(\S+)", text, re.M)
        tail_s = float(m.group(1)) if m else None
    quiescent_s = settle_s + tail_s if settle_s is not None and tail_s is not None else None
    rows, run, _ = score((d / "k6.log").read_text(errors="replace"), d / "attribution.ndjson",
                         tol_ms, tol_drain_ms, settle_s, quiescent_s)
    if rows:
        write_csv(d / "results.csv", RESULT_FIELDS + [k for k in rows[0] if k not in RESULT_FIELDS], rows)
    write_csv(d / "run.csv", RUN_FIELDS, [run])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--tol-ms", type=float, default=300)
    ap.add_argument("--tol-drain-ms", type=float, default=1000)
    args = ap.parse_args(argv)
    rc = 0
    for d in args.run_dirs:
        try:
            score_dir(d, args.tol_ms, args.tol_drain_ms)
        except (OSError, ValueError) as e:
            print(f"skip {d}: {e}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
