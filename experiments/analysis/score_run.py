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
START_RE = re.compile(r"scenario_start: (\d+) ns")
HEADER_RE = re.compile(r"^\s+burst\s+requests\s+expected")
ROW_RE = re.compile(r"^\s+(\d{3})\s+(\d+)\s+(\d+)")
TOD_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?$")

RESULT_FIELDS = [
    "gt_start_utc", "gt_end_utc", "onset_cp_utc", "drain_cp_utc",
    "detected", "drain_detected",
    "onset_latency_ms", "drain_latency_ms",
    "real_len_ms", "det_len_ms", "len_err_ms", "coverage_pct", "iou_pct",
    "req_delivered",
]
RUN_FIELDS = ["fp_events", "n_onset_events", "n_drain_events", "n_unpaired", "n_truncated",
              "scenario_offset_ms", "duration_s"]


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
    """Return ([(type, epoch_ns)], totals) from attribution NDJSON, one record per burst.

    Drain is skipped for unpaired records (onset only). Totals count every onset/drain
    present, even when its UTC field is missing and so unusable for scoring.
    """
    events, totals = [], {"onset": 0, "drain": 0, "unpaired": 0, "truncated": 0}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            unpaired = bool(rec.get("unpaired"))
            totals["unpaired"] += unpaired
            totals["truncated"] += bool(rec.get("truncated"))
            for typ, key in (("onset", "onset_change_point_utc"), ("drain", "drain_change_point_utc")):
                if typ == "drain" and unpaired:
                    continue
                totals[typ] += 1
                ns = tod_to_ns(rec.get(key) or "", ref_ns)
                if ns is not None:
                    events.append((typ, ns))
    events.sort(key=lambda e: e[1])
    return events, totals


def fmt_ts(ns):
    if ns is None:
        return ""
    dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
    return f"{dt:%H:%M:%S}.{ns % 1_000_000_000 // NS_MS:03d}"


def ms(x):
    return "" if x is None else f"{x:.3f}".rstrip("0").rstrip(".")


def match(bursts, events, tol_ns, tol_drain_ns):
    """Greedy in burst order. Returns ([(onset_ns|None, drain_ns|None)], fp_count)."""
    used, out = set(), []
    for start, end in bursts:
        onset = next((i for i, (t, ns) in enumerate(events)
                      if t == "onset" and i not in used and start - tol_ns <= ns <= end), None)
        if onset is not None:
            used.add(onset)
        lo = max(end - tol_ns, events[onset][1]) if onset is not None else end - tol_ns
        drain = next((i for i, (t, ns) in enumerate(events)
                      if t == "drain" and i not in used and lo <= ns <= end + tol_drain_ns), None)
        if drain is not None:
            used.add(drain)
        out.append((events[onset][1] if onset is not None else None,
                    events[drain][1] if drain is not None else None))
    return out, len(events) - len(used)


def score(k6_text, attribution_path, tol_ms=300, tol_drain_ms=1000, settle_s=None, quiescent_s=None):
    """quiescent_s: SETTLE_S + TAIL_S, only used for baseline-only runs (N_BURSTS=0, no plan lines)."""
    bursts, scen_start, delivered = parse_k6(k6_text)
    if not bursts:
        if scen_start is None or quiescent_s is None:
            raise ValueError("no 'plan: NNN start end' lines in k6 log")
        # Baseline-only run: every event is a false positive.
        events, totals = parse_attribution(attribution_path, scen_start)
        run = {
            "fp_events": len(events), "n_onset_events": totals["onset"], "n_drain_events": totals["drain"],
            "n_unpaired": totals["unpaired"], "n_truncated": totals["truncated"],
            "scenario_offset_ms": "", "duration_s": ms(quiescent_s),
        }
        return [], run, scen_start
    events, totals = parse_attribution(attribution_path, bursts[0][0])
    matched, fp = match(bursts, events, int(tol_ms * NS_MS), int(tol_drain_ms * NS_MS))
    rows = []
    for i, ((gs, ge), (on, dr)) in enumerate(zip(bursts, matched)):
        real = (ge - gs) / NS_MS
        lat_on = (on - gs) / NS_MS if on is not None else None
        lat_dr = (dr - ge) / NS_MS if dr is not None else None
        det = (dr - on) / NS_MS if on is not None and dr is not None else None
        cov = iou = None
        if det is not None:
            cov = max(0.0, min(100.0, 100 * (min(dr, ge) - max(on, gs)) / NS_MS / real))
            overlap = max(0, min(dr, ge) - max(on, gs))
            iou = 100 * overlap / ((dr - on) + (ge - gs) - overlap)
        rows.append({
            "gt_start_utc": fmt_ts(gs), "gt_end_utc": fmt_ts(ge),
            "onset_cp_utc": fmt_ts(on), "drain_cp_utc": fmt_ts(dr),
            "detected": int(on is not None), "drain_detected": int(dr is not None),
            "onset_latency_ms": ms(lat_on), "drain_latency_ms": ms(lat_dr),
            "real_len_ms": ms(real), "det_len_ms": ms(det),
            "len_err_ms": ms(det - real if det is not None else None),
            "coverage_pct": ms(cov), "iou_pct": ms(iou),
            "req_delivered": delivered.get(i, ""),
        })
    # Plan is anchored at setup(): t0 = burst0_start - settle - ramp. Offset = actual scenario start - t0.
    offset = None
    if scen_start is not None and settle_s is not None:
        m = RAMP_RE.search(k6_text)
        ramp_ns = int(m.group(1)) * NS_MS if m else 0
        offset = (scen_start - (bursts[0][0] - int(settle_s * 1e9) - ramp_ns)) / NS_MS
    run = {
        "fp_events": fp, "n_onset_events": totals["onset"], "n_drain_events": totals["drain"],
        "n_unpaired": totals["unpaired"], "n_truncated": totals["truncated"],
        "scenario_offset_ms": ms(offset), "duration_s": "",
    }
    return rows, run, scen_start


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
        write_csv(d / "results.csv", RESULT_FIELDS, rows)
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
