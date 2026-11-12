"""Load every scored rep of a campaign into one DataFrame (offline analysis only)."""
import glob
import sys

import pandas as pd

def read_meta(path):
    with open(path) as f:
        return dict(line.rstrip("\n").split("=", 1) for line in f if "=" in line)


def _load_files(campaign, root, name, with_burst_idx):
    frames = []
    for p in sorted(glob.glob(f"{root}/{campaign}/*/rep*/{name}")):
        cfg, rep, _ = p.split("/")[-3:]
        df = pd.read_csv(p)
        if with_burst_idx:
            df.insert(0, "burst_idx", range(len(df)))
        df.insert(0, "rep", int(rep[3:]))
        m = read_meta(p.rsplit("/", 1)[0] + "/meta.env")
        base = int(m["BASELINE_RATE"])
        df.insert(0, "burst_window_size", int(m["BURSTY_WINDOW_SIZE_MS"]))
        df.insert(0, "peak_rps", base + int(m["BURSTY_WINDOW_RPS"]))
        df.insert(0, "baseline_rps", base)
        df.insert(0, "cusum_window_size", int(m["WINDOW"].removesuffix("ms")))
        df.insert(0, "config_id", cfg)
        df.insert(0, "campaign", campaign)
        frames.append(df)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def load(campaign, root="tmp/runs", name="results.csv"):
    """One row per burst. Empty DataFrame when the campaign has no scored reps."""
    return _load_files(campaign, root, name, with_burst_idx=True)


def load_runs(campaign, root="tmp/runs"):
    """One row per run (run.csv: fp_events, duration_s, ...), same key columns as load()."""
    return _load_files(campaign, root, "run.csv", with_burst_idx=False)


if __name__ == "__main__":
    print(load(sys.argv[1]).groupby(["cusum_window_size", "burst_window_size"]).detected.mean())
