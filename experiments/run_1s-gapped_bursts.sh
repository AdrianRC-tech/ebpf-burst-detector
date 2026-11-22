#!/usr/bin/env bash
# 1 s gap sweep for windows 50/100 ms (5/10/25 were run manually), 5 reps each.
set -u
cd "$(dirname "$0")/.."

for w in 50 100; do
  for burst in 25 50 100 200 300 400 500; do
    echo "=== window=${w}ms burst=${burst}ms ==="
    GAP_S=1 BURSTY_WINDOW_SIZE_MS=$burst \
      ./experiments/run.sh "experiments/configs/w${w}.conf" \
        --campaign 1s-gapped-bursts --reps 5 --score \
      || echo "!!! FAILED w=${w} burst=${burst}" >&2
  done
done
