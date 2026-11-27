#!/usr/bin/env bash
# Staircase sweep: bursts climb 2500 -> 3333 -> 4167 -> 5000 rps in 3 equal abrupt steps, then drop
# to 2500. window x burst length, 5 reps each, run sequentially. Rates/gap come from the confs.
set -u
cd "$(dirname "$0")/.."

for w in 5 10 25 50 100; do
  for burst in 25 50 100 200 300 400; do
    echo "=== window=${w}ms burst=${burst}ms steps=3 ==="
    N_STEPS=3 BURSTY_WINDOW_SIZE_MS=$burst \
      ./experiments/run.sh "experiments/configs/w${w}.conf" \
        --campaign staircase_campaign --reps 5 --score \
      || echo "!!! FAILED w=${w} burst=${burst}" >&2
  done
done
