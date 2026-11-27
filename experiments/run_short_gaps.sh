#!/usr/bin/env bash
# Short-gap sweep: gap x window x burst length, 5 reps each, run sequentially.
# run.sh lets env vars override the conf, so the conf files are never edited.
set -u
cd "$(dirname "$0")/.."

for gap in 50 100 250 400; do
  for w in 5 10 25 50 100; do
    for burst in 100 200 500; do
      echo "=== gap=${gap}ms window=${w}ms burst=${burst}ms ==="
      WINDOW=${w}ms GAP_S=$(awk "BEGIN{print $gap/1000}") BURSTY_WINDOW_SIZE_MS=$burst \
        ./experiments/run.sh "experiments/configs/w${w}.conf" \
          --campaign "${gap}ms-gapped-bursts" --reps 5 --score \
        || echo "!!! FAILED gap=${gap} w=${w} burst=${burst}" >&2
    done
  done
done
