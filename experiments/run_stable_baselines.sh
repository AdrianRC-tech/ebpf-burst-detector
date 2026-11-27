#!/usr/bin/env bash
# Burst-free false-positive campaigns, 15 min each, 1 rep per window, run sequentially:
#   flat-baseline  : constant 2500 rps (bursts.js, N_BURSTS=0)  -> detector's intrinsic FP rate
#   drift-baseline : 2500 -> 3000 -> 2500 half-sine + +-8% wander (drift.js) -> FP rate under
#                    production-like drift
# Total ~2.6 h (10 runs x 15 min + startup/grace). run.sh lets env vars override the conf.
set -u
cd "$(dirname "$0")/.."

DURATION_S=${DURATION_S:-900}

for scenario in flat drift; do
  for w in 5 10 25 50 100; do
    echo "=== ${scenario} window=${w}ms duration=${DURATION_S}s ==="
    script=loadgen/k6/bursts.js; [ "$scenario" = drift ] && script=loadgen/k6/drift.js
    K6_SCRIPT=$script N_BURSTS=0 BURSTY_WINDOW_RPS=0 BURSTY_WINDOW_SIZE_MS=0 BASELINE_RATE=2500 \
      TAIL_S=$DURATION_S \
      ./experiments/run.sh "experiments/configs/w${w}.conf" \
        --campaign "${scenario}-baseline" --reps 1 --score \
      || echo "!!! FAILED ${scenario} w=${w}" >&2
  done
done
