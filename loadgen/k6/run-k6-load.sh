#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_SCRIPT="$SCRIPT_DIR/mixed-workload.js"

# ── tunables ──────────────────────────────────────────────────────────────────
# Edit here, or override the first five positionally.

TARGET="http://172.18.0.2:30500"
BASELINE_RATE=100            # steady-state rps
BURSTY_WINDOW_RPS=100        # ADDITIVE rps during a bursty window (peak = baseline + this)
BURSTY_WINDOW_SIZE_MS=800    # bursty window duration
N_BURSTS=10                  # bursty windows per run; 0 = baseline only
GAP_S=10                     # baseline seconds between bursty windows

# Rarely changed.
SETTLE_S=5                 # baseline lead-in so memcached/mongo caches fill; excluded from analysis
TAIL_S=5                    # baseline after the last bursty window
PRE_ALLOC_VUS=20             # wrk2 -c 20 equivalent
MAX_VUS=80
SEED=1337

usage() {
  cat >&2 <<EOF
Usage: $0 [baseline_rate] [bursty_window_rps] [bursty_window_size_ms] [n_bursts] [target]

  baseline_rate          steady-state rps                           (default $BASELINE_RATE)
  bursty_window_rps      ADDITIVE rps during a bursty window        (default $BURSTY_WINDOW_RPS)
  bursty_window_size_ms  bursty window duration in ms               (default $BURSTY_WINDOW_SIZE_MS)
  n_bursts               number of bursty windows, 0 = baseline only (default $N_BURSTS)
  target                 base URL                                   (default $TARGET)

Peak offered rate is baseline_rate + bursty_window_rps.
All bursty windows run inside ONE k6 process: n_bursts is a loop in the stage list, not in bash.
EOF
  exit 1
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then usage; fi
if [ "$#" -gt 5 ]; then usage; fi

if [ "$#" -ge 1 ]; then BASELINE_RATE="$1"; fi
if [ "$#" -ge 2 ]; then BURSTY_WINDOW_RPS="$2"; fi
if [ "$#" -ge 3 ]; then BURSTY_WINDOW_SIZE_MS="$3"; fi
if [ "$#" -ge 4 ]; then N_BURSTS="$4"; fi
if [ "$#" -ge 5 ]; then TARGET="$5"; fi

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 not found on PATH — see $SCRIPT_DIR/README.md for install." >&2
  exit 1
fi

PEAK_RATE=$(( BASELINE_RATE + BURSTY_WINDOW_RPS ))
TOTAL_S=$(( (SETTLE_S * 1000 + N_BURSTS * (BURSTY_WINDOW_SIZE_MS + GAP_S * 1000) + TAIL_S * 1000) / 1000 ))

echo "=== k6 mixed workload (60% search, 39% recommend, 1% login/reserve) ==="
echo "  baseline       ${BASELINE_RATE} rps"
echo "  bursty window  +${BURSTY_WINDOW_RPS} rps -> ${PEAK_RATE} rps peak, ${BURSTY_WINDOW_SIZE_MS} ms, x${N_BURSTS}, ${GAP_S}s apart"
echo "  target         ${TARGET}"
echo "  duration       ~${TOTAL_S}s (includes ${SETTLE_S}s settle + ${TAIL_S}s tail)"
echo ""

# exec so Ctrl-C reaches k6 directly.
exec k6 run \
  -e TARGET="$TARGET" \
  -e BASELINE_RATE="$BASELINE_RATE" \
  -e BURSTY_WINDOW_RPS="$BURSTY_WINDOW_RPS" \
  -e BURSTY_WINDOW_SIZE_MS="$BURSTY_WINDOW_SIZE_MS" \
  -e N_BURSTS="$N_BURSTS" \
  -e GAP_S="$GAP_S" \
  -e SETTLE_S="$SETTLE_S" \
  -e TAIL_S="$TAIL_S" \
  -e PRE_ALLOC_VUS="$PRE_ALLOC_VUS" \
  -e MAX_VUS="$MAX_VUS" \
  -e SEED="$SEED" \
  "$K6_SCRIPT"
