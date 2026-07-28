#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOTEL_RES_DIR="$(realpath "$SCRIPT_DIR/benchmark/hotelReservation")"
WRK2_DIR="$(realpath "$SCRIPT_DIR/wrk2")"
LUA_SCRIPT="$HOTEL_RES_DIR/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"

if [ "$#" -ne 5 ]; then
  echo "Usage: $0 <rate> <duration> <threads> <conns> <target>" >&2
  echo "  rate     requests/sec (-R); constant throughput model" >&2
  echo "  duration seconds (-d); e.g. 3600 for a baseline run long enough for the counter to settle" >&2
  echo "  threads  worker threads (-t)" >&2
  echo "  conns    open connections (-c); keep > threads" >&2
  echo "  target   base URL, e.g. http://172.18.0.x:<NodePort>" >&2
  exit 1
fi

RATE="$1"
DURATION="$2"
THREADS="$3"
CONNS="$4"
TARGET="$5"

PF_PID=0  # PID of the port-forward we own (0 = we didn't start it)

# ── Phase 2: Run wrk2 steady-baseline load ────────────────────────────────────

echo "=== Phase 2: Load (rate=${RATE} rps  duration=${DURATION}s  threads=${THREADS}  conns=${CONNS}) ==="
echo ""
echo "  Running mixed-workload (60% search, 39% recommend, 1% login/reserve)"
echo "  against $TARGET — this is your mu_0 measurement window."
echo "  In a separate terminal run: cusum-detector -window 100ms -sample-windows -sample-csv /tmp/windows.csv
  Watch per-window delta_bytes rows accumulate in /tmp/windows.csv to derive mu_0/k/h_* values."
echo ""

"$WRK2_DIR/wrk" \
  -D exp \
  -t "$THREADS" \
  -c "$CONNS" \
  -d "$DURATION" \
  -L \
  -s "$LUA_SCRIPT" \
  "$TARGET" \
  -R "$RATE"