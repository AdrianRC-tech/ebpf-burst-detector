#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOTEL_RES_DIR="$(realpath "$SCRIPT_DIR/benchmark/hotelReservation")"
WRK2_DIR="$(realpath "$SCRIPT_DIR/wrk2")"
LUA_SCRIPT="$HOTEL_RES_DIR/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"

# ── Parameters (override via env vars) ────────────────────────────────────────
# Defaults are tuned for a steady baseline run (mu_0 derivation):
# - Low rate (80 rps) produces a stable, low-variance signal.
# - 1h  duration gives the scenario a baseline for the ingress-counter.
# - 100 connections > 3 threads so threads are possibly not idle waiting for sockets.
RATE="${RATE:-80}"        # requests/sec (-R); constant throughput model
DURATION="${DURATION:-3600}" # seconds (-d); long enough for the counter to settle
THREADS="${THREADS:-3}"    # worker threads (-t)
CONNS="${CONNS:-100}"       # open connections (-c); keep > THREADS
TARGET="${TARGET:-http://localhost:5000}"

PF_PID=0  # PID of the port-forward we own (0 = we didn't start it)

# ── Phase 1: Ensure wrk2 binary ───────────────────────────────────────────────

echo "=== Phase 1: wrk2 binary ==="

if [ ! -f "$WRK2_DIR/wrk" ]; then
  echo "  wrk binary not found — building wrk2..."
  if ! command -v make &>/dev/null; then
    echo "ERROR: 'make' not found. Install build tools:" >&2
    echo "       sudo apt-get install -y build-essential libssl-dev" >&2
    exit 1
  fi
  if ! dpkg -s libssl-dev &>/dev/null 2>&1; then
    echo "  Installing build dependencies (build-essential libssl-dev)..."
    sudo apt-get install -y build-essential libssl-dev
  fi
  echo "  Running make -C wrk2/ (this takes ~1-2 min the first time)..."
  make -C "$WRK2_DIR"
  echo "  [OK] wrk built at $WRK2_DIR/wrk"
else
  echo "  [OK] wrk already built: $WRK2_DIR/wrk"
fi

# ── Phase 2: Run wrk2 steady-baseline load ────────────────────────────────────

echo "=== Phase 2: Load (rate=${RATE} rps  duration=${DURATION}s  threads=${THREADS}  conns=${CONNS}) ==="
echo ""
echo "  Running mixed-workload (60% search, 39% recommend, 1% login/reserve)"
echo "  against $TARGET — this is your mu_0 measurement window."
echo "  Watch 'delta_bytes' in the ingress-counter output stabilise."
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