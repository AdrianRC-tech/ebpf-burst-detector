#!/usr/bin/env bash
# One-command baseline calibration: detector sampling in the kind node + steady k6 load on the host,
# then baseline-stats. stdout is exactly the baseline-stats report (copy MU0/K/H_ONSET into the conf);
# progress and k6 output go to stderr.
# Usage: [BASELINE_RATE=2500 SETTLE_S=60 ...] ./experiments/calibrate.sh [--window 100ms]
set -euo pipefail
cd "$(dirname "$0")/.."

NODE=${NODE:-burst-detection-lab-worker}
BASELINE_RATE=${BASELINE_RATE:-2500}
SETTLE_S=${SETTLE_S:-60}
PRE_ALLOC_VUS=${PRE_ALLOC_VUS:-300}
MAX_VUS=${MAX_VUS:-350}
TARGET=${TARGET:-http://172.18.0.2:30500}
K_MULT=${K_MULT:-1}
H_MULT=${H_MULT:-6}
DROP_WARMUP=${DROP_WARMUP:-0}
BPF_DIR=/sys/fs/bpf/burst-detector

WINDOW=100ms
while [ $# -gt 0 ]; do
  case $1 in
    --window) WINDOW=${2:?--window needs a value}; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ $WINDOW =~ ^[0-9]+ms$ ]] || { echo "--window must look like 100ms, got: $WINDOW" >&2; exit 2; }
WINDOW_MS=${WINDOW%ms}

nx() { docker exec "$NODE" "$@"; }
log() { echo "calibrate: $*" >&2; }

[ -x bin/baseline-stats ] || { echo "bin/baseline-stats not found; build it first" >&2; exit 1; }
nx test -x /usr/local/bin/burst-detector 2>/dev/null \
  || { echo "/usr/local/bin/burst-detector missing or not executable in $NODE; build/deploy it first" >&2; exit 1; }

cleanup() {
  # Same pattern as run.sh: separate argv execs, never `sh -c` with pkill -f.
  if nx pgrep -f /burst-detector >/dev/null 2>&1; then
    nx pkill -f /burst-detector >/dev/null 2>&1 || true
    for _ in $(seq 50); do nx pgrep -f /burst-detector >/dev/null 2>&1 || break; sleep 0.2; done
    nx pkill -KILL -f /burst-detector >/dev/null 2>&1 || true
  fi
  nx rm -rf "$BPF_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

CSV=tmp/calibration/w${WINDOW_MS}_windows.csv
NODE_CSV=/tmp/ebpf-burst-detector/calibration/w${WINDOW_MS}_windows.csv
mkdir -p tmp/calibration
rm -f "$CSV"

cleanup
log "starting detector (window=$WINDOW)"
docker exec -d "$NODE" /usr/local/bin/burst-detector -window "$WINDOW" --sample-windows --sample-csv "$NODE_CSV"
for _ in $(seq 100); do [ -e "$CSV" ] && break; sleep 0.2; done
[ -e "$CSV" ] || { echo "detector did not create $CSV" >&2; exit 1; }

log "steady load: ${BASELINE_RATE} rps for ${SETTLE_S}s"
k6 run loadgen/k6/bursts.js \
  -e N_BURSTS=0 -e GAP_S=5 -e BURSTY_WINDOW_SIZE_MS=500 -e TAIL_S=0 \
  -e BASELINE_RATE="$BASELINE_RATE" -e SETTLE_S="$SETTLE_S" -e BURSTY_WINDOW_RPS=0 \
  -e TARGET="$TARGET" -e PRE_ALLOC_VUS="$PRE_ALLOC_VUS" -e MAX_VUS="$MAX_VUS" >&2

cleanup   # SIGTERM -> detector flushes the CSV before we read it

log "baseline-stats"
./bin/baseline-stats -drop-warmup "$DROP_WARMUP" -h-mult "$H_MULT" -k-mult "$K_MULT" --samples-csv "$CSV"
