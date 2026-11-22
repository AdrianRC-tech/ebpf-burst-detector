#!/usr/bin/env bash
# Collect per-window node ingress bytes under k6 load, for offline replay of CUSUM / other SPC detectors.
# Same load knobs and layout as run.sh, but no attribution: each rep stores windows.csv + k6.log + meta.env.
# Usage: [BURSTY_WINDOW_SIZE_MS=300 ...] ./experiments/run_windows_sampling.sh experiments/configs/w100.conf --campaign NAME [--reps N]
set -euo pipefail
cd "$(dirname "$0")/.."

NODE=${NODE:-burst-detection-lab-worker}
GRACE_S=${GRACE_S:-3}
SETTLE_BETWEEN_S=${SETTLE_BETWEEN_S:-10}
TAIL_S=${TAIL_S:-0}
BPF_DIR=/sys/fs/bpf/burst-detector

CONF=${1:?usage: $0 <conf> --campaign NAME [--reps N]}; shift
CAMPAIGN=""; REPS=1
while [ $# -gt 0 ]; do
  case $1 in
    --campaign) CAMPAIGN=$2; shift 2 ;;
    --reps) REPS=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$CAMPAIGN" ] || { echo "--campaign is required" >&2; exit 2; }

# Command-line env overrides win over the conf file.
OVERRIDES=""
for v in WINDOW BASELINE_RATE BURSTY_WINDOW_RPS BURSTY_WINDOW_SIZE_MS N_BURSTS GAP_S SETTLE_S TARGET; do
  if [ -n "${!v+x}" ]; then OVERRIDES+="$v=${!v}"$'\n'; fi
done
# shellcheck disable=SC1090
source "$CONF"
while IFS='=' read -r k v; do [ -n "$k" ] && printf -v "$k" %s "$v"; done <<<"$OVERRIDES"

WINDOW_MS=${WINDOW%ms}
PEAK=$((BASELINE_RATE + BURSTY_WINDOW_RPS))
CONFIG_ID="w${WINDOW_MS}_bl${BASELINE_RATE}_p${PEAK}_b${BURSTY_WINDOW_SIZE_MS}"
CONFIG_DIR=tmp/runs/$CAMPAIGN/$CONFIG_ID

nx() { docker exec "$NODE" "$@"; }

cleanup() {
  # Same pattern as run.sh: separate argv execs, never `sh -c` with pkill -f.
  # SIGTERM also makes the detector flush windows.csv.
  if nx pgrep -f /burst-detector >/dev/null 2>&1; then
    nx pkill -f /burst-detector >/dev/null 2>&1 || true
    for _ in $(seq 50); do nx pgrep -f /burst-detector >/dev/null 2>&1 || break; sleep 0.2; done
    nx pkill -KILL -f /burst-detector >/dev/null 2>&1 || true
  fi
  nx rm -rf "$BPF_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

one_run() {
  local n=1
  while [ -e "$CONFIG_DIR/$(printf rep%02d "$n")" ]; do n=$((n + 1)); done
  local rep; rep=$(printf rep%02d "$n")
  RUN=$CONFIG_DIR/$rep
  mkdir -p "$RUN"
  cleanup

  {
    for v in WINDOW BASELINE_RATE BURSTY_WINDOW_RPS BURSTY_WINDOW_SIZE_MS N_BURSTS GAP_S SETTLE_S TAIL_S TARGET; do
      echo "$v=${!v}"
    done
    echo "CAMPAIGN=$CAMPAIGN"; echo "CONFIG_ID=$CONFIG_ID"; echo "CONF=$CONF"
    echo "START_TIME=$(date -u +%FT%TZ)"
  } >"$RUN/meta.env"

  # Load first, detector second (same as run.sh): otherwise the first windows are k6 startup, i.e. zero bytes.
  ( k6 run loadgen/k6/bursts.js \
    -e N_BURSTS="$N_BURSTS" -e GAP_S="$GAP_S" -e BURSTY_WINDOW_SIZE_MS="$BURSTY_WINDOW_SIZE_MS" \
    -e TAIL_S="$TAIL_S" -e BASELINE_RATE="$BASELINE_RATE" -e SETTLE_S="$SETTLE_S" \
    -e BURSTY_WINDOW_RPS="$BURSTY_WINDOW_RPS" -e TARGET="$TARGET" \
    ${PRE_ALLOC_VUS:+-e PRE_ALLOC_VUS="$PRE_ALLOC_VUS"} ${MAX_VUS:+-e MAX_VUS="$MAX_VUS"} \
    2>&1 | tee "$RUN/k6.log" >&2 ) &
  local k6_pid=$!
  # scenario_start is logged on the first iteration, i.e. once traffic is actually flowing.
  for _ in $(seq 200); do grep -q scenario_start "$RUN/k6.log" 2>/dev/null && break; sleep 0.05; done
  grep -q scenario_start "$RUN/k6.log" || { echo "k6 did not start" >&2; kill "$k6_pid"; exit 1; }

  # ponytail: CUSUM params left at C defaults; its decisions are irrelevant here, only the samples are kept.
  docker exec -d "$NODE" /usr/local/bin/burst-detector -window "$WINDOW" \
    -sample-windows -sample-csv "/tmp/ebpf-burst-detector/runs/$CAMPAIGN/$CONFIG_ID/$rep/windows.csv"
  # Created empty at startup, so wait for existence, not content.
  for _ in $(seq 100); do [ -e "$RUN/windows.csv" ] && break; sleep 0.05; done
  [ -e "$RUN/windows.csv" ] || { echo "detector did not create windows.csv" >&2; kill "$k6_pid"; exit 1; }
  echo "DETECTOR_ARMED_UTC=$(date -u +%FT%T.%NZ)" >>"$RUN/meta.env"

  wait "$k6_pid"

  sleep "$GRACE_S"
  cleanup
  echo "$RUN"
}

for i in $(seq "$REPS"); do
  one_run
  if [ "$i" -lt "$REPS" ]; then sleep "$SETTLE_BETWEEN_S"; fi
done
