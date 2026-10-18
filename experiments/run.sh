#!/usr/bin/env bash
# Collect one (or --reps N) experiment run(s): detector in the kind node + k6 on the host.
# Usage: [BURSTY_WINDOW_SIZE_MS=300 ...] ./experiments/run.sh experiments/configs/w100.conf --campaign NAME [--reps N] [--score]
set -euo pipefail
cd "$(dirname "$0")/.."

NODE=${NODE:-burst-detection-lab-worker}
GRACE_S=${GRACE_S:-3}      # after k6 ends: > window + drain horizon
SETTLE_BETWEEN_S=${SETTLE_BETWEEN_S:-10}
TAIL_S=${TAIL_S:-0}        # quiescent tail after the last burst; set e.g. 300 with N_BURSTS=0 for the FPR campaign
BPF_DIR=/sys/fs/bpf/burst-detector

CONF=${1:?usage: $0 <conf> --campaign NAME [--reps N] [--score]}; shift
CAMPAIGN=""; REPS=1; SCORE=0
while [ $# -gt 0 ]; do
  case $1 in
    --campaign) CAMPAIGN=$2; shift 2 ;;
    --reps) REPS=$2; shift 2 ;;
    --score) SCORE=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$CAMPAIGN" ] || { echo "--campaign is required" >&2; exit 2; }

# Command-line env overrides win over the conf file.
OVERRIDES=""
for v in WINDOW MU0 K H_ONSET H_SLACK_MULT BASELINE_RATE BURSTY_WINDOW_RPS BURSTY_WINDOW_SIZE_MS N_BURSTS GAP_S SETTLE_S TARGET; do
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
  # Safety net: the daemon already unpins on clean exit. Separate argv execs, never `sh -c`
  # (pkill -f inside a shell whose cmdline contains the pattern would kill that shell).
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
  cleanup   # no stale daemon / pinned maps from a previous run

  {
    for v in WINDOW MU0 K H_ONSET H_SLACK_MULT BASELINE_RATE BURSTY_WINDOW_RPS BURSTY_WINDOW_SIZE_MS N_BURSTS GAP_S SETTLE_S TAIL_S TARGET; do
      echo "$v=${!v}"
    done
    echo "CAMPAIGN=$CAMPAIGN"; echo "CONFIG_ID=$CONFIG_ID"; echo "CONF=$CONF"
    echo "START_TIME=$(date -u +%FT%TZ)"
  } >"$RUN/meta.env"

  docker exec -d "$NODE" /usr/local/bin/burst-detector -window "$WINDOW" -mu0 "$MU0" -k "$K" \
    -h-onset "$H_ONSET" -h-slack-mult "$H_SLACK_MULT" \
    -snapshot-interval "$WINDOW" \
    -attribution-out "/tmp/ebpf-burst-detector/runs/$CAMPAIGN/$CONFIG_ID/$rep/attribution.ndjson"
  # Created empty at startup, so wait for existence, not content.
  for _ in $(seq 100); do [ -e "$RUN/attribution.ndjson" ] && break; sleep 0.2; done
  [ -e "$RUN/attribution.ndjson" ] || { echo "detector did not create attribution.ndjson" >&2; exit 1; }

  k6 run loadgen/k6/bursts.js \
    -e N_BURSTS="$N_BURSTS" -e GAP_S="$GAP_S" -e BURSTY_WINDOW_SIZE_MS="$BURSTY_WINDOW_SIZE_MS" \
    -e TAIL_S="$TAIL_S" -e BASELINE_RATE="$BASELINE_RATE" -e SETTLE_S="$SETTLE_S" \
    -e BURSTY_WINDOW_RPS="$BURSTY_WINDOW_RPS" -e TARGET="$TARGET" \
    ${PRE_ALLOC_VUS:+-e PRE_ALLOC_VUS="$PRE_ALLOC_VUS"} ${MAX_VUS:+-e MAX_VUS="$MAX_VUS"} \
    2>&1 | tee "$RUN/k6.log" >&2

  sleep "$GRACE_S"
  cleanup
  if [ "$SCORE" = 1 ]; then python3 experiments/analysis/score_run.py "$RUN"; fi
  echo "$RUN"
}

for i in $(seq "$REPS"); do
  one_run
  if [ "$i" -lt "$REPS" ]; then sleep "$SETTLE_BETWEEN_S"; fi
done
