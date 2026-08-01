#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LUA_SCRIPT="$SCRIPT_DIR/benchmark/hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua"
WRK="$SCRIPT_DIR/wrk2/wrk"

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <rate> <seq> <sleep>" >&2
  echo "  rate  requests/sec (-R) per burst" >&2
  echo "  seq   number of bursts to fire" >&2
  echo "  sleep seconds to wait between bursts" >&2
  exit 1
fi

RATE="$1"
SEQ="$2"
SLEEP="$3"

human_ts() {
  local ns="$1" secs nanos
  secs="${ns:0:-9}"
  nanos="${ns: -9}"
  printf '%s.%s' "$(date -d "@$secs" +%H:%M:%S)" "$nanos"
}

for i in $(seq "$SEQ"); do
  ts_start="$(date +%s%N)"
  echo " --> i=$i"
  echo " --> burst_start $(human_ts "$ts_start")  <-- "
  echo ""
  "$WRK" -D exp -t 4 -c 20 -d 1 -s "$LUA_SCRIPT" http://172.18.0.2:30500 -R "$RATE"
  ts_end="$(date +%s%N)" # -L (latency analysis flag) out to reduce output noise, but we still want to know when the burst ended
  echo ""
  echo " --> burst_end   i=$i $(human_ts "$ts_end") <-- "
  echo ""

  if [ "$i" -lt "$SEQ" ]; then
    sleep "$SLEEP"
  fi
done


# If using kubectl port-forwarding replace dest_ip with http://localhost:5000