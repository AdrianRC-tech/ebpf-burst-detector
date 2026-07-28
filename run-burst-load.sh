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

for i in $(seq "$SEQ"); do
  echo "burst_start i=$i $(date +%s%N)"
  "$WRK" -D exp -t 3 -c 100 -d 1 -L -s "$LUA_SCRIPT" http://172.18.0.2:30500 -R "$RATE"
  echo "burst_end   i=$i $(date +%s%N)"

  if [ "$i" -lt "$SEQ" ]; then
    sleep "$SLEEP"
  fi
done


# If using kubectl port-forwarding replace dest_ip with http://localhost:5000