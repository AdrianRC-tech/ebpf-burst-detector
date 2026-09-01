# k6 load generator

Generates the HotelReservation mixed workload with **subsecond bursty windows**, which `wrk2` cannot do
(wrk2 has second granularity, and forking a fresh `wrk` per burst costs ~15 ms before the first byte
reaches a pod).

The wrk2 harness (`run-load.sh`, `run-burst-load.sh`) is untouched and still works.

## Install

Follow instrusction at https://grafana.com/docs/k6/latest/set-up/install-k6/.

### Debian

```bash
curl -fsSL https://dl.k6.io/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/k6-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6
```

Validated against **k6 v2.2.0**.

**Do not run k6 in Docker for these experiments.** The extra NAT hop and the container's own network
stack sit between the loader and the kind bridge, smearing exactly the burst edges this exists to sharpen.

## Usage

```bash
./run-k6-load.sh [baseline_rate] [bursty_window_rps] [bursty_window_size_ms] [n_bursts] [target]
```

```bash
./run-k6-load.sh                          # defaults: 100 rps + 100 rps for 800ms, x10
./run-k6-load.sh 100 100 800 3            # quick smoke test, 3 bursty windows
./run-k6-load.sh 100 0 0 0                # baseline only, no bursts
./run-k6-load.sh 100 100 400 10           # 400 ms windows (see detectability note below)
```

Edit the tunables at the top of `run-k6-load.sh`; they are passed to `mixed-workload.js` as `-e` flags.
You should never need to edit the JS.

| Tunable | Default | Meaning |
|---|---|---|
| `TARGET` | `http://172.18.0.2:30500` | frontend NodePort on the kind bridge |
| `BASELINE_RATE` | 100 | steady-state rps |
| `BURSTY_WINDOW_RPS` | 100 | **additive** rps during a window; peak = baseline + this |
| `BURSTY_WINDOW_SIZE_MS` | 800 | window duration |
| `N_BURSTS` | 10 | windows per run; 0 = baseline only |
| `GAP_S` | 10 | baseline seconds between windows |
| `SETTLE_S` | 100 | baseline lead-in; excluded from analysis |
| `TAIL_S` | 30 | baseline after the last window |
| `PRE_ALLOC_VUS` / `MAX_VUS` | 20 / 80 | VU pool |
| `SEED` | 1337 | PRNG seed; same seed reproduces the same request stream |

**Never run this and the wrk2 scripts at the same time** — offered rates add, so the app sees a load
neither harness reports.

The generator does not police the rate you ask for; checking that the cluster can absorb it is on you.
Watch `failed` in the summary. HotelReservation's services trip gRPC `too_many_pings` GOAWAY under
enough concurrency, and the resulting connection churn produces byte-rate artifacts that resemble the
bursts you are trying to detect — a contaminated run that still looks plausible. It was seen around
250 rps under wrk2 with 100 connections; k6 needs only ~3 VUs at those rates, so the real threshold
here is different and unmeasured.

## Output

`setup()` prints the burst plan up front, in epoch-ns and `HH:MM:SS.nnnnnnnnn` UTC to match the detector's
`time_utc` column. This replaces the `burst_start` / `burst_end` lines `run-burst-load.sh` printed.

The end-of-run summary reports per-bursty-window request counts:

```
  burst   requests   expected   delta
  000          159        160    -0.6%
  004          121        160   -24.4%  !!
  across 10 bursts: mean 156.2  sd 12.4  cv 7.9%  min 121  max 162
```

`!!` marks windows more than 5% off expected. This matters: under wrk2, two of ten bursts silently
delivered 85 requests instead of 115, and those two were exactly the detection misses. If a CUSUM onset
is missing, check this table before blaming the detector.

Three numbers in the summary are acceptance gates:

- `dropped_iterations` should be `0`. It is emitted by the executor rather than VU code, so it cannot
  carry the phase tag — if it is non-zero, re-run with `--out csv` to find which window.
- `vus_max` should equal `PRE_ALLOC_VUS` (20). A higher value means k6 allocated VUs *mid-run*, which
  k6's own docs warn "can overload the load generator and skew results" — and it would happen exactly at
  a bursty-window edge. Measured occupancy is ~3 VUs at 200 rps, so this needs sustained ~100 ms
  latency to trigger.
- `connecting max` should stay well under a millisecond. Connection setup is the mechanism behind the
  ~200 ms harness intercept the wrk2 loop suffered; a small max means VUs reused warm connections
  across windows rather than handshaking at each burst edge.

## Detectability

At +100 rps over a 100 rps baseline (M = 2.0), replays against the `tmp/4.measure_changepoint/` captures
give recall by window size and duration:

| Window size | W=50 ms | W=100 ms | W=200 ms |
|---|---|---|---|
| 800 ms | 99% | 98% | 95% |
| 600 ms | 93% | 92% | 79% |
| 400 ms | 82% | 66% | 38% |
| 200 ms | 34% | 14% | 3% |

Shorter windows need more amplitude, not a different harness — the generator delivers whatever you ask
for. Once `BURSTY_WINDOW_RPS` reaches what the cluster can absorb, the remaining lever is bytes per
request (endpoint mix), not requests per second.

## Mapping from wrk2

| wrk2 | k6 |
|---|---|
| `-t 4 -c 20` | `preAllocatedVUs: 20`, `maxVUs: 80` (VU concurrency = open connections) |
| `-R <rate>` | `startRate` and stage `target` |
| `-d <seconds>` | stage `duration` — accepts `800ms` |
| `-D exp` | not needed; arrival-rate executors are open-model and immune to coordinated omission |
| `-s script.lua` | `mixed-workload.js` |
| N processes in a bash loop | N bursty windows in one stage list, one process |
