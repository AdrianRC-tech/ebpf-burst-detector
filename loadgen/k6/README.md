# k6 load generator

Generates the HotelReservation mixed workload with **subsecond bursty windows**, which `wrk2` cannot do
(wrk2 has second granularity, and forking a fresh `wrk` per burst costs ~15 ms before the first byte
reaches a pod due to cold start of connections, meanwhile k6 offers VUs pre-allocation).

The wrk2 harness (`run-load.sh`, `run-burst-load.sh`) is untouched and still works.

## Files

- `workload-lib.js` — shared code: the seeded HotelReservation request mix (RNG, endpoint
  weights) and the summary-reporting helpers. No stage-shape logic; imported by every scenario
  script below:
  - `bursts.js` — repeated-burst stage shape. Covers scenarios **A** (baseline only, `N_BURSTS=0`),
    **B**/**C** (bursts spaced `GAP_S` apart, abrupt edges), and **E** (`RAMP_MS>0`, gradual
    onset/drain instead of abrupt).
  - `staircase.js` — scenario **D**: an abrupt up/down staircase from below-baseline to the
    burst-size rate and back.

For executing each scenario, only the tunables
passed via `-e` to `bursts.js` or `staircase.js` need to be set properly.

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

Run a scenario directly with `k6 run <file>.js -e VAR=value ...`. You should never need to edit
the JS — every tunable is exposed as an env var (defaults live in the `envNum(...)` calls at the
top of each script).

```bash
# Scenario A — baseline only, 30 min, for false-positive rate
k6 run bursts.js -e N_BURSTS=0 -e SETTLE_S=1800 -e TAIL_S=0 -e BASELINE_RATE=100

# Scenario B — bursts well spaced (5s gap)
k6 run bursts.js -e GAP_S=5 -e BURSTY_WINDOW_SIZE_MS=500 -e BASELINE_RATE=100


# Scenario C — bursts tightly spaced (1s gap), tests re-arm after a detection
k6 run bursts.js -e GAP_S=1 -e BURSTY_WINDOW_SIZE_MS=500 -e BASELINE_RATE=100

# Scenario D — staircase: 50->100->150->200->150->100->50 rps, 500ms per step
k6 run staircase.js -e STEP_MS=500

# Scenario E — same burst shape as B, but a 7s ramp on onset/drain instead of abrupt edges
k6 run bursts.js -e GAP_S=5 -e BURSTY_WINDOW_SIZE_MS=500 -e RAMP_MS=7000
```

### `bursts.js` tunables (scenarios A/B/C/E)

| Tunable | Default | Meaning |
|---|---|---|
| `TARGET` | `http://172.18.0.2:30500` | frontend NodePort on the kind bridge |
| `BASELINE_RATE` | 100 | steady-state rps |
| `BURSTY_WINDOW_RPS` | 100 | **additive** rps during a window; peak = baseline + this |
| `BURSTY_WINDOW_SIZE_MS` | 800 | window duration (hold-at-peak; excludes ramp) |
| `RAMP_MS` | 0 | onset/drain transition duration; `0` = abrupt (A/B/C), `>0` = gradual (E) |
| `N_BURSTS` | 10 | windows per run; 0 = baseline only (A) |
| `GAP_S` | 10 | baseline seconds between windows — 5 for B, 1 for C |
| `SETTLE_S` | 100 | baseline lead-in; excluded from analysis |
| `TAIL_S` | 30 | baseline after the last window |
| `PRE_ALLOC_VUS` / `MAX_VUS` | 20 / 80 | VU pool |
| `BURST_MIX` | unset | request mix of the burst's *added* traffic: `search,recommend,user,reserve` fractions, exactly 4 comma-separated values summing to 1 (e.g. `0.1,0.1,0.4,0.4`). Baseline keeps the default 0.6,0.39,0.005,0.005 mix, so during a burst the stream is a blend; unset = no change |
| `SEED` | 1337 | PRNG seed; same seed reproduces the same request stream |

### `staircase.js` tunables (scenario D)

The staircase shape itself — `[50, 100, 150, 200, 150, 100, 50]` rps — is a hardcoded `LEVELS`
array in the script, not env-tunable; `STEP_MS` is the only axis meant to vary per run. The
settle/gap hold rate and `startRate` derive from `LEVELS[0]`, so they move with it if you edit
the array.

| Tunable | Default | Meaning |
|---|---|---|
| `TARGET` | `http://172.18.0.2:30500` | frontend NodePort on the kind bridge |
| `STEP_MS` | 500 | hold duration per step; transitions are abrupt (0s) |
| `N_CYCLES` | 1 | how many up/down staircases to run, separated by `GAP_S` |
| `GAP_S` / `SETTLE_S` / `TAIL_S` / `PRE_ALLOC_VUS` / `MAX_VUS` / `SEED` | same as `bursts.js` | |

## Output

`setup()` prints the burst plan up front, in epoch-ns and `HH:MM:SS.nnnnnnnnn` UTC to match the detector's
`time_utc` column. This replaces the `burst_start` / `burst_end` lines `run-burst-load.sh` printed.

The end-of-run summary reports per-bursty-window request counts:

```
  burst   requests   expected
  000          159        160
  004          121        160
  across 10 bursts: mean 156.2  sd 12.4  cv 7.9%  min 121  max 162
```

Compare `requests` against `expected` per window. This matters: under wrk2, two of ten bursts
silently delivered 85 requests instead of 115, and those two were exactly the detection misses. If
a CUSUM onset is missing, check this table before blaming the detector.

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
| `-s script.lua` | `bursts.js` / `staircase.js` |
| N processes in a bash loop | N bursty windows in one stage list, one process |
