# eBPF Burst Detector

This repository implements a subsecond, two-sided CUSUM burst detector for
Kubernetes microservices, which not only detects the burst but also adds characterization to it collecting the flows/sources that most contributed to it.

**Layer 1** is the measurement substrate: a BPF program that counts ingress
bytes per pod at the **pod-side peer netkit device**, plus a timer-triggered
CUSUM detector that turns the resulting per-CPU counter into onset/drain
events. **Layer 2** adds a second BPF program on the same netkit peer device
that counts per-flow (5-tuple) bytes, and a userspace pipeline in
`burst-detector` that lists the flows that carried each detected burst, ranked
by *share of burst bytes* and labelled with Cilium service names — see
[Burst attribution (Layer 2)](#burst-attribution-layer-2) below.

**Datapath:** Cilium netkit + BPF host-routing (no legacy mode), kernel ≥ 6.8.

**Current state.** One daemon, `cmd/burst-detector/`, runs the whole of Layer 1
(and Layer 2's collection side) with a single flag set and one lifecycle. The
three BPF objects stay separate (`ebpf/ingress_counter.bpf.c`,
`ebpf/flow_stats.bpf.c`, `ebpf/cusum_detector.bpf.c`) and share their maps
through the BPF filesystem (`LIBBPF_PIN_BY_NAME` declarations +
`PinPath: /sys/fs/bpf/burst-detector`), so downstream layers can read the pinned
maps too.

- **Attach path** — attaches **two** tcx-ingress BPF programs, chained, to every
  pod's netkit peer device: `ingress_counter` (Layer 1's node-wide byte counter)
  and `flow_counter` (Layer 2's per-flow counter). The two are always loaded and
  attached together as one unit — either both attach or neither does. It is
  event-driven (`RTNLGRP_LINK` netlink), auto-discovers netkit devices, and
  filters by Kubernetes namespace.
- **Detector** — timer-triggered two-sided CUSUM running entirely in kernel
  space, reading the shared per-CPU counter every window and emitting
  onset/drain events to userspace via a ring buffer. Optionally (via
  `--attribution-out`) also polls the per-flow counter map and emits one NDJSON
  attribution record per burst.

If either half dies the daemon stops, so the detector never runs on stale maps.

---

## Requirements

| Tool | Version | Why |
|---|---|---|
| Linux kernel | **≥ 6.8** (developed on 6.17) | netkit datapath (Cilium, kernel ≥ 6.8); `bpf_link` lifecycle |
| Go | **≥ 1.24** (host has 1.26) | `tool` directive in `go.mod` |
| clang | ≥ 12 (host has 18) | BPF C compilation |
| bpftool | recent | BTF dump for `vmlinux.h` |
| docker, kind, kubectl, helm, cilium CLI | recent | local Kubernetes test cluster |
| `linux-headers-$(uname -r)` package | matching kernel | provides libbpf headers for refresh |

**BPF feature minimums** (all comfortably below the netkit floor of 6.8):

| Feature | Minimum kernel | Used by |
|---|---|---|
| tcx multi-attach (`bpf_mprog`) | 6.6 | both `ingress_counter` and `flow_counter`, chained on the same netkit peer device |
| `bpf_skb_load_bytes_relative` | 4.18 | `flow_counter`'s offset-independent header parse |
| `BPF_MAP_TYPE_LRU_PERCPU_HASH` | 4.10 | the `flow_stats` per-flow counter map |

Verify:

```bash
uname -r
go version
clang --version
bpftool version
docker info
kind version
kubectl version --client
helm version
cilium version --client
```

---

## Build

One-off setup (records `bpf2go` as a Go tool dependency in `go.mod`):

```bash
go get -tool github.com/cilium/ebpf/cmd/bpf2go
```

Then build the binary:

```bash
go generate ./cmd/burst-detector/
go build -o bin/burst-detector ./cmd/burst-detector
```

(`./build.sh` does both.)

`go generate` invokes `bpf2go` (cached by Go's tool machinery — rebuilt only
when the tool version in `go.mod` changes) to compile each BPF C source and
emit Go bindings at `cmd/burst-detector/{counter,flow,cusum}_bpfel.{go,o}` (one
prefix per BPF object so the generated identifiers don't collide).

If `ebpf/headers/vmlinux.h` is missing, regenerate it first (see below).

---

## Run the burst detector on a cluster node

The cluster is created and Cilium is installed by `cluster-setup.sh`; the
HotelReservation workload is deployed by `deploy-hotelreservation.sh`. The
binary runs **inside one of the kind node containers**, not on the host —
kind nodes have their own netns, and that's where the pods and their netkit
peer devices live.

1. **Copy the binary into the worker node:**

   ```bash
   docker cp bin/burst-detector burst-detection-lab-worker:/usr/local/bin/burst-detector
   ```

2. **Pick a node to which we want to attach the programs.** With the Cilium netkit
   datapath, the pod's device (inside its netns) is type `netkit`. The daemon
   attaches **two** chained tcx-ingress BPF programs to each pod's
   netkit peer device — `ingress_counter` then `flow_counter`, in that order —
   requiring a brief `setns()` to enter the pod netns. Both attach or neither
   does; there is no flag to run one without the other.

   ```bash                                       
   kubectl get pods -o wide   # pick a pod we want to specially monitor, note its node
   docker exec burst-detection-lab-worker ip -d link | grep -B1 netkit   # list netkit devices by type
   ```

  The mapping visualized:

  POD NAMESPACE                  HOST NAMESPACE
  ───────────────────────────    ────────────────────────────────────
  eth0 (netkit peer)    ←peer──→   lxcXXXXXX (netkit primary / host)
  └── BPF attaches here             (peer netns crossing at attach time)
      (tcx-ingress: ingress_counter -> flow_counter, chained)

3. **Run the binary inside the kind node:**

   ```bash
   docker exec -it burst-detection-lab-worker \
       /usr/local/bin/burst-detector -namespaces default -window 100ms
   ```

   Attach-side flags:
   - `-namespaces` (default `default`): comma-separated allow-list of
     Kubernetes namespaces to attach to. Pods placed in namespaces not provided are skipped automatically.
   - `-cilium-socket` (default `/var/run/cilium/cilium.sock`): path to the
     Cilium agent unix socket, used both to resolve pod namespaces and to label
     attribution flows with service names.

   The daemon auto-discovers netkit peer devices via `RTNLGRP_LINK` netlink
   events and emits a structured JSON log line per attach/detach event and per
   `burst_event`. Ctrl-C (or SIGTERM) detaches all netkit links cleanly and
   exits. The detector flags are described in
   [Run the CUSUM burst detector](#run-the-cusum-burst-detector).

### A note on non-IPv4 packets (IPv6 NDP/MLD)

The data-path counter adds `skb->len` for every packet regardless of L3
protocol, so IPv6 Neighbor Discovery / MLD link-local chatter (the kernel brings
up an IPv6 link-local address on every interface, including each pod's netkit
peer, even though IPv6 is disabled at the CNI layer) is included in the CUSUM
baseline. That is deliberate: Linux really does deliver these bytes to the pod's
interface, so they are genuine ingress. The volume is tiny (link-local bring-up
only).

---

---

## Run the CUSUM burst detector

The detector runs in the same process as the attach path and reads
`node_ingr_bytes` (also pinned at `/sys/fs/bpf/burst-detector/node_ingr_bytes`
for downstream readers). Copy the binary into the kind node and run it there:

```bash
docker cp bin/burst-detector burst-detection-lab-worker:/usr/local/bin/burst-detector

docker exec -it burst-detection-lab-worker /usr/local/bin/burst-detector \
    --namespaces default \
    --mu0      500000 \
    --k        250000 \
    --h-onset  2000000 \
    --window   10ms

# IF we want to capture per-window byte samples to fine-tune cusum values first
docker exec -it burst-detection-lab-worker \
    /usr/local/bin/burst-detector -window 100ms -sample-windows \
    -sample-csv /tmp/windows.csv
```

Flags (all CUSUM parameters are baked into `.rodata` at load time — change
them by restarting the binary, not by editing the running program):

| Flag | Unit | Meaning |
|---|---|---|
| `--mu0` | bytes/window | baseline byte rate per CUSUM window |
| `--k` | bytes | slack factor — typically half the step you want to detect |
| `--h-onset` | bytes | threshold on `upper_sum` that triggers onset |
| `--h-drain` | bytes | static override for the threshold on `lower_sum` that triggers drain (default: derived as `--h-slack-mult × k_drain`; set explicitly only to reproduce pre-derivation runs) |
| `--h-slack-mult` | dimensionless | drain threshold in slack units, `h_drain = h-slack-mult × k_drain` (default: derived from `h_onset / k`, the onset arm's own operating point) |
| `--window` | duration | CUSUM window (e.g. `10ms`, `5ms`) |
| `--sample-windows` | bool | emit per-window byte samples to CSV for parameter tuning (default off) |
| `--sample-csv` | path | destination for window sample CSV (default: stderr) |

`--sample-windows` is the **single canonical byte-per-window analysis and
tuning source for Layer 1** — it captures the exact signal the kernel CUSUM
consumes, window-aligned and at full resolution. For parameter tuning, run
with `-window 100ms -sample-windows -sample-csv /tmp/windows.csv`, drive load
with k6 (`loadgen/k6`), then derive `mu_0`/`k`/`h_*` from the captured per-window byte
deltas.

Output is structured JSON to stderr, one line per arming event plus one line
per onset/drain transition. The detector also exposes a single-byte `burst_flag`
BPF map (0 = quiescent, 1 = burst) as Layer 1's architectural output for
downstream consumers.

**Start order is irrelevant.** Whichever process loads first creates the pinned
`node_ingr_bytes` map at `/sys/fs/bpf/burst-detector/`; the other reuses it.

**To reset all shared state** (e.g. for a fresh CUSUM tuning run with no
historical counter accumulation):

```bash
sudo rm -rf /sys/fs/bpf/burst-detector
```

This unpins the shared map. Both binaries must be stopped first.

---

## Burst attribution (Layer 2)

Layer 1 says *a burst happened*; attribution says *who carried it*. It lists
the **flows** (5-tuples) that moved the most bytes between the onset change
point and drain, each with its **share of the burst's bytes** and the Cilium
service identity of both endpoints. It deliberately does **not** compute
excess over a per-flow baseline: under connection pooling (e.g. memcached)
5-tuples are ephemeral and swap load, so a flow's own recent past is not a
meaningful reference (see `docs/design-decisions-layer1-to-layer2-interface.md`
§5). The trade-off: it answers "who carried the burst", not "which service
changed most".

Attribution needs nothing extra attached — `flow_counter` is already running
alongside `ingress_counter` on every pod (see above). It's off by default in
`burst-detector`; turn it on with `--attribution-out`:

```bash
docker exec -it burst-detection-lab-worker /usr/local/bin/burst-detector \
    --mu0 500000 --k 250000 --h-onset 2000000 --window 100ms \
    --attribution-out /tmp/attribution.ndjson
```

One NDJSON line is appended to that file per burst, at drain time. Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--attribution-out` | *(empty — disabled)* | path to the NDJSON output file; attribution only runs when this is set |
| `--cilium-socket` | `/var/run/cilium/cilium.sock` | Cilium agent API socket used to label flows with service names; must be visible in the node container (this is the same flag the attach path uses). If unreachable, records omit `src_service`/`dst_service` |
| `--ring-retention` | `3s` | how far back the in-memory flow-snapshot ring keeps history; must span onset change point → drain, so a longer burst gets `truncated: true` |
| `--snapshot-interval` | the effective `--window` (floored at 50ms) | how often the flow counter map is polled into the ring |
| `--top-n` | `25` | max flows listed per record (`flows`/`total_bytes` are never capped, only the list) |

A shorter `--window` (e.g. the 5–25ms windows used in `tmp/6.layer_1_validations`)
does **not** shrink `--snapshot-interval` below the 50ms floor — the ring's
memory is `depth × distinct flows`, and `depth = ring-retention / interval`, so
an unfloored interval at a 5ms window would put the ring in the hundreds of MB
per node. Deltas use each snapshot's actual counters, never the
nominal interval, so the floor costs temporal resolution in the ring, not
correctness. Pass `--snapshot-interval` explicitly if you need finer than 50ms.

### Reading a record

```json
{
  "onset_change_point_utc": "12:03:45.100000000",
  "drain_change_point_utc": "12:03:46.800000000",
  "total_bytes": 820000, "flows": 4,
  "truncated": false, "unpaired": false, "evicted_flows": 0,
  "parse_anomaly_delta": 0, "lru_saturated_delta": 0,
  "contributors": [
    {"src": "10.0.1.42:41234", "dst": "10.0.2.9:11211", "proto": "tcp",
     "src_service": "default/search", "dst_service": "default/memcached-rate",
     "bytes": 600000, "skbs": 410, "bytes_per_skb": 1463.4},
    {"src": "10.0.1.7:50112", "dst": "10.0.2.9:11211", "proto": "tcp",
     "src_service": "default/frontend", "dst_service": "default/memcached-rate",
     "bytes": 220000, "skbs": 180, "bytes_per_skb": 1222.2}
  ]
}
```

- **`contributors`** has one entry per flow, ranked by `bytes` descending
  (ties: skbs, then src, dst), capped at `--top-n`. A flow's share of the burst is
  `bytes / total_bytes`; the listed bytes sum to less than `total_bytes` when
  the cap hides flows.
- **`src_service` / `dst_service`** are `<namespace>/<workload>` (workload from
  `app.kubernetes.io/name`, `app`, `io.kompose.service` or `k8s-app`), or a
  reserved name (`host`, `remote-node`, `world`, `kube-apiserver`, ...), taken
  from the Cilium agent's ipcache (`/v1/ip`) joined with `/v1/identity`, so
  remote pods resolve too. Cached ~10s; only the listed flows are looked up.
- **`truncated: true`** means the onset's change point was older than the
  ring's oldest retained slot — the record still uses the oldest slot it has
  rather than being dropped, but treat its numbers as a lower bound.
- **`unpaired: true`** means a burst did not drain within `--ring-retention` (measured from the onset change point, i.e. before its onset slot leaves the ring);
  the record is a partial, best-effort snapshot, not a complete burst window.
- **`lru_saturated_delta`** reads 0 under ordinary connection churn even if
  the 8192-entry flow table is thrashing — an LRU map evicts rather than
  fails on insert. `evicted_flows` (count of flows present at onset but gone
  by drain) is the more useful churn signal; treat a nonzero
  `lru_saturated_delta` as a sign of deeper trouble (e.g. per-CPU free-list
  exhaustion), not the absence of one as "no thrashing".
- Sources are **raw IPs** in this iteration — naming them (pod/workload) is a
  later increment (spec §6, not yet built); see `CLAUDE.md`'s Phase 2 note.

---

## Execute end-to-end load with the HotelReservation workload

While `burst-detector` runs, drive traffic and capture per-window byte samples
via `--sample-windows`.

```bash
# Terminal 1 — port-forward the frontend service
kubectl port-forward svc/frontend 5000:5000

# Terminal 2 — run the daemon capturing per-window byte samples
docker exec -it burst-detection-lab-worker \
    /usr/local/bin/burst-detector -window 100ms -sample-windows \
    -sample-csv /tmp/windows.csv

# Terminal 3 — generate load (curl, or k6 scripts under loadgen/k6 for sustained load)
curl http://localhost:5000/
```

Watch `delta_bytes` rows accumulate in `/tmp/windows.csv` — that CSV is the
canonical byte-per-window signal for deriving `mu_0`/`k`/`h_*`.

`environment-interaction.md` lists port-forward commands for HotelReservation
UI, Hubble UI, and Jaeger if you want to observe traffic from the cluster's
own observability stack alongside the loader's readings.


## Monitoring (Prometheus + Grafana)

`cluster-setup.sh` deploys a lean monitoring stack in the `monitoring` namespace:

- **Prometheus** (`prometheus-community/prometheus`) — built-in jobs scrape the kubelet `/metrics/cadvisor` endpoint (per-pod ingress bytes/packets aggregated to node level in PromQL) and the Hubble `hubble-metrics` service (port 9965, dropped-packet counts). No operator, no ServiceMonitor CRDs.
- **Grafana** — pre-loads the *CUSUM Layer 1 Tuning* dashboard with three panels.

### Access

```bash
kubectl port-forward -n monitoring svc/grafana          3000:80   # admin / admin
kubectl port-forward -n monitoring svc/prometheus-server 9090:80
```

Open http://localhost:3000 → Dashboards → default → *CUSUM Layer 1 Tuning*.

### Dashboard panels

| Panel | Purpose |
|---|---|
| Node bytes/sec | Primary CUSUM tuning signal; read `mu_0` from the steady-state value |
| Node packets/sec | Directional context (GRO-coalesced — not wire-exact) |
| Cilium drop bytes/sec | **Must stay ~0** during load runs; BPF map counter (lossless) — non-zero = lossy measurement |

> **How pod churn is handled automatically:** cAdvisor's `interface` label is the in-pod name (`eth0`), identical for every pod — pod identity lives in the `pod`/`namespace` labels. The panels use `namespace="default", pod!="", interface="eth0"` which matches every app pod that exists now or appears later, with no per-pod configuration. New pods are picked up automatically by Prometheus service discovery; deleted pods go stale. `namespace="default"` also excludes host-network system pods (cilium-agent, apiserver…) that would otherwise double-count traffic against the eBPF measurement.

### Resolution ceiling

cAdvisor housekeeping runs every ~10 s — **~100× coarser than the 100 ms CUSUM window**. These panels characterise the load-generator *envelope* and steady-state baseline. Actual per-window validation comes from the ring-buffer → offline CSV path.

### Deriving `mu_0`

Run a steady k6 load (`loadgen/k6/staircase.js`) and read off the sustained bytes/sec value for your node:

```
mu_0 [bytes/window] = bytes_per_sec / 10    # 100 ms windows = 10 windows/sec
```

Pass to `--mu0` when launching `burst-detector`.

---

## Test

```bash
go test ./...
```

This runs all pure-Go unit tests across every package (loader helpers, the
flow-snapshot ring, attribution scoring, the CUSUM event-pairing state
machine, CSV/NDJSON decoding) plus the
`BPF_PROG_TEST_RUN` tests for both data-path programs. The BPF tests **skip
automatically** when run without `CAP_BPF` — that's expected for
unprivileged developer runs and CI. To actually exercise both BPF programs
in isolation:

```bash
sudo go test ./cmd/burst-detector/ -v
```

This covers `ingress_counter` (TCX chaining, byte counting) and
`flow_counter` (per-flow parsing, the map-insert race, the non-first-fragment
and IPv6-parse-anomaly cases) — the privileged `BPF_PROG_TEST_RUN` tests. Each loads a
**fresh, unpinned** copy of the BPF object (`LoadAndAssign` with every map's
`Pinning` cleared) so tests never depend on run order or a prior pinned
state at `/sys/fs/bpf/burst-detector`.

---

## Regenerate `vmlinux.h`

`vmlinux.h` is dumped from the running kernel's BTF and is gitignored. Run
once on a fresh checkout, and again after any kernel upgrade:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h
```

---

## Refresh vendored libbpf headers

The headers under `ebpf/headers/bpf/` (`bpf_helpers.h`, `bpf_helper_defs.h`,
`bpf_endian.h`, `bpf_core_read.h`, `bpf_tracing.h`) are vendored from the
kernel's `linux-headers` package and committed to the repo. This avoids
depending on a separately-installed `libbpf-dev` and ties helper signatures
to the kernel we'll actually load into.

Refresh procedure when bumping the host kernel:

```bash
cp /usr/src/linux-headers-$(uname -r)/tools/bpf/resolve_btfids/libbpf/include/bpf/{bpf_helpers.h,bpf_helper_defs.h,bpf_endian.h,bpf_core_read.h,bpf_tracing.h} ebpf/headers/bpf/
go test ./...      # smoke-check that compilation and the BPF test still pass
git diff           # review the header diff before committing
```

---

## Troubleshooting

- **"failed to set memlock rlimit: operation not permitted"** — the loader
  needs `CAP_BPF` (or run as root). Inside a kind node container the default
  user has it; on the host, `sudo` the binary.
- **netkit multi-attach (`bpf_mprog`) coexistence with Cilium.** Cilium
  manages BPF programs on netkit devices via `bpf_mprog`; `ingress_counter`
  and `flow_counter` attach alongside them at the peer device (kernel ≥ 6.8).
  To confirm all three are present after attach:
  ```bash
  docker exec burst-detection-lab-worker bpftool net show dev <netkit-peer>
  ```
  You should see Cilium's programs, `ingress_counter`, *and* `flow_counter`
  listed under the netkit peer device, in that chain order.
- **Confirming the two-program chain is actually running** (not just
  attached). Both `ingress_counter` and `flow_counter` must show the same
  `run_cnt` in `bpftop` — if `flow_counter`'s `run_cnt` is 0 or lags
  `ingress_counter`'s, the chain is broken (most likely `ingress_counter`
  returning a terminal verdict instead of `TCX_NEXT`, which would silently
  stop the chain before `flow_counter` ever runs):
  ```bash
  docker exec -it burst-detection-lab-worker bpftop
  ```
- **Cluster connectivity breaks after attach.** Shouldn't happen — both
  programs return `TCX_NEXT` unconditionally (letting the chain continue to
  whatever Cilium itself has attached) and only write to counters. If it
  does: detach (Ctrl-C the loader), confirm Cilium's programs survive via
  `bpftool net show`, and check that kernel version is ≥ 6.8 (netkit
  multi-attach requires kernel ≥ 6.8).
- **VS Code IntelliSense can't find `bpf/bpf_helpers.h`.** Point the C/C++
  extension's `includePath` at `${workspaceFolder}/ebpf/headers` via
  `.vscode/c_cpp_properties.json`.
