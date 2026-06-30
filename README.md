# eBPF Burst Detector — Layer 1

This repository implements **Layer 1** of a subsecond, two-sided CUSUM burst
detector for Kubernetes microservices. Layer 1 is the measurement substrate: a
BPF program that counts ingress bytes per pod at the **pod-side peer netkit
device**, plus the userspace loader that observes the resulting per-CPU counter.

**Datapath:** Cilium netkit + BPF host-routing (no legacy mode), kernel ≥ 6.8.

**Current iteration: 2.** Both binaries are in place:

- `cmd/ingress-counter/` — data-path program that counts ingress bytes per pod
  at the netkit peer device via `AttachNetkitPeer`; the loader is an
  event-driven daemon (`RTNLGRP_LINK` netlink) that auto-discovers netkit
  devices and filters by Kubernetes namespace (iteration 1).
- `cmd/cusum-detector/` — timer-triggered two-sided CUSUM detector running
  entirely in kernel space; reads the shared per-CPU counter every window and
  emits onset/drain events to userspace via a ring buffer (iteration 2).

The two binaries share `node_ingr_bytes` automatically through the BPF
filesystem (`LIBBPF_PIN_BY_NAME` declaration + `PinPath: /sys/fs/bpf/burst-detector`
on both loaders). Start them in either order — whichever loads first creates
the pinned map; the other reuses it.

Architectural rationale lives in `CLAUDE.md` and `docs/superpowers/specs/`. This
README covers how to build, run, and validate both binaries.

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

Then build both binaries:

```bash
go generate ./cmd/ingress-counter/ ./cmd/cusum-detector/
go build -o bin/ingress-counter  ./cmd/ingress-counter
go build -o bin/cusum-detector   ./cmd/cusum-detector
```

`go generate` invokes `bpf2go` (cached by Go's tool machinery — rebuilt only
when the tool version in `go.mod` changes) to compile each BPF C source and
emit Go bindings at `cmd/*/bpf_bpfel.{go,o}`.

If `ebpf/headers/vmlinux.h` is missing, regenerate it first (see below).

---

## Run the ingress_counter on the pods of a cluster node

The cluster is created and Cilium is installed by `cluster-setup.sh`; the
HotelReservation workload is deployed by `deploy-hotelreservation.sh`. The
binary runs **inside one of the kind node containers**, not on the host —
kind nodes have their own netns, and that's where the pods and their netkit
peer devices live.

1. **Copy the binary into the worker node:**

   ```bash
   docker cp bin/ingress-counter burst-detection-lab-worker:/usr/local/bin/ingress-counter
   ```

2. **Pick a node to which we want to attach the programs.** With the Cilium netkit
   datapath, the pod's device (inside its netns) is type `netkit`. The ingress
   counter attaches a tcx-ingress BPF program to each pod's netkit peer device,
   requiring a brief `setns()` to enter the pod netns.

   ```bash                                       
   kubectl get pods -o wide   # pick a pod we want to specially monitor, note its node
   docker exec burst-detection-lab-worker ip -d link | grep -B1 netkit   # list netkit devices by type
   ```

  The mapping visualized:

  POD NAMESPACE                  HOST NAMESPACE
  ───────────────────────────    ────────────────────────────────────
  eth0 (netkit peer)    ←peer──→   lxcXXXXXX (netkit primary / host)
  └── BPF attaches here             (peer netns crossing at attach time)
      (tcx-ingress)

3. **Run the binary inside the kind node:**

   ```bash
   docker exec -it burst-detection-lab-worker \
       /usr/local/bin/ingress-counter -namespaces default
   ```

   Flags:
   - `-namespaces` (default `default`): comma-separated allow-list of
     Kubernetes namespaces to attach to. Pods placed in namespaces not provided are skipped automatically.
   - `-cilium-socket` (default `/var/run/cilium/cilium.sock`): path to the
     Cilium agent unix socket used to resolve pod namespaces.

   The daemon auto-discovers netkit peer devices via `RTNLGRP_LINK` netlink
   events and emits a structured JSON log line per attach/detach event, then
   stays silent until Ctrl-C. Ctrl-C detaches all netkit links cleanly and
   exits. Byte-per-window analysis is handled by `cusum-detector
   --sample-windows` — see [Run the CUSUM burst detector](#run-the-cusum-burst-detector-iteration-2).

### A note on non-IPv4 packets (IPv6 NDP/MLD)

With `--trace-packets` you will see occasional trace rows with an all-zero tuple and
`protocol=0`, e.g. `len=70, src_ip=0.0.0.0, dst_ip=0.0.0.0, src_port=0, dst_port=0`. These are
**non-IPv4 packets**: the data-path program only decodes IPv4 (`skb->protocol == ETH_P_IP`) and
records just the timestamp and `skb->len` for anything else (`family=0`). On this IPv4-only
Cilium cluster they are almost always **IPv6 Neighbor Discovery (NDP) / MLD link-local chatter** —
the kernel brings up an IPv6 link-local address on every interface (including each pod's netkit
peer) even though IPv6 is disabled at the CNI layer. They are *not* Kubernetes health checks
(those are IPv4 TCP and decode with a real tuple and `protocol=6`).

> **These bytes are counted on purpose.** `node_ingr_bytes` adds `skb->len` for every packet
> regardless of L3 protocol, so this IPv6 chatter is included in the CUSUM baseline. That is
> deliberate: Linux really does deliver these bytes to the pod's interface, so they are genuine
> ingress and belong in the node-wide byte signal. The volume is tiny (link-local bring-up only)
> and it does not break `trace-crosscheck` — the packets are still logged with their `len`, so
> `packet_sum` and `delta_bytes` stay balanced.

---

---

## Run the CUSUM burst detector

The detector loads alongside `ingress-counter` and shares `node_ingr_bytes`
via the pinned map at `/sys/fs/bpf/burst-detector/node_ingr_bytes`. Copy
the binary into the kind node and run it inside the same netns as
`ingress-counter`:

```bash
docker cp bin/cusum-detector burst-detection-lab-worker:/usr/local/bin/cusum-detector

docker exec -it burst-detection-lab-worker /usr/local/bin/cusum-detector \
    --mu0      500000 \
    --k        250000 \
    --h-onset  2000000 \
    --h-drain  2000000 \
    --window   10ms

# Terminal 2 — IF we want to capture per-window byte samples to finte-tune cusum values first
docker exec -it burst-detection-lab-worker \
    /usr/local/bin/cusum-detector -window 100ms -sample-windows \
    -sample-csv /tmp/windows.csv
```

Flags (all CUSUM parameters are baked into `.rodata` at load time — change
them by restarting the binary, not by editing the running program):

| Flag | Unit | Meaning |
|---|---|---|
| `--mu0` | bytes/window | baseline byte rate per CUSUM window |
| `--k` | bytes | slack factor — typically half the step you want to detect |
| `--h-onset` | bytes | threshold on `upper_sum` that triggers onset |
| `--h-drain` | bytes | threshold on `lower_sum` that triggers drain |
| `--window` | duration | CUSUM window (e.g. `10ms`, `5ms`) |
| `--sample-windows` | bool | emit per-window byte samples to CSV for parameter tuning (default off) |
| `--sample-csv` | path | destination for window sample CSV (default: stderr) |

`--sample-windows` is the **single canonical byte-per-window analysis and
tuning source for Layer 1** — it captures the exact signal the kernel CUSUM
consumes, window-aligned and at full resolution. For parameter tuning, run
with `-window 100ms -sample-windows -sample-csv /tmp/windows.csv`, drive load
with `wrk2`, then derive `mu_0`/`k`/`h_*` from the captured per-window byte
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

## Execute end-to-end load with the HotelReservation workload

While `ingress-counter` runs as a silent attach daemon, drive traffic and
capture per-window byte samples via `cusum-detector --sample-windows`.

```bash
# Terminal 1 — port-forward the frontend service
kubectl port-forward svc/frontend 5000:5000

# Terminal 2 — capture per-window byte samples
docker exec -it burst-detection-lab-worker \
    /usr/local/bin/cusum-detector -window 100ms -sample-windows \
    -sample-csv /tmp/windows.csv

# Terminal 3 — generate load (curl loop, or wrk2 from DeathStarBench)
curl http://localhost:5000/
# or for sustained load:
# wrk2/wrk -D exp -t 2 -c 2 -d 30 -L -R 100 \
#     -s DeathStarBench/hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua \
#     http://localhost:5000
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

Run a steady `wrk2` load and read off the sustained bytes/sec value for your node:

```
mu_0 [bytes/window] = bytes_per_sec / 10    # 100 ms windows = 10 windows/sec
```

Pass to `--mu0` when launching `cusum-detector`.

---

## Test

```bash
go test ./...
```

This runs the unit tests for `activeCPUs` plus the `BPF_PROG_TEST_RUN` test
for the data-path program. The BPF test **skips automatically** when run
without `CAP_BPF` — that's expected for unprivileged developer runs and CI.
To actually exercise the BPF program in isolation:

```bash
sudo go test ./cmd/ingress-counter/
```

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
  attaches alongside them at the peer device (kernel ≥ 6.8). To confirm both
  are present after attach:
  ```bash
  docker exec burst-detection-lab-worker bpftool net show dev <netkit-peer>
  ```
  You should see both Cilium's programs and `ingress_counter` listed under the
  netkit peer device.
- **Cluster connectivity breaks after attach.** Shouldn't happen — the
  program returns `TC_ACT_OK` unconditionally and only writes to a counter.
  If it does: detach (Ctrl-C the loader), confirm Cilium's programs survive
  via `bpftool net show`, and check that kernel version is ≥ 6.8 (netkit
  multi-attach requires kernel ≥ 6.8).
- **VS Code IntelliSense can't find `bpf/bpf_helpers.h`.** Point the C/C++
  extension's `includePath` at `${workspaceFolder}/ebpf/headers` via
  `.vscode/c_cpp_properties.json`.
