# eBPF Burst Detector — Layer 1

This repository implements **Layer 1** of a subsecond, two-sided CUSUM burst
detector for Kubernetes microservices. Layer 1 is the measurement substrate: a
TCX-attached BPF program that counts ingress bytes per pod via the host-side
veth, plus the userspace loader that observes the resulting per-CPU counter.

**Current iteration: 1.** The data-path BPF program (`ebpf/ingress_counter.bpf.c`)
and its userspace driver (`cmd/ingress-counter/`) are in place. The CUSUM
detection program — the part that actually decides "burst onset" / "burst
drain" — is iteration 2, not yet implemented.

Architectural rationale lives in `CLAUDE.md` and `docs/superpowers/specs/`. This
README covers only how to build, run, and validate the iteration-1 binary.

---

## Requirements

| Tool | Version | Why |
|---|---|---|
| Linux kernel | **≥ 6.6** (developed on 6.17) | TCX attach API; `bpf_link` lifecycle |
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

Then the build is two commands:

```bash
go generate ./cmd/ingress-counter/
go build -o bin/ingress-counter ./cmd/ingress-counter
```

The `go generate` step invokes `bpf2go` (cached by Go's tool machinery —
rebuilt only when the tool version in `go.mod` changes) to compile
`ebpf/ingress_counter.bpf.c` and emit Go bindings at
`cmd/ingress-counter/bpf_bpfel.{go,o}`.

If `ebpf/headers/vmlinux.h` is missing, regenerate it first (see below).

---

## Run on the kind cluster

The cluster is created and Cilium is installed by `cluster-setup.sh`; the
HotelReservation workload is deployed by `deploy-hotelreservation.sh`. The
binary runs **inside one of the kind node containers**, not on the host —
kind nodes have their own netns, and that's where the pod veths live.

1. **Copy the binary into the worker node:**

   ```bash
   docker cp bin/ingress-counter burst-detection-lab-worker:/usr/local/bin/ingress-counter
   ```

2. **Pick a pod and find its host-side veth.** Cilium names host-side veths
   `lxcXXXX@ifN`, where `ifN` is the peer index inside the pod's netns.

   ```bash
   kubectl get pod -o wide                                              # pick a pod, note its node
   docker exec burst-detection-lab-worker ip link | grep lxc            # candidate veths in that node
   kubectl exec <pod> -- ip link                                        # confirm by cross-referencing the @ifN index
   ```

  The mapping visualized:

  POD NAMESPACE              HOST NAMESPACE
  ─────────────────          ─────────────────────────
  7: eth0@if13    ←peer──→  13: lxcXXXXXX@if7
     ^    ^^^                    ^^        ^^^
     │    host-side index         │        pod-side index
     pod-side index               host-side index (what you grep for)

3. **Run the binary inside the kind node:**

   ```bash
   docker exec -it burst-detection-lab-worker \
       /usr/local/bin/ingress-counter --iface lxcXXXX --interval 1s
   ```

   Flags:
   - `--iface` (required): host-side veth name as seen inside the kind node.
   - `--interval` (default `1s`): reporting cadence.
   - `--oracle` (default `true`): also read
     `/sys/class/net/<iface>/statistics/tx_bytes` each tick and report drift
     against the BPF counter.

   Output is structured JSON to stderr (one line per tick). Ctrl-C
   detaches the TCX link cleanly and exits.

---

## End-to-end with the HotelReservation workload

While `ingress-counter` runs against a pod's veth, drive traffic from the host
side and watch the byte counters move.

```bash
# Terminal 1 — port-forward the frontend service
kubectl port-forward svc/frontend 5000:5000

# Terminal 2 — generate load (curl loop, or wrk2 from DeathStarBench)
curl http://localhost:5000/
# or for sustained load:
# wrk2/wrk -D exp -t 2 -c 2 -d 30 -L -R 100 \
#     -s DeathStarBench/hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua \
#     http://localhost:5000
```

In the loader's output, `delta_bytes` should track each request and
`oracle_drift` should stay within roughly one MTU per tick.

`environment-interaction.md` lists port-forward commands for HotelReservation
UI, Hubble UI, and Jaeger if you want to observe traffic from the cluster's
own observability stack alongside the loader's readings.

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
- **TCX coexistence with Cilium.** Cilium attaches its own programs to the
  same veths via classic clsact filters; TCX runs alongside them, not over
  them. To confirm both are present after attach:
  ```bash
  docker exec burst-detection-lab-worker bpftool net show dev lxcXXXX
  ```
  You should see both Cilium's classic-TC programs and the `ingress_counter`
  TCX program listed.
- **Cluster connectivity breaks after attach.** Shouldn't happen — the
  program returns `TC_ACT_OK` unconditionally and only writes to a counter.
  If it does: detach (Ctrl-C the loader), confirm Cilium's programs survive
  via `bpftool net show`, and check that kernel version is ≥ 6.6 (TCX
  coexistence is a 6.6 feature).
- **VS Code IntelliSense can't find `bpf/bpf_helpers.h`.** Point the C/C++
  extension's `includePath` at `${workspaceFolder}/ebpf/headers` via
  `.vscode/c_cpp_properties.json`.
- **`oracle_drift` is large and growing.** The kernel updates
  `/sys/class/net/.../statistics/tx_bytes` asynchronously relative to the
  BPF read; a small steady drift is expected. Sustained large drift suggests
  the wrong veth (you're counting one pod, the oracle is reading another)
  or a stale attachment.
