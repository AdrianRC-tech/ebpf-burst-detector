### Requirements

- **Linux kernel == 6.17** was used for local development. (recommended ≥ 5.15 for solid TC BPF + `BPF_MAP_TYPE_PERCPU_ARRAY` behavior).

- Installed:
    - **docker**
    - **clang**
    - **bpftool**
    - **kind**
    - **kubectl**
    - **helm**
    - **cilium CLI**

Verify with:
```bash
uname -r                       # ≥ 5.10
clang --version                # ≥ 12
bpftool version
docker info
kind version
kubectl version --client
helm version
cilium version --client