# Start burst detector with window sampling for CUSUM fine-tunning
/usr/local/bin/burst-detector -window 50ms --sample-windows --sample-csv /tmp/ebpf-burst-detector/offline_baseline_50ms_windows.csv

# Compute CUSUM stats from baseline rate extraction
./bin/baseline-stats -drop-warmup 0 -h-mult 6 -k-mult 1 --samples-csv tmp/<csv_file_with_per_window_info>

## Cleanup bpf maps and programs after run
pkill -f burst-detector
rm -rf /sys/fs/bpf/burst-detector

# Run whole solution with attribution flow
/usr/local/bin/burst-detector -mu0 293374 -k 127714 -h-onset 766284 -h-slack-mult 6 -window 100ms --snapshot-interval 100ms -attribution-out tmp/ebpf-burst-detector/7.characterization_layer/attribution.ndjson

# Introduce load 
k6 run loadgen/k6/bursts.js -e N_BURSTS=5 -e GAP_S=5 -e BURSTY_WINDOW_SIZE_MS=500 -e TAIL_S=0 -e BASELINE_RATE=1000 -e SETTLE_S=10 -e PRE_ALLOC_VUS=300 -e MAX_VUS=350 -e BURSTY_WINDOW_RPS=2000

# Stop kind cluster
docker stop $(docker ps -aq --filter "label=io.x-k8s.kind.cluster=burst-detection-lab")

# Start kind cluster
docker start $(docker ps -aq --filter "label=io.x-k8s.kind.cluster=burst-detection-lab")

# Check from existing pods which are in hostNetwork and which have their own network namespace (own netkit devices). Cilium_health device created by cilium to test connectivity.
kubectl get pods -A \
  --field-selector spec.nodeName=burst-detection-lab-worker \
  -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,HOSTNET:.spec.hostNetwork'

# Check registerd networking endpoint at each cilium agent. 
cilium endpoint list -o json | jq '.[].status.networking'