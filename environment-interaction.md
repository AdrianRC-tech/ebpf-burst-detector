# Make hotelReservation UI accesible.
kubectl port-forward svc/frontend 5000:5000

# Make Hubble UI accesible
kubectl port-forward -n kube-system svc/hubble-ui 12000:80

# Make Jaeger UI accesible
kubectl port-forward svc/jaeger 16686:16686

# Make Grafana accessible (login: admin / admin)
kubectl port-forward -n monitoring svc/grafana 3000:80

# Make Prometheus accessible
kubectl port-forward -n monitoring svc/prometheus-server 9090:80

# Stop kind cluster
docker stop $(docker ps -aq --filter "label=io.x-k8s.kind.cluster=burst-detection-lab")

# Start kind cluster
docker start $(docker ps -aq --filter "label=io.x-k8s.kind.cluster=burst-detection-lab")

# Configure kubectl again
kubectl cluster-info --context kind-burst-detection-lab

# Check from existing pods which are in hostNetwork and which have their own network namespace (own netkit devices). Cilium_health device created by cilium to test connectivity.
kubectl get pods -A \
  --field-selector spec.nodeName=burst-detection-lab-worker \
  -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,HOSTNET:.spec.hostNetwork'

# Start ebpf programs with window sampling for CUSUM fine-tunning
/usr/local/bin/ingress-counter & /usr/local/bin/cusum-detector -window 50ms --sample-windows --sample-csv /tmp/ebpf-burst-detector/offline_baseline_50ms_windows.csv

# Start CUSUM detector with setted params
/usr/local/bin/ingress-counter & /usr/local/bin/cusum-detector -mu0 168702 -k 70371 -h-onset 422226 -h-slack-mult 6 -window 100ms

# Check registerd networking endpoint at each cilium agent. 
cilium endpoint list -o json | jq '.[].status.networking'

# Valiadte windows sum fits the per packet tracing
./bin/trace-crosscheck --trace-csv tmp/packet_trace.csv --samples-csv tmp/windows_cusum.csv

# Compute CUSUM stats from baseline rate extraction
./bin/baseline-stats -drop-warmup 0 -h-mult 6 -k-mult 1 --samples-csv tmp/<csv_file_with_per_window_info>

## Cleanup bpf maps and programs after run
pkill -f ingress-counter
pkill -f cusum-detector
rm -rf /sys/fs/bpf/burst-detector

# Introduce load configuring everything from bash instead of script.
k6 run --quiet -e TARGET=http://172.18.0.2:30500 -e BASELINE_RATE=100 -e BURSTY_WINDOW_RPS=0   -e BURSTY_WINDOW_SIZE_MS=0 -e N_BURSTS=0 -e GAP_S=0 -e SETTLE_S=180 -e TAIL_S=0   -e PRE_ALLOC_VUS=20 -e MAX_VUS=80 -e SEED=1337   loadgen/k6/mixed-workload.js 2>&1 | grep -E "requests|failed|duration|dropped|vus_max"

# Introduce load basic conf
k6 run bursts.js -e N_BURSTS=5 -e GAP_S=5 -e BURSTY_WINDOW_SIZE_MS=800 -e TAIL_S=0 -e BASELINE_RATE=100 -e SETTLE_S=10

# Run whole solution with attribution flow
usr/local/bin/ingress-counter & /usr/local/bin/cusum-detector -mu0 293374 -k 127714 -h-onset 766284 -h-slack-mult 6 -window 100ms -attribution-out tmp/ebpf-burst-detector/7.characterization_layer/attribution.ndjson