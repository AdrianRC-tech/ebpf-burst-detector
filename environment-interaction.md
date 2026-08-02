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

# Run single load benchmark
wrk2/wrk -D exp -t 3 -c 100 -d 2 -L -s benchmark/hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua http://172.18.0.2:30500 -R 100

# Check from existing pods which are in hostNetwork and which have their own network namespace (own netkit devices). Cilium_health device created by cilium to test connectivity.
kubectl get pods -A \
  --field-selector spec.nodeName=burst-detection-lab-worker \
  -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,HOSTNET:.spec.hostNetwork'

# Start ebpf programs with window sampling for CUSUM fine-tunning
/usr/local/bin/ingress-counter & /usr/local/bin/cusum-detector -window 50ms --sample-windows --sample-csv /tmp/ebpf-burst-detector/offline_baseline_50ms_windows.csv

# Check registerd networking endpoint at each cilium agent. 
cilium endpoint list -o json | jq '.[].status.networking'

# Valiadte windows sum fits the per packet tracing
./bin/trace-crosscheck --trace-csv tmp/packet_trace.csv --samples-csv tmp/windows_cusum.csv

# Compute CUSUM stats from baseline rate extraction
./bin/baseline-stats --samples-csv tmp/<csv_file_with_per_window_info>

# Burst on loop
./run-burst-load.sh <rate> <seq> <sleep>
./run-burst-load.sh 100 15 10

## Cleanup bpf maps and programs after run
pkill -f ingress-counter
pkill -f cusum-detector
rm -rf /sys/fs/bpf/burst-detector