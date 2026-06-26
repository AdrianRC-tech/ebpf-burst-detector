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

# Run load benchmark
wrk2/wrk -D exp -t 3 -c 100 -d 2 -L -s benchmark/hotelReservation/wrk2/scripts/hotel-reservation/mixed-workload_type_1.lua http://localhost:5000 -R 100

# Check fro existing pods which are in hostNetwork and which have their own network namespace (own netkit devices). Cilium_health device created by cilium to test connectivity.
kubectl get pods -A \
  --field-selector spec.nodeName=burst-detection-lab-worker \
  -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,HOSTNET:.spec.hostNetwork'

# Check registerd networking endpoint at each cilium agent. 
cilium endpoint list -o json | jq '.[].status.networking'
