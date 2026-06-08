# Make hotelReservation UI accesible.
kubectl port-forward svc/frontend 5000:5000 &

# Make Hubble UI accesible
kubectl port-forward -n kube-system svc/hubble-ui 12000:80 &

# Make Grafana accessible (login: admin / admin)
kubectl port-forward -n monitoring svc/grafana 3000:80 &

# Make Prometheus accessible
kubectl port-forward -n monitoring svc/prometheus-server 9090:80 &