# Make hotelReservation UI accesible.
kubectl port-forward svc/frontend 5000:5000

# Make Hubble UI accesible
kubectl port-forward -n kube-system svc/hubble-ui 12000:80

# Make Jaeger UI accesible
kubectl port-forward svc/jaeger 16686:16686
