#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOTEL_RES_DIR="$(realpath "$SCRIPT_DIR/benchmark/hotelReservation/")"
KIND_CLUSTER="burst-detection-lab"
IMAGE="${HOTEL_IMAGE:-deathstarbench/hotel-reservation:kind-local}"

# ── Phase 1: Host load-generation prerequisites ───────────────────────────

echo "=== Phase 1: Host load-generation prerequisites ==="

if ! command -v luarocks &>/dev/null; then
  echo "Installing luarocks..."
  sudo apt-get install -y luarocks
else
  echo "  [OK] luarocks"
fi

if ! luarocks list 2>/dev/null | grep -q "^luasocket"; then
  echo "Installing luasocket..."
  sudo luarocks install luasocket
else
  echo "  [OK] luasocket"
fi

# ── Phase 3: Build and load application image into kind ───────────────────

echo "=== Phase 3: Build HotelReservation image ==="

docker build --provenance=false -t "$IMAGE" "$HOTEL_RES_DIR"

echo "Loading image into kind cluster '$KIND_CLUSTER'..."
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER"

# ── Phase 4: Deploy HotelReservation to Kubernetes ───────────────────────

echo "=== Phase 4: Deploy HotelReservation ==="

kind export kubeconfig --name "$KIND_CLUSTER"
kubectl apply -Rf "$HOTEL_RES_DIR/kubernetes/"

# K8s manifests hardcode :latest; override each deployment to use our local tag.
# Non-:latest tags default to imagePullPolicy=IfNotPresent, so kubelets use the
# kind-loaded image without contacting Docker Hub.
echo "Updating deployments to use local image $IMAGE..."
for svc in frontend geo profile rate recommendation reservation search user; do
  kubectl set image deployment/"$svc" "hotel-reserv-$svc=$IMAGE" 2>/dev/null || true
done

# OPTIONAL: Additional instructions to limit memory usage by PODs due to hitting oom in host.
# echo "Applying memory limits to bound host RAM..."
# for svc in frontend geo profile rate recommendation reservation search user; do
#   kubectl set resources deployment/"$svc" \
#     --requests=memory=64Mi --limits=memory=200Mi 2>/dev/null || true
# done
# for svc in mongodb-geo mongodb-profile mongodb-rate \
#            mongodb-recommendation mongodb-reservation mongodb-user; do
#   kubectl set resources deployment/"$svc" \
#     --requests=memory=128Mi --limits=memory=300Mi 2>/dev/null || true
# done
# for svc in memcached-profile memcached-rate memcached-reserve; do
#   kubectl set resources deployment/"$svc" \
#     --requests=memory=32Mi --limits=memory=96Mi 2>/dev/null || true
# done
# kubectl set resources deployment/consul --requests=memory=96Mi --limits=memory=256Mi 2>/dev/null || true
# kubectl set resources deployment/jaeger --requests=memory=128Mi --limits=memory=400Mi 2>/dev/null || true

echo "Waiting for all pods to be ready (timeout 5 min)..."
kubectl wait --for=condition=ready pod --all --timeout=400s

# ── Done ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Expose the frontend:"
echo "  kubectl port-forward svc/frontend 5000:5000
        OR
        curl http://<internal-ip-of-any-of-the-nodes>:30500
"
echo ""
echo "Run load test with k6: see loadgen/k6/README.md"
