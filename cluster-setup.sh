#!/bin/bash
set -e

echo "System requirements check for eBPF-based burst detection lab..."

check_tool() {
  local name=$1
  shift
  if "$@" &>/dev/null; then
    echo "  [OK] $name"
  else
    echo "  [MISSING] $name"
    MISSING=$((MISSING + 1))
  fi
}

MISSING=0
check_tool "kernel (≥5.10)" uname -r
check_tool "clang (≥12)"    clang --version
check_tool "bpftool"        bpftool version
check_tool "docker"         docker info
check_tool "kind"           kind version
check_tool "kubectl"        kubectl version --client
check_tool "helm"           helm version
check_tool "cilium CLI"     cilium version --client

if [ "$MISSING" -ne 0 ]; then
  echo "$MISSING required tool(s) missing. Aborting."
  exit 1
fi

echo "All tools are installed. Building custom kind node image with bpftool/bpftop..."

NODE_IMAGE_TAG="burst-detector-node:latest"
docker build -t "${NODE_IMAGE_TAG}" .

echo "Creating Kubernetes cluster with kind..."

kind create cluster --config=kind-config.yaml

echo "Cluster created. Installing Cilium CNI with kube-proxy replacement and Hubble observability..."
helm repo add cilium https://helm.cilium.io/
helm repo update

helm upgrade --install cilium cilium/cilium \
  --version 1.19.4 \
  --namespace kube-system \
  --values cilium-values.yaml

kubectl -n kube-system rollout status daemonset/cilium --timeout=120s
cilium status --wait


echo "Verify nodes are created and ready:"
kubectl get nodes

echo "Setting up monitoring stack (lean Prometheus + Grafana)..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana              https://grafana.github.io/helm-charts
helm repo update

kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install prometheus prometheus-community/prometheus \
  --namespace monitoring \
  --values monitoring/prometheus-values.yaml

helm upgrade --install grafana grafana/grafana \
  --namespace monitoring \
  --values monitoring/grafana-values.yaml

kubectl -n monitoring rollout status deployment/prometheus-server --timeout=120s
kubectl -n monitoring rollout status deployment/grafana          --timeout=120s

echo ""
echo "Monitoring stack ready:"
echo "  Grafana:    kubectl port-forward -n monitoring svc/grafana          3000:80  (admin / admin)"
echo "  Prometheus: kubectl port-forward -n monitoring svc/prometheus-server 9090:80"
echo ""
echo "NOTE: the bytes/sec and packets/sec dashboard panels contain a REPLACE_ME placeholder."
echo "      After port-forwarding Prometheus (9090), explore container_network_receive_bytes_total"
echo "      to find the correct interface label for your kind topology, then update"
echo "      monitoring/grafana-values.yaml (see TODO(human) in panel id:1) and re-run:"
echo "        helm upgrade --install grafana grafana/grafana -n monitoring --values monitoring/grafana-values.yaml"

