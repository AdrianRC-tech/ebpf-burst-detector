#!/bin/bash

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

echo "All tools are installed. Creating Kubernetes cluster with kind..."

kind create cluster --config=kind-config.yaml

echo "Cluster created. Installing Cilium CNI with kube-proxy replacement and Hubble observability..."
helm repo add cilium https://helm.cilium.io/
helm repo update

helm install cilium cilium/cilium \
  --version 1.19.4 \
  --namespace kube-system \
  --values cilium-values.yaml

kubectl -n kube-system rollout status daemonset/cilium --timeout=120s
cilium status --wait


echo "Verify nodes are created and ready:"
kubectl get nodes

