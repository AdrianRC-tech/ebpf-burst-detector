# syntax=docker/dockerfile:1
ARG KIND_NODE_VERSION=v1.35.0
ARG BPFTOOL_VERSION=v7.7.0
ARG BPFTOP_VERSION=0.4.0

# ---- stage 1: build bpftool 7.7 from source ----
FROM ubuntu:24.04 AS bpftool-builder
ARG BPFTOOL_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential \
        clang llvm \
        libelf-dev zlib1g-dev libcap-dev libssl-dev \
        pkg-config \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --branch "${BPFTOOL_VERSION}" --depth 1 --recurse-submodules \
        https://github.com/libbpf/bpftool.git /bpftool \
 && cd /bpftool/src \
 && EXTRA_CFLAGS=--static make -j"$(nproc)" \
 && strip bpftool \
 && ./bpftool version

# ---- stage 2: the kind node, augmented ----
FROM kindest/node:${KIND_NODE_VERSION}
ARG BPFTOP_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        net-tools \
        iputils-ping \
        ca-certificates \
        curl \
 && curl -fsSL "https://github.com/Netflix/bpftop/releases/download/v${BPFTOP_VERSION}/bpftop" \
        -o /usr/local/bin/bpftop \
 && chmod +x /usr/local/bin/bpftop \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# static bpftool 7.7 — no runtime libs needed, so it just works on the node
COPY --from=bpftool-builder /bpftool/src/bpftool /usr/local/sbin/bpftool
