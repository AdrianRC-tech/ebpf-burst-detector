ARG KIND_NODE_VERSION=v1.35.0
FROM kindest/node:${KIND_NODE_VERSION}

ARG BPFTOP_VERSION=0.4.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bpftool \
        net-tools \
        ca-certificates \
        curl \
 && curl -fsSL "https://github.com/Netflix/bpftop/releases/download/v${BPFTOP_VERSION}/bpftop" \
        -o /usr/local/bin/bpftop \
 && chmod +x /usr/local/bin/bpftop \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
