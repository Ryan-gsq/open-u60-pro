FROM debian:bookworm-slim
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends iproute2 iptables nftables procps python3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
