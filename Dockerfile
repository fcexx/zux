# Minimal build container for zux kernel
# Provides reproducible environment and ccache to speed up builds
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV CCACHE_DIR=/ccache
ENV PATH=/usr/lib/ccache:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget curl git build-essential gcc g++ make nasm binutils \
    xorriso ccache python3 pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m builder || true
RUN mkdir -p /work /ccache && chown builder:builder /work /ccache

WORKDIR /work
USER builder

CMD ["/bin/bash"]


