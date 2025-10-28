FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget curl git build-essential gcc g++ make nasm binutils xorriso ccache python3 \
    && rm -rf /var/lib/apt/lists/*

# Install prebuilt cross toolchain (x86_64-elf) from xpack to provide
# x86_64-elf-as, x86_64-elf-ld, x86_64-elf-gcc, etc. This speeds up builds
# and avoids requiring host toolchain packages.
ENV XPACK_GCC_URL="https://github.com/xpack-dev-tools/xpack-gcc-x86_64-elf/releases/download/v10.3.0-1/xpack-gcc-x86_64-elf-10.3.0-1.x86_64-linux.tar.gz"
RUN set -eux; \
    mkdir -p /opt/cross; \
    if curl -fsSL "$XPACK_GCC_URL" -o /tmp/xpack.tar.gz; then \
        tar -xzf /tmp/xpack.tar.gz -C /opt/cross --strip-components=1; \
        rm /tmp/xpack.tar.gz; \
        chown -R root:root /opt/cross; \
    else \
        echo "xpack download failed, falling back to host tool wrappers"; \
        mkdir -p /opt/cross/bin; \
        ln -sf /usr/bin/gcc /opt/cross/bin/x86_64-elf-gcc; \
        ln -sf /usr/bin/g++ /opt/cross/bin/x86_64-elf-g++; \
        ln -sf /usr/bin/as /opt/cross/bin/x86_64-elf-as; \
        ln -sf /usr/bin/ld /opt/cross/bin/x86_64-elf-ld; \
        ln -sf /usr/bin/ar /opt/cross/bin/x86_64-elf-ar; \
    fi

ENV PATH="/opt/cross/bin:${PATH}"

RUN useradd -m builder || true
RUN mkdir -p /work /ccache /opt/cross && chown builder:builder /work /ccache /opt/cross

WORKDIR /work
USER builder

CMD ["/bin/bash"]
