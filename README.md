Zux is a POSIX-compatible kernel written in C, C++ and NASM. It supports booting with GRUB (Multiboot2) and can run on BIOS and UEFI systems.

GRUB example:

```
multiboot2 /boot/zuxImg
module2 /boot/bzbx bzbx
boot
```

This repository contains build scripts and a Docker setup to produce reproducible builds on any host.

build with Docker:

```sh
# build image (first time or after Dockerfile changes)
docker build -t zux-build:latest .

# build the project (uses ccache mounted at .cache/ccache)
./docker_build.sh

# interactive container shell
docker run --rm -it -v "$(pwd)":/work -v "$(pwd)/.cache/ccache":/ccache -w /work zux-build:latest bash
# then inside container: make -j$(nproc)
```

Notes:
- image is based on Debian and includes gcc, make, nasm, binutils, xorriso and ccache.
- ccache is mounted from `.cache/ccache` to speed rebuilds.
- `.dockerignore` excludes build artifacts to speed up docker build context