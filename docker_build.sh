#!/usr/bin/env bash
set -euo pipefail

# Usage: ./docker_build.sh [--rebuild] [--target <image>]
REBUILD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild) REBUILD=1; shift ;;
    *) shift ;;
  esac
done

IMAGE=zux-build:latest
DOCKERFILE_PATH="docker/Dockerfile"
if [[ "$REBUILD" -eq 1 ]]; then
  docker build -t "$IMAGE" -f "$DOCKERFILE_PATH" .
else
  docker build -t "$IMAGE" -f "$DOCKERFILE_PATH" . || true
fi

mkdir -p .cache/ccache

# If host provides x86_64-elf-* toolchain (installed via brew or package), mount binaries into container
HOST_MOUNTS=()
if command -v x86_64-elf-gcc >/dev/null 2>&1; then
  XGCC=$(command -v x86_64-elf-gcc)
  XGPP=$(command -v x86_64-elf-g++) || true
  XAS=$(command -v x86_64-elf-as) || true
  XLD=$(command -v x86_64-elf-ld) || true
  HOST_MOUNTS+=( -v "$XGCC":/usr/local/bin/x86_64-elf-gcc )
  if [[ -n "$XGPP" ]]; then HOST_MOUNTS+=( -v "$XGPP":/usr/local/bin/x86_64-elf-g++ ); fi
  if [[ -n "$XAS" ]]; then HOST_MOUNTS+=( -v "$XAS":/usr/local/bin/x86_64-elf-as ); fi
  if [[ -n "$XLD" ]]; then HOST_MOUNTS+=( -v "$XLD":/usr/local/bin/x86_64-elf-ld ); fi
  echo "Using host x86_64-elf toolchain: $XGCC"
fi

docker run --rm -it \
  -v "$(pwd)":/work \
  -v "$(pwd)/.cache/ccache":/ccache \
  -w /work \
  ${HOST_MOUNTS[@]} \
  "$IMAGE" \
  bash -lc "export CCACHE_DIR=/ccache; export PATH=/usr/lib/ccache:\$PATH; make -j$(nproc)"


