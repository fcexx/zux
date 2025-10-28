#!/usr/bin/env bash
set -euo pipefail

IMAGE=zux-build-cross:latest

docker build -t "$IMAGE" -f docker/Dockerfile .

mkdir -p .cache/ccache
docker run --rm -it \
  -v "$(pwd)":/work \
  -v "$(pwd)/.cache/ccache":/ccache \
  -v "$(pwd)/docker/setup-cross.sh":/setup-cross.sh \
  -w /work \
  "$IMAGE" \
  bash -lc "sudo /setup-cross.sh \"$1\" && make -j$(nproc)"

#!/usr/bin/env bash
set -euo pipefail

CROSS=/opt/cross
TARGET=x86_64-elf
JOBS=$(nproc || echo 2)
mkdir -p /tmp/src
cd /tmp/src

BINUTILS_VER=2.40
GCC_VER=13.2.0

if [ ! -f binutils-$BINUTILS_VER.tar.xz ]; then
    wget -c https://ftp.gnu.org/gnu/binutils/binutils-$BINUTILS_VER.tar.xz
fi
if [ ! -f gcc-$GCC_VER.tar.xz ]; then
    wget -c https://ftp.gnu.org/gnu/gcc/gcc-$GCC_VER/gcc-$GCC_VER.tar.xz
fi

rm -rf binutils-$BINUTILS_VER build-binutils gcc-$GCC_VER build-gcc
tar -xf binutils-$BINUTILS_VER.tar.xz
tar -xf gcc-$GCC_VER.tar.xz

# build binutils
mkdir -p build-binutils
cd build-binutils
../binutils-$BINUTILS_VER/configure --target=$TARGET --prefix=$CROSS --with-sysroot --disable-nls --disable-werror
make -j${JOBS}
make install
cd ..

# prepare gcc prerequisites
cd gcc-$GCC_VER
./contrib/download_prerequisites
cd ..

# build gcc (stage1)
mkdir -p build-gcc
cd build-gcc
../gcc-$GCC_VER/configure --target=$TARGET --prefix=$CROSS --disable-nls --enable-languages=c,c++ --without-headers --disable-shared --disable-multilib --with-newlib
make -j${JOBS} all-gcc
make -j${JOBS} all-target-libgcc
make install-gcc
make install-target-libgcc
cd /

echo "CROSS toolchain installed to $CROSS"
$CROSS/bin/$TARGET-gcc --version || true


