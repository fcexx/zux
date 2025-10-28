Docker build & CI for cross-compiling zux kernel

Quick start (local):

1) Build image (first time will compile cross toolchain inside image):

   docker build -t zux-cross-builder ./docker

2) Build project using the image (mount repo):

   docker run --rm -v /ABS/PATH/TO/zux:/work -w /work zux-cross-builder bash -lc "export PATH=/opt/cross/bin:\$PATH && make -j$(nproc)"

Notes:
- Building toolchain inside the image takes time. Consider building once and pushing the image to a registry.
- On Windows with Docker Desktop, use absolute Windows path (`C:/path/to/zux`) when mounting.
- CI pipeline is provided in `.github/workflows/cross-build.yml` which builds the image and runs `make`.


