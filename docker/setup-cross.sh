#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ge 1 ]]; then
    URL="$1"
else
    URL="${CROSS_URL:-}"
fi

if [[ -z "$URL" ]]; then
    echo "Usage: $0 <cross-toolchain-tarball-url>"
    echo "Or set CROSS_URL environment variable."
    exit 2
fi

TMPF=/tmp/cross_toolchain.tar.xz
echo "Downloading cross toolchain from $URL ..."
curl -L --fail -o "$TMPF" "$URL"

DEST=/opt/cross
rm -rf "$DEST"
mkdir -p "$DEST"
echo "Extracting to $DEST ..."
tar -xJf "$TMPF" -C "$DEST" --strip-components=1

echo "Creating symlinks for cross tools in /usr/local/bin ..."
for f in "$DEST"/bin/*; do
    bn=$(basename "$f")
    # only symlink ELF cross prefixed tools (x86_64-elf-* or similar)
    if [[ "$bn" == *x86_64* || "$bn" == x86_64-* || "$bn" == *-elf-* ]]; then
        ln -sf "$f" "/usr/local/bin/$bn"
    fi
done

echo "Wrote symlinks. To use the toolchain in the build container, run builds as root or ensure /usr/local/bin is in PATH."
echo "You can also source /work/.cross_env if created by your build wrapper."

echo "Done."


