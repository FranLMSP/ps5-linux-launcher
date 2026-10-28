#!/usr/bin/env bash
# Build the versioned installer ELF and standalone PC setup host.
set -euo pipefail
cd "$(dirname "$0")"
if [ "$#" -ne 0 ]; then
    echo "Usage: BUILD_TYPE=stable|dev|pre-release CUSTOM_VERSION=<suffix> ./build_release.sh" >&2
    exit 1
fi
BUILD_VERSION="$(python3 tools/gen_version.py --print)"
if [ -z "$BUILD_VERSION" ]; then
    echo "Error: Could not compute version" >&2
    exit 1
fi
export BUILD_VERSION
OUTPUT_ELF="ps5-linux-launcher-installer_v${BUILD_VERSION}.elf"
HOST_PY="ps5-linux-launcher-host_v${BUILD_VERSION}.py"
IMAGE_NAME="ps5-ps5-linux-launcher-sdk"

# Remove previous versioned release outputs before rebuilding.
rm -f ps5-linux-launcher-installer_v*.elf ps5-linux-launcher-host_v*.py

if [ -z "$(docker images -q "$IMAGE_NAME")" ]; then
    docker build -t "$IMAGE_NAME" -f third_party/ps5-webkit-remote-loader/Dockerfile.sdk third_party/ps5-webkit-remote-loader
fi
docker run --rm -u "$(id -u):$(id -g)" \
    -e BUILD_VERSION -e "BUILD_TYPE=${BUILD_TYPE:-dev}" -e "CUSTOM_VERSION=${CUSTOM_VERSION:-}" \
    -v "$(pwd)":/src -w /src "$IMAGE_NAME" make clean all
[ -f ps5-linux-launcher-installer.elf ] && cp ps5-linux-launcher-installer.elf installer.elf || true
mv installer.elf "$OUTPUT_ELF" 2>/dev/null || true
[ -f "$OUTPUT_ELF" ] || mv ps5-linux-launcher-installer.elf "$OUTPUT_ELF" 2>/dev/null || true
make host HOST_PAYLOAD="$OUTPUT_ELF"
[ -f ps5-linux-launcher-host.py ] && mv ps5-linux-launcher-host.py "$HOST_PY" || mv webkit-autoloader-host.py "$HOST_PY" 2>/dev/null || true
echo "Built $OUTPUT_ELF and $HOST_PY (Windows .exe is built by GitHub Actions)."
