#!/usr/bin/env bash
# Step 09: build liboqs (ML-KEM only) + install liboqs-python into the venv.
# Needs git, CMake, Ninja and a C compiler (tested: MinGW-w64 gcc 15.2, Windows 11).
# Run from mlkem/:  bash scripts/build_liboqs.sh
set -euo pipefail
LIBOQS_TAG=0.16.0
LIBOQS_PY_TAG=0.16.0.1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # Project/
SRC="$ROOT/liboqs"

[ -d "$SRC" ] || git clone --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs "$SRC"
cmake -S "$SRC" -B "$SRC/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" \
  -DCMAKE_INSTALL_PREFIX="$SRC/install"
cmake --build "$SRC/build" --parallel 8 --target oqs speed_kem test_kem
cmake --install "$SRC/build"

"$ROOT/mlkem/.venv/Scripts/python" -m pip install "git+https://github.com/open-quantum-safe/liboqs-python@$LIBOQS_PY_TAG" \
  || "$ROOT/mlkem/.venv/bin/python" -m pip install "git+https://github.com/open-quantum-safe/liboqs-python@$LIBOQS_PY_TAG"
echo "liboqs installed to $SRC/install (mlkem.oqs_backend finds it automatically)"
