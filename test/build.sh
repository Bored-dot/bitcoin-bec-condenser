#!/usr/bin/env bash
# build.sh — izgradnja bitcoin-bec-condenser
#
# libsecp256k1 se MORA izgraditi iz izvora jer distribucijski paketi
# (libsecp256k1-dev) ne sadrže secp256k1_musig.h — MuSig2 je eksperimentalni modul.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SECP_SRC="${SECP_SRC:-$ROOT/../secp256k1}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
JOBS="${JOBS:-$(nproc)}"

echo "==> 1/5  libsecp256k1"
if [ ! -f "$SECP_PREFIX/include/secp256k1_musig.h" ]; then
  if [ ! -d "$SECP_SRC" ]; then
    echo "    kloniram secp256k1 ..."
    git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git "$SECP_SRC"
  fi
  ( cd "$SECP_SRC"
    ./autogen.sh
    ./configure --enable-module-musig --enable-experimental \
                --enable-module-extrakeys --enable-module-schnorrsig \
                --prefix="$SECP_PREFIX" >/dev/null
    make -j"$JOBS" >/dev/null
    make install >/dev/null )
  echo "    instaliran u $SECP_PREFIX"
else
  echo "    već postoji: $SECP_PREFIX"
fi

echo "==> 2/5  bec binary"
g++ -std=c++17 -O2 -Wall -Wextra \
    -I"$SECP_PREFIX/include" \
    "$ROOT/src/main.cpp" \
    -o "$ROOT/bec" \
    -L"$SECP_PREFIX/lib" -lsecp256k1
echo "    $ROOT/bec"

echo "==> 3/5  bec-bitvm binary (BitVM jezgra)"
g++ -std=c++17 -O2 -Wall -Wextra \
    -I"$SECP_PREFIX/include" \
    "$ROOT/src/bitvm_main.cpp" \
    -o "$ROOT/bec-bitvm" \
    -L"$SECP_PREFIX/lib" -lsecp256k1
echo "    $ROOT/bec-bitvm"

echo "==> 4/5  bec-matrix binary (BitVM2 matrica skriptova)"
g++ -std=c++17 -O2 -Wall -Wextra \
    -I"$SECP_PREFIX/include" \
    "$ROOT/src/matrix_main.cpp" \
    -o "$ROOT/bec-matrix" \
    -L"$SECP_PREFIX/lib" -lsecp256k1
echo "    $ROOT/bec-matrix"

echo "==> 5/5  bec-vtxo binary (VTXO settlement)"
g++ -std=c++17 -O2 -Wall -Wextra \
    -I"$SECP_PREFIX/include" \
    "$ROOT/src/vtxo_main.cpp" \
    -o "$ROOT/bec-vtxo" \
    -L"$SECP_PREFIX/lib" -lsecp256k1
echo "    $ROOT/bec-vtxo"

echo "==> gotovo"
echo
echo "Pokretanje testa na Bitcoin Core regtestu:"
echo "  BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=$SECP_PREFIX \\"
echo "      bash $ROOT/test/run_regtest.sh"
