#!/bin/bash
# Builds the Linux node (anp-node, anp-admin, anp-ad, anp-search) in WSL or on a Linux machine, from this checkout, in ~/anp-linux.
# Needs rustc/cargo, gcc, and libclang for bindgen (set LIBCLANG_PATH to a folder holding libclang.so if the system has none).
# Couchbase Lite for Linux x86_64 comes from the couchbase-lite-rust crate's own repository (cargo fetches it with the crate).
#
#   bash scripts/linux-node-build.sh [DEST]
set -e
DEST=${1:-$HOME/anp-linux}
SRC=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$DEST"
tar -C "$SRC" -cf - Cargo.toml Cargo.lock crates testdata | tar -C "$DEST" -xf -
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:--I$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include | head -1)}"
cd "$DEST"
cargo build -p anp-node -p anp-authz -p anp-ad -p anp-search
echo "built in $DEST/target/debug; run with LD_LIBRARY_PATH=$(ls -d "$DEST"/target/debug/build/couchbase_lite-*/out | head -1)"