#!/bin/bash
# The cold-stock rescue with an on-device model advising the store's agent, on Linux or in WSL: builds the node with LiteRT (and the
# admin tool, the search agent and xtask) from this checkout in ~/anp-linux, then runs `xtask e2e-model` with the model you give.
#
#   bash scripts/linux-model.sh MODEL.litertlm [DEST]
#
# Needs rustc/cargo, gcc and libclang (set LIBCLANG_PATH to a folder holding libclang.so if the system has none: the `libclang` wheel from
# PyPI has one). LiteRT-LM's runtime is downloaded by the litert-lm-sys crate into ~/.cache/litert-lm-sys. Models: any LiteRT-LM chat model
# that speaks ChatML; Qwen2.5-1.5B-Instruct answered in about 50 s on two CPU cores in WSL.
set -e
MODEL=${1:?give a .litertlm model}
DEST=${2:-$HOME/anp-linux}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$DEST"
tar -C "$SRC" -cf - Cargo.toml Cargo.lock common a2a/crates anp/crates anp/testdata anp/xtask .cargo | tar -C "$DEST" -xf -
export BINDGEN_EXTRA_CLANG_ARGS="${BINDGEN_EXTRA_CLANG_ARGS:--I$(ls -d /usr/lib/gcc/x86_64-linux-gnu/*/include | head -1)}"
cd "$DEST"
cargo build -p anp-node --features litert -p anp-authz -p anp-search -p xtask
CBL=$(ls -td target/debug/build/couchbase_lite-*/out | head -1)
LITERT=$(ls -d "$HOME"/.cache/litert-lm-sys/*/x86_64-unknown-linux-gnu | head -1)
export LD_LIBRARY_PATH="$PWD/$CBL:$LITERT:$LD_LIBRARY_PATH"
./target/debug/xtask e2e-model --model "$MODEL"
