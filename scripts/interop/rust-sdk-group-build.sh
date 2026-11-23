#!/bin/bash
# Build the program that drives the official ANP Rust SDK (anp 1.0.7, with its MLS feature) as a P6 group device, in an isolated
# folder: nothing is built in the project. Needs rustc/cargo, gcc (rusqlite builds SQLite from source) and the same libclang
# setup as scripts/linux-node-build.sh if the system has none.
set -e
source ~/.cargo/env 2>/dev/null || true
HERE="$(cd "$(dirname "$0")" && pwd)"
D=${ANP_RUST_GROUP_INTEROP:-$HOME/anp-interop/rust-sdk-group}
rm -rf "$D" && mkdir -p "$D"
cp -r "$HERE/rust-sdk-group/." "$D/"
cd "$D"
cargo build 2>&1 | tail -15
ls -la target/debug/anp-rust-group-interop