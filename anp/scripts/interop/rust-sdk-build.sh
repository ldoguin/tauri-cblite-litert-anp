#!/bin/bash
# Build the program that drives the official ANP Rust SDK (anp 1.0.7) in an isolated folder: nothing is built in the project.
set -e
source ~/.cargo/env 2>/dev/null || true
HERE="$(cd "$(dirname "$0")" && pwd)"
D=${ANP_RUST_INTEROP:-$HOME/anp-interop/rust-sdk}
rm -rf "$D" && mkdir -p "$D"
cp -r "$HERE/rust-sdk/." "$D/"
cd "$D"
cargo +stable build 2>&1 | tail -15
ls -la target/debug/anp-rust-interop