#!/usr/bin/env bash
# Build the Privex crypto WASM module for the web target.
# Requires: rustup wasm32 target + wasm-pack on PATH.
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --target web --release
