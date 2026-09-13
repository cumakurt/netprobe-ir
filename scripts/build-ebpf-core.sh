#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/dist/bpf"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c "$ROOT/bpf/netprobe_runtime.bpf.c" -o "$ROOT/dist/bpf/netprobe_runtime.bpf.o"
echo "Built $ROOT/dist/bpf/netprobe_runtime.bpf.o"
