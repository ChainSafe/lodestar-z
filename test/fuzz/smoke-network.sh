#!/bin/bash
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${FUZZ_DIR}/zig-out/bin"
CORPUS_DIR="${FUZZ_DIR}/corpus"
TARGETS=(network_reqresp network_gossip)

for target in "${TARGETS[@]}"; do
    bin="${BIN_DIR}/fuzz-${target}"
    corpus="${CORPUS_DIR}/${target}-initial"
    test -x "$bin"
    test -d "$corpus"
    found=0
    for seed in "$corpus"/*; do
        test -f "$seed" || continue
        found=1
        __AFL_DEFER_FORKSRV=1 "$bin" < "$seed" >/dev/null
    done
    test "$found" -eq 1
    rm -rf "/tmp/lodestar-z-afl-${target}"
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 afl-fuzz -i "$corpus" -o "/tmp/lodestar-z-afl-${target}" -V 3 -- "$bin" >/dev/null 2>&1
    test ! -e "/tmp/lodestar-z-afl-${target}/default/crashes/id:000000"
done
