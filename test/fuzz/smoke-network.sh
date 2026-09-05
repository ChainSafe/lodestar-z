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
    log="/tmp/lodestar-z-afl-${target}.log"
    if ! AFL_SKIP_CPUFREQ=1 afl-fuzz -i "$corpus" -o "/tmp/lodestar-z-afl-${target}" -V 3 -- "$bin" >"$log" 2>&1; then
        cat "$log" >&2
        exit 1
    fi
    for finding in /tmp/lodestar-z-afl-${target}/default/{crashes,hangs}/id:*; do
        if test -f "$finding"; then
            echo "Unexpected AFL finding: $finding" >&2
            exit 1
        fi
    done
    echo "$target: seeds replayed; three-second AFL smoke passed"
done
