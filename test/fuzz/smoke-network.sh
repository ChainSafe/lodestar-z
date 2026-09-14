#!/bin/bash
set -euo pipefail
FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${FUZZ_DIR}/network-targets.sh"
TARGETS=("${NETWORK_TARGETS[@]}")
if test "$#" -gt 0; then TARGETS=("$@"); fi
for target in "${TARGETS[@]}"; do
    test -n "${NETWORK_CORPUS[$target]:-}"
    bin="${FUZZ_DIR}/zig-out/bin/fuzz-${target}"
    corpus="${FUZZ_DIR}/corpus/${target}-${NETWORK_CORPUS[$target]}"
    test -x "$bin"
    test -d "$corpus"
    count=0
    for seed in "$corpus"/*; do
        test -f "$seed" || continue
        count=$((count + 1))
        test "$count" -le 4096
        __AFL_DEFER_FORKSRV=1 "$bin" < "$seed" >/dev/null
    done
    test "$count" -gt 0
    output="$(mktemp -d "/tmp/lodestar-z-afl-${target}-XXXXXX")"
    if ! AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 afl-fuzz -i "$corpus" -o "$output" -V 3 -G "${NETWORK_INPUT_MAX[$target]}" -- "$bin" >"$output.log" 2>&1; then
        cat "$output.log" >&2
        exit 1
    fi
    for finding in "$output"/default/{crashes,hangs}/id:*; do
        if test -f "$finding"; then
            echo "Unexpected AFL finding: $finding" >&2
            exit 1
        fi
    done
    echo "$target: $count seeds replayed; three-second AFL smoke passed; evidence $output.log"
done
