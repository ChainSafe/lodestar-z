#!/bin/bash
set -euo pipefail
fuzz_dir="$(cd "$(dirname "$0")" && pwd)"
binary="${fuzz_dir}/zig-out/bin/fuzz-network_identify"
corpus="${fuzz_dir}/corpus/network_identify-initial"
test -x "$binary"
count=0
for seed in "$corpus"/*; do
    test -f "$seed"
    count=$((count + 1))
    test "$count" -le 64
    __AFL_DEFER_FORKSRV=1 "$binary" < "$seed" >/dev/null
done
test "$count" -gt 0
output="$(mktemp -d /tmp/network-identify-afl-XXXXXX)"
AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 afl-fuzz -i "$corpus" -o "$output" -V 3 -G 82021 -- "$binary" > "$output.log" 2>&1
for finding in "$output"/default/{crashes,hangs}/id:*; do
    if test -f "$finding"; then
        echo "Unexpected finding: $finding" >&2
        exit 1
    fi
done
echo "Identify: $count seeds replayed; three-second AFL smoke passed; evidence $output.log"
