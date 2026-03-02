#!/bin/bash
# Minimize the AFL++ evolved corpus using afl-cmin.
#
# After a fuzzing run, afl-out/<target>/default/queue/ contains
# all interesting inputs AFL++ found. Many of these are redundant
# (they cover the same edges). afl-cmin deduplicates them into
# corpus/<target>-cmin/ for faster future runs.
#
# Usage:
#   ./minimize-corpus.sh              # minimize all targets
#   ./minimize-corpus.sh ssz_lists    # minimize one target

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${FUZZ_DIR}/zig-out/bin"
AFL_OUT="${FUZZ_DIR}/afl-out"
CORPUS_DIR="${FUZZ_DIR}/corpus"

targets=(ssz_basic ssz_bitlist ssz_bitvector ssz_bytelist ssz_containers ssz_lists)

# Filter to specific target if given as argument.
if [ $# -ge 1 ]; then
    targets=("$1")
fi

for target in "${targets[@]}"; do
    queue_dir="${AFL_OUT}/${target}/default/queue"
    bin="${BIN_DIR}/fuzz-${target}"
    cmin_dir="${CORPUS_DIR}/${target}-cmin"

    if [ ! -d "$queue_dir" ]; then
        echo "SKIP ${target}: no queue at ${queue_dir}"
        continue
    fi

    queue_count=$(ls -1 "$queue_dir" 2>/dev/null | wc -l)
    if [ "$queue_count" -eq 0 ]; then
        echo "SKIP ${target}: empty queue"
        continue
    fi

    if [ ! -x "$bin" ]; then
        echo "SKIP ${target}: binary not found at ${bin}"
        continue
    fi

    # Merge initial seeds + evolved queue into a temp dir.
    tmp_input=$(mktemp -d)
    trap "rm -rf $tmp_input" EXIT

    initial_dir="${CORPUS_DIR}/${target}-initial"
    if [ -d "$initial_dir" ]; then
        cp "$initial_dir"/* "$tmp_input/" 2>/dev/null || true
    fi
    cp "$queue_dir"/* "$tmp_input/" 2>/dev/null || true

    input_count=$(ls -1 "$tmp_input" | wc -l)

    # Run afl-cmin.bash (not afl-cmin) to avoid Python wrapper bugs
    # in some AFL++ versions.
    #
    # Environment variables:
    #   __AFL_DEFER_FORKSRV=1  — Tell the AFL++ runtime inside the
    #     binary to defer fork server startup until __afl_manual_init()
    #     is called in main(). Without this, the __afl_auto_init()
    #     constructor starts the fork server before main(), and then
    #     the Zig bitcode's guard init constructor fires after the
    #     fork server is up, causing a FATAL abort.
    #     Note: afl-fuzz sets this automatically when it detects the
    #     ##SIG_AFL_DEFER_FORKSRV## marker, but afl-showmap in
    #     single-file mode does not scan for it.
    #   AFL_NO_FORKSRV=1  — Tell afl-showmap to not use the fork
    #     server protocol. Each input runs as a fresh process.
    #
    # No @@ — our binary reads input from stdin, not file args.
    mkdir -p "$cmin_dir"
    echo "CMIN ${target}: ${input_count} inputs → ${cmin_dir}"
    __AFL_DEFER_FORKSRV=1 AFL_NO_FORKSRV=1 afl-cmin.bash \
        -i "$tmp_input" -o "$cmin_dir" -- "$bin" 2>/dev/null

    # Sanitize filenames: replace colons with underscores.
    # AFL++ output filenames contain colons (id:000001,...) which
    # are not valid on macOS/NTFS. This matches Ghostty's approach.
    for f in "$cmin_dir"/*; do
        bn=$(basename "$f")
        new=$(echo "$bn" | tr ':' '_')
        if [ "$bn" != "$new" ]; then
            mv "$f" "$cmin_dir/$new"
        fi
    done

    cmin_count=$(ls -1 "$cmin_dir" | wc -l)
    echo "  => ${cmin_count} unique inputs (reduced from ${input_count})"
    echo ""

    rm -rf "$tmp_input"
    trap - EXIT
done
