#!/bin/bash
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${FUZZ_DIR}/zig-out/bin"
CORPUS_DIR="${FUZZ_DIR}/corpus"
AFL_OUT="${FUZZ_DIR}/afl-out"
LOGS_DIR="${FUZZ_DIR}/logs"

TARGETS=(bls_public_key bls_signature bls_aggregate_pk bls_aggregate_sig)

# Duration per round in seconds. Override with: ROUND_DURATION=7200 ./fuzz-loop.sh
ROUND_DURATION=${ROUND_DURATION:-3600}

mkdir -p "$LOGS_DIR"

run_round() {
    local round=$1
    echo "[Round ${round}] Fuzzing all targets for ${ROUND_DURATION}s..."

    local pids=()
    for target in "${TARGETS[@]}"; do
        local input_dir="${CORPUS_DIR}/${target}-cmin"
        if [ ! -d "$input_dir" ] || [ -z "$(ls -A "$input_dir" 2>/dev/null)" ]; then
            input_dir="${CORPUS_DIR}/${target}-initial"
        fi

        local output_dir="${AFL_OUT}/${target}/round-${round}"
        mkdir -p "$output_dir"

        afl-fuzz \
            -i "$input_dir" \
            -o "$output_dir" \
            -V "$ROUND_DURATION" \
            -- "${BIN_DIR}/fuzz-${target}" \
            >> "${LOGS_DIR}/${target}.log" 2>&1 &

        pids+=($!)
        echo "  fuzz-${target} started (pid $!)"
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    echo "[Round ${round}] Fuzzing done."
}

run_cmin() {
    local round=$1
    echo "[Round ${round}] Minimizing corpus..."

    for target in "${TARGETS[@]}"; do
        local queue_dir="${AFL_OUT}/${target}/round-${round}/default/queue"
        local cmin_tmp="${CORPUS_DIR}/${target}-cmin-tmp"
        local cmin_final="${CORPUS_DIR}/${target}-cmin"

        if [ ! -d "$queue_dir" ] || [ -z "$(ls -A "$queue_dir" 2>/dev/null)" ]; then
            echo "  ${target}: no queue, skipping"
            continue
        fi

        afl-cmin \
            -i "$queue_dir" \
            -o "$cmin_tmp" \
            -T all \
            -- "${BIN_DIR}/fuzz-${target}"

        rm -rf "$cmin_final"
        mv "$cmin_tmp" "$cmin_final"
        echo "  ${target}: $(ls "$cmin_final" | wc -l) files"
    done
}

check_crashes() {
    local round=$1
    local found=0
    for target in "${TARGETS[@]}"; do
        local crash_dir="${AFL_OUT}/${target}/round-${round}/default/crashes"
        if [ -d "$crash_dir" ] && compgen -G "${crash_dir}/id:*" > /dev/null 2>&1; then
            local count
            count=$(ls "${crash_dir}"/id:* 2>/dev/null | wc -l)
            echo "  CRASH ${target}: ${count} crash(es) in ${crash_dir}"
            found=$((found + count))
        fi
    done
    if [ "$found" -gt 0 ]; then
        echo "[Round ${round}] WARNING: ${found} total crash(es) found. Run ./replay-crashes.sh to inspect."
    fi
}

round=0
while true; do
    round=$((round + 1))
    echo "========================================"
    echo "Starting round ${round} at $(date)"
    echo "========================================"

    run_round "$round"
    check_crashes "$round"
    run_cmin "$round"

    echo "[Round ${round}] Done at $(date)"
done
