#!/bin/bash
# Starts fuzz-loop.sh detached from the terminal and keeps its output in logs/overnight.log.
# Usage: ./overnight.sh [target[=instances]...]
# Default: the five stateful network harnesses, one instance each, with a 1 s run timeout.
set -euo pipefail
FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGETS=("$@")
if [ "${#TARGETS[@]}" -eq 0 ]; then
    TARGETS=(network_gossip_sessions network_gossip_recovery network_processor_admission network_reqresp_session network_quic_session)
fi
export TIMEOUT_MS="${TIMEOUT_MS:-1000}"
mkdir -p "${FUZZ_DIR}/logs"
cd "${FUZZ_DIR}"
echo "overnight start $(date) targets=${TARGETS[*]} TIMEOUT_MS=${TIMEOUT_MS}" >> logs/overnight.log
setsid nohup ./fuzz-loop.sh "${TARGETS[@]}" >> logs/overnight.log 2>&1 < /dev/null &
sleep 2
tail -n "$((${#TARGETS[@]} * 4 + 2))" logs/overnight.log
echo "Status: ./fuzz-loop.sh --status ${TARGETS[*]%%=*}"
