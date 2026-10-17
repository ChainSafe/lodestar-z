#!/bin/bash
NETWORK_TARGETS=()
declare -A NETWORK_CORPUS NETWORK_INPUT_MAX
while read -r name corpus input_max link extra; do
    if [[ ! "$name" =~ ^(network|discv5)_[a-z_]+$ || ! "$input_max" =~ ^[1-9][0-9]*$ ||
          ! "$corpus" =~ ^(initial|cmin)$ || ! "$link" =~ ^(none|snappy|quiche)$ || -n "$extra" || -n "${NETWORK_CORPUS[$name]:-}" ]]; then
        echo "Invalid or duplicate network fuzz target: $name" >&2
        return 1
    fi
    NETWORK_TARGETS+=("$name")
    NETWORK_CORPUS["$name"]="$corpus"
    NETWORK_INPUT_MAX["$name"]="$input_max"
done < "$(dirname "${BASH_SOURCE[0]}")/network-targets.tsv"
