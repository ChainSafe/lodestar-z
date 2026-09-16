#!/bin/bash
NETWORK_TARGETS=()
declare -A NETWORK_CORPUS NETWORK_INPUT_MAX
while read -r name corpus input_max link; do
    [[ "$name" =~ ^(network|discv5)_[a-z_]+$ && "$input_max" =~ ^[0-9]+$ ]]
    NETWORK_TARGETS+=("$name")
    NETWORK_CORPUS["$name"]="$corpus"
    NETWORK_INPUT_MAX["$name"]="$input_max"
done < "$(dirname "${BASH_SOURCE[0]}")/network-targets.tsv"
