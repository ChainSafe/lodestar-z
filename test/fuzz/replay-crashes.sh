#!/bin/bash
set -euo pipefail

readonly METADATA_SCHEMA="2"
readonly EXPECTED_TARGET_COUNT=13
readonly MAX_ARGUMENT_COUNT=64
readonly MAX_METADATA_BYTES=262144
readonly MAX_MANIFEST_BYTES=65536

declare -A META_RAW=()
declare -A TARGET_GROUP=()
declare -A TARGET_EXECUTABLE=()
declare -A TARGET_CMIN=()
declare -A TARGET_MAX_INPUT_LEN=()
declare -A RECORDED_SELECTED_SET=()
declare -A SELECTED_SET=()
declare -a SELECTORS=()
declare -a RECORDED_SELECTED_TARGETS=()
declare -a SELECTED_TARGETS=()

STATE_DIR_RAW=""
TIMEOUT_MS=""
TIMEOUT_DURATION=""
TOTAL_INPUTS=0
PASSED_INPUTS=0
FAILED_INPUTS=0
INFRASTRUCTURE_ERRORS=0

usage() {
    cat <<EOF
Usage: $0 --state-dir PATH --timeout-ms N [all|ssz|bls|TARGET ...]

Selectors default to "all" and may only select targets recorded in the state.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

normalize_positive_decimal() {
    local variable_name="$1"
    local -n value_ref="$variable_name"

    [[ "$value_ref" =~ ^[0-9]+$ ]] || die "${variable_name} must be a positive integer"
    [[ ! "$value_ref" =~ ^0+$ ]] || die "${variable_name} must be greater than zero"
    value_ref="${value_ref#"${value_ref%%[!0]*}"}"
}

decimal_le() {
    local left="$1"
    local right="$2"

    if (( ${#left} != ${#right} )); then
        (( ${#left} < ${#right} ))
        return
    fi
    [[ "$left" == "$right" || "$left" < "$right" ]]
}

milliseconds_to_seconds() {
    local milliseconds="$1"
    local whole_length

    case "${#milliseconds}" in
        1) printf '0.00%ss\n' "$milliseconds"; return ;;
        2) printf '0.0%ss\n' "$milliseconds"; return ;;
        3) printf '0.%ss\n' "$milliseconds"; return ;;
    esac

    whole_length=$((${#milliseconds} - 3))
    printf '%s.%ss\n' "${milliseconds:0:whole_length}" "${milliseconds:whole_length}"
}

format_argv() {
    local output_name="$1"
    shift

    printf -v "$output_name" ' %q' "$@"
}

resolve_tool() {
    local name="$1"
    local path

    path="$(command -v "$name")" || die "required tool '$name' was not found"
    path="$(realpath -e -- "$path")" || die "could not resolve '$name'"
    [[ -x "$path" ]] || die "resolved tool '$path' is not executable"
    printf '%s\n' "$path"
}

capture_version() {
    local path="$1"
    local version_argument="$2"
    local version

    version="$({ "$path" "$version_argument"; } 2>&1)" ||
        die "could not obtain the version of '$path'"
    [[ -n "$version" ]] || die "'$path $version_argument' returned no version"
    printf '%s\n' "$version"
}

parse_arguments() {
    local selectors_started=false

    (( $# <= MAX_ARGUMENT_COUNT )) || die "too many arguments (maximum ${MAX_ARGUMENT_COUNT})"
    while (( $# > 0 )); do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --state-dir|--timeout-ms)
                $selectors_started && die "named arguments must precede selectors"
                (( $# >= 2 )) || die "missing value for $1"
                case "$1" in
                    --state-dir) STATE_DIR_RAW="$2" ;;
                    --timeout-ms) TIMEOUT_MS="$2" ;;
                esac
                shift 2
                ;;
            --*) die "unknown argument '$1'" ;;
            *)
                selectors_started=true
                SELECTORS+=("$1")
                shift
                ;;
        esac
    done

    [[ -n "$STATE_DIR_RAW" ]] || die "--state-dir is required"
    [[ -n "$TIMEOUT_MS" ]] || die "--timeout-ms is required"
    [[ "$STATE_DIR_RAW" != *$'\n'* && "$STATE_DIR_RAW" != *$'\t'* ]] ||
        die "--state-dir must not contain tabs or newlines"

    normalize_positive_decimal TIMEOUT_MS
    TIMEOUT_DURATION="$(milliseconds_to_seconds "$TIMEOUT_MS")"

    if (( ${#SELECTORS[@]} == 0 )); then
        SELECTORS=(all)
    fi
}

require_read_only_file() {
    local path="$1"
    local mode

    [[ -f "$path" && ! -L "$path" ]] || die "required state file '$path' is missing or not regular"
    mode="$(stat -c '%a' -- "$path")" || die "could not inspect '$path'"
    [[ "$mode" == "444" ]] || die "state file '$path' is not immutable"
}

require_bounded_file() {
    local path="$1"
    local maximum="$2"
    local size

    size="$(stat -c '%s' -- "$path")" || die "could not inspect '$path'"
    decimal_le "$size" "$maximum" || die "state file '$path' exceeds ${maximum} bytes"
}

decode_qword() {
    local encoded="$1"
    local output_name="$2"
    local decoded=""
    local segment
    local segment_encoded
    local canonical
    local character
    local index=0

    if [[ "$encoded" == "''" ]]; then
        printf -v "$output_name" '%s' ""
        return
    fi
    [[ -n "$encoded" ]] || die "empty metadata value"

    while (( index < ${#encoded} )); do
        character="${encoded:index:1}"
        if [[ "${encoded:index:2}" == \$\' ]]; then
            segment_encoded=""
            ((index += 2))
            while true; do
                (( index < ${#encoded} )) || die "unterminated metadata quoting"
                character="${encoded:index:1}"
                if [[ "$character" == "'" ]]; then
                    ((index += 1))
                    break
                fi
                if [[ "$character" == "\\" ]]; then
                    segment_encoded+="$character"
                    ((index += 1))
                    (( index < ${#encoded} )) || die "malformed metadata quoting"
                    character="${encoded:index:1}"
                fi
                segment_encoded+="$character"
                ((index += 1))
            done
            printf -v segment '%b' "$segment_encoded"
            decoded+="$segment"
            continue
        elif [[ "$character" == "\\" ]]; then
            ((index += 1))
            (( index < ${#encoded} )) || die "malformed metadata quoting"
            decoded+="${encoded:index:1}"
        else
            decoded+="$character"
        fi
        ((index += 1))
    done

    printf -v canonical '%q' "$decoded"
    [[ "$canonical" == "$encoded" ]] || die "unsupported or malformed metadata quoting"
    printf -v "$output_name" '%s' "$decoded"
}

read_metadata() {
    local metadata="$STATE_DIR/metadata"
    local line key value

    require_read_only_file "$metadata"
    require_bounded_file "$metadata" "$MAX_METADATA_BYTES"

    while IFS= read -r line || [[ -n "$line" ]]; do
        (( ${#line} <= 65536 )) || die "metadata line is too long"
        [[ "$line" == *=* ]] || die "invalid metadata line"
        key="${line%%=*}"
        value="${line#*=}"
        [[ "$key" =~ ^[a-z0-9_.]+$ ]] || die "invalid metadata key"
        [[ -z "${META_RAW[$key]+present}" ]] || die "duplicate metadata key '$key'"
        META_RAW["$key"]="$value"
    done < "$metadata"
}

require_metadata_key() {
    local key="$1"

    [[ -n "${META_RAW[$key]+present}" ]] || die "missing metadata key '$key'"
}

decode_metadata_value() {
    local key="$1"
    local output_name="$2"

    require_metadata_key "$key"
    decode_qword "${META_RAW[$key]}" "$output_name"
}

validate_metadata() {
    local schema head optimize recorded_state repo_path canonical_repo_path build_cwd build_argv
    local expected_build_argv manifest_sha256
    local selected_count target key
    local recorded_timeout_ms recorded_memory_mb recorded_min_input_len
    local zig_path zig_version afl_cc_path afl_cc_version afl_fuzz_path afl_fuzz_version
    local original_value canonical_tool_path recorded_tool_path recorded_tool_version
    local current_head tool_name current_tool_path current_tool_version
    local index

    local required_key
    local -a required_keys=(
        schema head optimize state_dir repo_path manifest_sha256
        policy.timeout_ms policy.memory_mb policy.min_input_len
        tool.zig.path tool.zig.version tool.afl_cc.path tool.afl_cc.version
        tool.afl_fuzz.path tool.afl_fuzz.version build.cwd build.argv selected.count
    )
    local -A expected_keys=()
    for required_key in "${required_keys[@]}"; do
        require_metadata_key "$required_key"
        expected_keys["$required_key"]=1
    done

    decode_metadata_value schema schema
    [[ "$schema" == "$METADATA_SCHEMA" ]] || die "unsupported metadata schema '$schema'"
    decode_metadata_value head head
    [[ "$head" =~ ^[0-9a-f]{40}$ ]] || die "invalid recorded commit"
    decode_metadata_value optimize optimize
    [[ "$optimize" == "ReleaseSafe" ]] || die "state was not built with ReleaseSafe"
    decode_metadata_value state_dir recorded_state
    [[ "$recorded_state" == "$STATE_DIR" ]] || die "metadata state_dir does not match '$STATE_DIR'"
    decode_metadata_value repo_path repo_path
    [[ "$repo_path" == /* ]] || die "metadata repo_path is not absolute"
    canonical_repo_path="$(realpath -m -- "$repo_path")" || die "could not normalize metadata repo_path"
    [[ "$canonical_repo_path" == "$repo_path" ]] || die "metadata repo_path is not canonical"
    current_head="$(git -C "$repo_path" rev-parse --verify 'HEAD^{commit}')" ||
        die "could not resolve HEAD in recorded repository '$repo_path'"
    [[ "$current_head" == "$head" ]] || die "recorded repository HEAD does not match metadata"
    decode_metadata_value build.cwd build_cwd
    [[ "$build_cwd" == "$repo_path/test/fuzz" ]] || die "metadata build.cwd is inconsistent"
    RECORDED_FUZZ_DIR="$build_cwd"

    build_argv="${META_RAW[build.argv]}"
    format_argv expected_build_argv "zig" "build" "-Doptimize=ReleaseSafe"
    [[ "$build_argv" == "$expected_build_argv" ]] || die "metadata build.argv is inconsistent"

    decode_metadata_value manifest_sha256 manifest_sha256
    [[ "$manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || die "invalid recorded manifest hash"
    RECORDED_MANIFEST_SHA256="$manifest_sha256"

    decode_metadata_value tool.zig.path zig_path
    decode_metadata_value tool.zig.version zig_version
    decode_metadata_value tool.afl_cc.path afl_cc_path
    decode_metadata_value tool.afl_cc.version afl_cc_version
    decode_metadata_value tool.afl_fuzz.path afl_fuzz_path
    decode_metadata_value tool.afl_fuzz.version afl_fuzz_version
    for key in zig afl_cc afl_fuzz; do
        case "$key" in
            zig)
                tool_name="zig"
                recorded_tool_path="$zig_path"
                recorded_tool_version="$zig_version"
                ;;
            afl_cc)
                tool_name="afl-cc"
                recorded_tool_path="$afl_cc_path"
                recorded_tool_version="$afl_cc_version"
                ;;
            afl_fuzz)
                tool_name="afl-fuzz"
                recorded_tool_path="$afl_fuzz_path"
                recorded_tool_version="$afl_fuzz_version"
                ;;
        esac
        [[ "$recorded_tool_path" == /* ]] || die "metadata tool.${key}.path is not absolute"
        canonical_tool_path="$(realpath -m -- "$recorded_tool_path")" ||
            die "could not normalize metadata tool.${key}.path"
        [[ "$canonical_tool_path" == "$recorded_tool_path" ]] ||
            die "metadata tool.${key}.path is not canonical"
        [[ -n "$recorded_tool_version" ]] || die "metadata tool.${key}.version is empty"
        current_tool_path="$(resolve_tool "$tool_name")"
        [[ "$current_tool_path" == "$recorded_tool_path" ]] ||
            die "metadata tool.${key}.path does not match the current tool"
        if [[ "$key" == "zig" ]]; then
            current_tool_version="$(capture_version "$current_tool_path" version)"
        else
            current_tool_version="$(capture_version "$current_tool_path" --version)"
        fi
        [[ "$current_tool_version" == "$recorded_tool_version" ]] ||
            die "metadata tool.${key}.version does not match the current tool"
    done
    RECORDED_AFL_FUZZ_PATH="$afl_fuzz_path"

    decode_metadata_value policy.timeout_ms recorded_timeout_ms
    decode_metadata_value policy.memory_mb recorded_memory_mb
    decode_metadata_value policy.min_input_len recorded_min_input_len
    original_value="$recorded_timeout_ms"
    normalize_positive_decimal recorded_timeout_ms
    [[ "$recorded_timeout_ms" == "$original_value" ]] || die "recorded timeout policy is not canonical"
    original_value="$recorded_memory_mb"
    normalize_positive_decimal recorded_memory_mb
    [[ "$recorded_memory_mb" == "$original_value" ]] || die "recorded memory policy is not canonical"
    original_value="$recorded_min_input_len"
    normalize_positive_decimal recorded_min_input_len
    [[ "$recorded_min_input_len" == "$original_value" ]] || die "recorded minimum input length is not canonical"
    RECORDED_TIMEOUT_MS="$recorded_timeout_ms"
    RECORDED_MEMORY_MB="$recorded_memory_mb"
    RECORDED_MIN_INPUT_LEN="$recorded_min_input_len"

    decode_metadata_value selected.count selected_count
    original_value="$selected_count"
    normalize_positive_decimal selected_count
    [[ "$selected_count" == "$original_value" ]] || die "recorded selected target count is not canonical"
    decimal_le "$selected_count" "$EXPECTED_TARGET_COUNT" || die "recorded selected target count is too large"
    RECORDED_SELECTED_COUNT="$selected_count"

    for ((index = 0; index < selected_count; index += 1)); do
        printf -v key 'selected.%02d' "$index"
        decode_metadata_value "$key" target
        expected_keys["$key"]=1
        [[ "$target" =~ ^[a-z0-9_]+$ ]] || die "invalid recorded target '$target'"
        [[ -z "${RECORDED_SELECTED_SET[$target]+present}" ]] || die "duplicate recorded target '$target'"
        RECORDED_SELECTED_TARGETS+=("$target")
        RECORDED_SELECTED_SET["$target"]=1
        require_metadata_key "worker.first.${target}.argv"
        require_metadata_key "worker.resume.${target}.argv"
        expected_keys["worker.first.${target}.argv"]=1
        expected_keys["worker.resume.${target}.argv"]=1
    done

    for key in "${!META_RAW[@]}"; do
        [[ -n "${expected_keys[$key]+present}" ]] || die "unexpected metadata key '$key'"
    done
}

validate_completion_marker() {
    local marker="$STATE_DIR/.initialized"
    local marker_size
    local marker_value

    require_read_only_file "$marker"
    marker_size="$(stat -c '%s' -- "$marker")" || die "could not inspect '$marker'"
    [[ "$marker_size" == "9" ]] || die "invalid state completion marker"
    IFS= read -r marker_value < "$marker" || die "could not read state completion marker"
    [[ "$marker_value" == "complete" ]] || die "invalid state completion marker"
}

validate_manifest() {
    local manifest="$STATE_DIR/targets.tsv"
    local actual_hash header
    local line line_without_tabs tab_count
    local schema group target executable cmin max_input_len original_value
    local row_count=0
    local executable_path cmin_path

    require_read_only_file "$manifest"
    require_bounded_file "$manifest" "$MAX_MANIFEST_BYTES"
    actual_hash="$(sha256sum -- "$manifest")" || die "could not hash state manifest"
    actual_hash="${actual_hash%% *}"
    [[ "$actual_hash" == "$RECORDED_MANIFEST_SHA256" ]] || die "state manifest hash does not match metadata"

    exec {manifest_fd}< "$manifest" || die "could not open state manifest"
    IFS= read -r header <&"$manifest_fd" || die "could not read state manifest"
    [[ "$header" == $'schema\tgroup\ttarget\texecutable\tcmin\tmax_input_len' ]] ||
        die "invalid targets.tsv header"

    while IFS= read -r line <&"$manifest_fd" || [[ -n "$line" ]]; do
        ((row_count += 1))
        (( row_count <= EXPECTED_TARGET_COUNT )) || die "targets.tsv has too many rows"
        line_without_tabs="${line//$'\t'/}"
        tab_count=$((${#line} - ${#line_without_tabs}))
        (( tab_count == 5 )) || die "invalid field count in targets.tsv row ${row_count}"
        IFS=$'\t' read -r schema group target executable cmin max_input_len <<< "$line"
        [[ "$schema" == "$METADATA_SCHEMA" ]] || die "invalid schema in targets.tsv row ${row_count}"
        [[ "$group" == "ssz" || "$group" == "bls" ]] || die "invalid group in targets.tsv row ${row_count}"
        [[ "$target" =~ ^[a-z0-9_]+$ ]] || die "invalid target in targets.tsv row ${row_count}"
        [[ -n "$executable" && -n "$cmin" && -n "$max_input_len" ]] ||
            die "invalid field count in targets.tsv row ${row_count}"
        [[ "$executable" != /* && "$cmin" != /* ]] || die "targets.tsv paths must be relative"
        [[ -z "${TARGET_GROUP[$target]+present}" ]] || die "duplicate target '$target' in targets.tsv"
        original_value="$max_input_len"
        normalize_positive_decimal max_input_len
        [[ "$max_input_len" == "$original_value" ]] ||
            die "max input length is not canonical in targets.tsv row ${row_count}"

        executable_path="$(realpath -m -- "$RECORDED_FUZZ_DIR/$executable")" ||
            die "could not resolve executable for '$target'"
        cmin_path="$(realpath -m -- "$RECORDED_FUZZ_DIR/$cmin")" ||
            die "could not resolve cmin directory for '$target'"
        [[ "$executable_path" == "$RECORDED_FUZZ_DIR/"* ]] ||
            die "executable for '$target' escapes the recorded fuzz directory"
        [[ "$cmin_path" == "$RECORDED_FUZZ_DIR/"* ]] ||
            die "cmin directory for '$target' escapes the recorded fuzz directory"
        TARGET_GROUP["$target"]="$group"
        TARGET_EXECUTABLE["$target"]="$executable_path"
        TARGET_CMIN["$target"]="$cmin_path"
        TARGET_MAX_INPUT_LEN["$target"]="$max_input_len"
    done
    exec {manifest_fd}<&-

    (( row_count == EXPECTED_TARGET_COUNT )) ||
        die "targets.tsv must contain exactly ${EXPECTED_TARGET_COUNT} rows"
}

validate_recorded_targets_and_binaries() {
    local target binary cmin output_dir
    local expected_first_argv expected_resume_argv

    for target in "${RECORDED_SELECTED_TARGETS[@]}"; do
        [[ -n "${TARGET_GROUP[$target]+present}" ]] || die "recorded target '$target' is absent from targets.tsv"
        decimal_le "$RECORDED_MIN_INPUT_LEN" "${TARGET_MAX_INPUT_LEN[$target]}" ||
            die "recorded minimum input length exceeds the maximum for target '$target'"
        binary="${TARGET_EXECUTABLE[$target]}"
        cmin="${TARGET_CMIN[$target]}"
        output_dir="$STATE_DIR/output/$target"
        [[ -f "$binary" && -x "$binary" ]] || die "recorded binary '$binary' is missing or not executable"

        format_argv expected_first_argv \
            "$RECORDED_AFL_FUZZ_PATH" -i "$cmin" -o "$output_dir" \
            -t "$RECORDED_TIMEOUT_MS" -m "$RECORDED_MEMORY_MB" \
            -g "$RECORDED_MIN_INPUT_LEN" -G "${TARGET_MAX_INPUT_LEN[$target]}" -- "$binary"
        format_argv expected_resume_argv \
            "$RECORDED_AFL_FUZZ_PATH" -i - -o "$output_dir" \
            -t "$RECORDED_TIMEOUT_MS" -m "$RECORDED_MEMORY_MB" \
            -g "$RECORDED_MIN_INPUT_LEN" -G "${TARGET_MAX_INPUT_LEN[$target]}" -- "$binary"
        [[ "${META_RAW[worker.first.${target}.argv]}" == "$expected_first_argv" ]] ||
            die "recorded first-run worker argv is inconsistent for '$target'"
        [[ "${META_RAW[worker.resume.${target}.argv]}" == "$expected_resume_argv" ]] ||
            die "recorded resume worker argv is inconsistent for '$target'"
    done
}

select_target() {
    local target="$1"

    if [[ -z "${SELECTED_SET[$target]+present}" ]]; then
        (( ${#SELECTED_TARGETS[@]} < RECORDED_SELECTED_COUNT )) || die "selected target bound exceeded"
        SELECTED_TARGETS+=("$target")
        SELECTED_SET["$target"]=1
    fi
}

select_group() {
    local requested_group="$1"
    local target

    for target in "${RECORDED_SELECTED_TARGETS[@]}"; do
        if [[ "$requested_group" == "all" || "${TARGET_GROUP[$target]}" == "$requested_group" ]]; then
            select_target "$target"
        fi
    done
}

resolve_selectors() {
    local selector

    for selector in "${SELECTORS[@]}"; do
        case "$selector" in
            all|ssz|bls) select_group "$selector" ;;
            *)
                [[ -n "${RECORDED_SELECTED_SET[$selector]+present}" ]] ||
                    die "target '$selector' was not selected in the recorded state"
                select_target "$selector"
                ;;
        esac
    done
    (( ${#SELECTED_TARGETS[@]} > 0 )) || die "selectors matched no recorded targets"
}

record_infrastructure_error() {
    echo "ERROR $*" >&2
    ((INFRASTRUCTURE_ERRORS += 1))
}

replay_input() {
    local target="$1"
    local result_kind="$2"
    local input="$3"
    local binary="${TARGET_EXECUTABLE[$target]}"
    local size status display_name

    printf -v display_name '%q' "${input##*/}"
    ((TOTAL_INPUTS += 1))

    if [[ ! -f "$input" || -L "$input" ]]; then
        record_infrastructure_error "${target} [${result_kind}]: ${display_name} is no longer a regular file"
        ((FAILED_INPUTS += 1))
        return
    fi
    if [[ ! -r "$input" ]]; then
        record_infrastructure_error "${target} [${result_kind}]: ${display_name} is unreadable"
        ((FAILED_INPUTS += 1))
        return
    fi
    size="$(stat -c '%s' -- "$input")" || {
        record_infrastructure_error "${target} [${result_kind}]: could not inspect ${display_name}"
        ((FAILED_INPUTS += 1))
        return
    }
    if ! decimal_le "$size" "${TARGET_MAX_INPUT_LEN[$target]}"; then
        echo "OVERSIZED ${target} [${result_kind}]: ${display_name} (${size} > ${TARGET_MAX_INPUT_LEN[$target]} bytes)"
        ((FAILED_INPUTS += 1))
        return
    fi

    set +e
    __AFL_DEFER_FORKSRV=1 timeout --foreground --kill-after="$TIMEOUT_DURATION" "$TIMEOUT_DURATION" \
        "$binary" < "$input"
    status=$?
    set -e

    case "$status" in
        0)
            echo "PASS ${target} [${result_kind}]: ${display_name}"
            ((PASSED_INPUTS += 1))
            ;;
        124|137)
            echo "TIMEOUT ${target} [${result_kind}]: ${display_name} (status ${status})"
            ((FAILED_INPUTS += 1))
            ;;
        125|126|127)
            record_infrastructure_error "${target} [${result_kind}]: ${display_name} could not be replayed (status ${status})"
            ((FAILED_INPUTS += 1))
            ;;
        *)
            echo "FAIL ${target} [${result_kind}]: ${display_name} (status ${status})"
            ((FAILED_INPUTS += 1))
            ;;
    esac
}

replay_result_directory() {
    local target="$1"
    local result_kind="$2"
    local result_dir="$STATE_DIR/output/$target/default/$result_kind"
    local input

    if [[ ! -d "$result_dir" || -L "$result_dir" ]]; then
        record_infrastructure_error "${target} [${result_kind}]: missing result-input directory '$result_dir'"
        return
    fi
    if [[ ! -r "$result_dir" || ! -x "$result_dir" ]]; then
        record_infrastructure_error "${target} [${result_kind}]: result-input directory is not readable"
        return
    fi

    while IFS= read -r -d '' input; do
        replay_input "$target" "$result_kind" "$input"
    done < <(find "$result_dir" -mindepth 1 -maxdepth 1 -type f -name 'id:*' -print0)
}

main() {
    local timeout_version
    local target

    export LC_ALL=C
    [[ "$(uname -s)" == "Linux" ]] || die "this replayer requires Linux"
    (( BASH_VERSINFO[0] >= 5 )) || die "this replayer requires Bash 5 or newer"
    parse_arguments "$@"

    timeout_version="$(timeout --version 2>&1)" || die "GNU timeout was not found"
    [[ "$timeout_version" == timeout\ \(GNU\ coreutils\)* ]] || die "GNU timeout was not found"
    command -v realpath >/dev/null || die "required tool 'realpath' was not found"
    command -v sha256sum >/dev/null || die "required tool 'sha256sum' was not found"
    command -v find >/dev/null || die "required tool 'find' was not found"

    STATE_DIR="$(realpath -e -- "$STATE_DIR_RAW")" || die "state directory does not exist"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "state path must be a directory"

    validate_completion_marker
    read_metadata
    validate_metadata
    validate_manifest
    validate_recorded_targets_and_binaries
    resolve_selectors

    echo "Targets: ${SELECTED_TARGETS[*]}"
    echo "State: $STATE_DIR"
    for target in "${SELECTED_TARGETS[@]}"; do
        replay_result_directory "$target" crashes
        replay_result_directory "$target" hangs
    done

    echo "Replayed ${TOTAL_INPUTS} input(s): ${PASSED_INPUTS} passed, ${FAILED_INPUTS} failed, ${INFRASTRUCTURE_ERRORS} infrastructure error(s)."
    (( FAILED_INPUTS == 0 && INFRASTRUCTURE_ERRORS == 0 ))
}

main "$@"
