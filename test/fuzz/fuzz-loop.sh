#!/bin/bash
set -euo pipefail

readonly METADATA_SCHEMA="2"
readonly EXPECTED_TARGET_COUNT=13
readonly MAX_ARGUMENT_COUNT=64
readonly SHUTDOWN_POLLS=50
readonly SHUTDOWN_POLL_SECONDS="0.1"

declare -A TARGET_GROUP=()
declare -A TARGET_EXECUTABLE=()
declare -A TARGET_CMIN=()
declare -A TARGET_MAX_INPUT_LEN=()
declare -A SELECTED_SET=()
declare -A PID_TARGET=()
declare -a SELECTORS=()
declare -a SELECTED_TARGETS=()
declare -a WORKER_PIDS=()

STATE_DIR_RAW=""
TIMEOUT_MS=""
MEMORY_MB=""
MIN_INPUT_LEN=""
STAGING_DIR=""

usage() {
    cat <<EOF
Usage: $0 --state-dir PATH --timeout-ms N --memory-mb N \\
    --min-input-len N [all|ssz|bls|TARGET ...]

Selectors default to "all". Target names are read from the installed targets.tsv.
The state directory must be outside the canonical Git checkout.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

cleanup_staging() {
    if [[ -n "$STAGING_DIR" && -e "$STAGING_DIR" ]]; then
        rm -rf -- "$STAGING_DIR"
    fi
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

parse_arguments() {
    local selectors_started=false

    (( $# <= MAX_ARGUMENT_COUNT )) || die "too many arguments (maximum ${MAX_ARGUMENT_COUNT})"
    while (( $# > 0 )); do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --state-dir|--timeout-ms|--memory-mb|--min-input-len)
                $selectors_started && die "named arguments must precede selectors"
                (( $# >= 2 )) || die "missing value for $1"
                case "$1" in
                    --state-dir) STATE_DIR_RAW="$2" ;;
                    --timeout-ms) TIMEOUT_MS="$2" ;;
                    --memory-mb) MEMORY_MB="$2" ;;
                    --min-input-len) MIN_INPUT_LEN="$2" ;;
                esac
                shift 2
                ;;
            --*)
                die "unknown argument '$1'"
                ;;
            *)
                selectors_started=true
                SELECTORS+=("$1")
                shift
                ;;
        esac
    done

    [[ -n "$STATE_DIR_RAW" ]] || die "--state-dir is required"
    [[ -n "$TIMEOUT_MS" ]] || die "--timeout-ms is required"
    [[ -n "$MEMORY_MB" ]] || die "--memory-mb is required"
    [[ -n "$MIN_INPUT_LEN" ]] || die "--min-input-len is required"
    [[ "$STATE_DIR_RAW" != *$'\n'* && "$STATE_DIR_RAW" != *$'\t'* ]] ||
        die "--state-dir must not contain tabs or newlines"

    normalize_positive_decimal TIMEOUT_MS
    normalize_positive_decimal MEMORY_MB
    normalize_positive_decimal MIN_INPUT_LEN

    if (( ${#SELECTORS[@]} == 0 )); then
        SELECTORS=(all)
    fi
}

require_clean_checkout() {
    local phase="$1"
    local status

    status="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)"
    [[ -z "$status" ]] || die "Git checkout is not fully clean ${phase} the fuzz build"
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

build_fuzzers() {
    local build_status
    local head_after
    local status_after

    require_clean_checkout "before"
    HEAD_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"

    set +e
    (
        cd "$REPO_ROOT"
        (cd test/fuzz && zig build -Doptimize=ReleaseSafe)
    )
    build_status=$?
    set -e

    head_after="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"
    status_after="$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)"
    [[ "$head_after" == "$HEAD_COMMIT" ]] || die "HEAD changed while building fuzzers"
    [[ -z "$status_after" ]] || die "Git checkout is not fully clean after the fuzz build"
    (( build_status == 0 )) || die "fuzz build failed with status ${build_status}"
}

validate_manifest() {
    local header
    local line line_without_tabs tab_count
    local schema group target executable cmin max_input_len original_value
    local row_count=0

    [[ -f "$INSTALLED_MANIFEST" ]] || die "missing installed manifest '$INSTALLED_MANIFEST'"
    IFS= read -r header < "$INSTALLED_MANIFEST" || die "could not read installed manifest"
    [[ "$header" == $'schema\tgroup\ttarget\texecutable\tcmin\tmax_input_len' ]] ||
        die "invalid targets.tsv header"

    while IFS= read -r line || [[ -n "$line" ]]; do
        ((row_count += 1))
        (( row_count <= EXPECTED_TARGET_COUNT )) || die "targets.tsv has too many rows"
        line_without_tabs="${line//$'\t'/}"
        tab_count=$((${#line} - ${#line_without_tabs}))
        (( tab_count == 5 )) || die "invalid field count in targets.tsv row ${row_count}"
        IFS=$'\t' read -r schema group target executable cmin max_input_len <<< "$line"
        [[ "$schema" == "$METADATA_SCHEMA" ]] || die "invalid schema in targets.tsv row ${row_count}"
        [[ "$group" == "ssz" || "$group" == "bls" ]] ||
            die "invalid group in targets.tsv row ${row_count}"
        [[ "$target" =~ ^[a-z0-9_]+$ ]] || die "invalid target in targets.tsv row ${row_count}"
        [[ -n "$executable" && -n "$cmin" && -n "$max_input_len" ]] ||
            die "invalid field count in targets.tsv row ${row_count}"
        [[ "$executable" != /* && "$cmin" != /* ]] ||
            die "targets.tsv paths must be relative"
        original_value="$max_input_len"
        normalize_positive_decimal max_input_len
        [[ "$max_input_len" == "$original_value" ]] ||
            die "max input length is not canonical in targets.tsv row ${row_count}"

        [[ -z "${TARGET_GROUP[$target]+present}" ]] || die "duplicate target '$target' in targets.tsv"
        TARGET_GROUP["$target"]="$group"
        TARGET_EXECUTABLE["$target"]="$(realpath -m -- "$FUZZ_DIR/$executable")"
        TARGET_CMIN["$target"]="$(realpath -m -- "$FUZZ_DIR/$cmin")"
        TARGET_MAX_INPUT_LEN["$target"]="$max_input_len"
        [[ "${TARGET_EXECUTABLE[$target]}" == "$FUZZ_DIR/"* ]] ||
            die "executable for '$target' escapes the fuzz directory"
        [[ "${TARGET_CMIN[$target]}" == "$FUZZ_DIR/"* ]] ||
            die "cmin directory for '$target' escapes the fuzz directory"
    done < <(tail -n +2 -- "$INSTALLED_MANIFEST")

    (( row_count == EXPECTED_TARGET_COUNT )) ||
        die "targets.tsv must contain exactly ${EXPECTED_TARGET_COUNT} rows"
}

select_target() {
    local target="$1"

    if [[ -z "${SELECTED_SET[$target]+present}" ]]; then
        (( ${#SELECTED_TARGETS[@]} < EXPECTED_TARGET_COUNT )) || die "selected target bound exceeded"
        SELECTED_TARGETS+=("$target")
        SELECTED_SET["$target"]=1
    fi
}

select_group() {
    local requested_group="$1"
    local schema group target executable cmin max_input_len extra

    while IFS=$'\t' read -r schema group target executable cmin max_input_len extra; do
        if [[ "$requested_group" == "all" || "$group" == "$requested_group" ]]; then
            select_target "$target"
        fi
    done < <(tail -n +2 -- "$INSTALLED_MANIFEST")
}

resolve_selectors() {
    local selector target

    for selector in "${SELECTORS[@]}"; do
        case "$selector" in
            all|ssz|bls) select_group "$selector" ;;
            *)
                [[ -n "${TARGET_GROUP[$selector]+present}" ]] || die "unknown target '$selector'"
                select_target "$selector"
                ;;
        esac
    done
    (( ${#SELECTED_TARGETS[@]} > 0 )) || die "no targets selected"
    for target in "${SELECTED_TARGETS[@]}"; do
        decimal_le "$MIN_INPUT_LEN" "${TARGET_MAX_INPUT_LEN[$target]}" ||
            die "--min-input-len exceeds the maximum for target '$target'"
    done
}

validate_selected_artifacts() {
    local target executable cmin cmin_relative tracked untracked

    for target in "${SELECTED_TARGETS[@]}"; do
        executable="${TARGET_EXECUTABLE[$target]}"
        cmin="${TARGET_CMIN[$target]}"
        [[ -f "$executable" && -x "$executable" ]] ||
            die "selected executable '$executable' is missing or not executable"
        [[ -d "$cmin" ]] || die "selected cmin directory '$cmin' is missing"
        [[ -n "$(find "$cmin" -mindepth 1 -maxdepth 1 -type f -print -quit)" ]] ||
            die "selected cmin directory '$cmin' is empty"

        cmin_relative="${cmin#"$REPO_ROOT/"}"
        tracked="$(git -C "$REPO_ROOT" ls-files -- "$cmin_relative")"
        [[ -n "$tracked" ]] || die "selected cmin directory '$cmin' has no committed files"
        untracked="$(git -C "$REPO_ROOT" ls-files --others -- "$cmin_relative")"
        [[ -z "$untracked" ]] || die "selected cmin directory '$cmin' contains uncommitted files"
    done
}

write_value() {
    local file="$1"
    local key="$2"
    local value="$3"

    printf '%s=' "$key" >> "$file"
    printf '%q' "$value" >> "$file"
    printf '\n' >> "$file"
}

write_argv() {
    local file="$1"
    local key="$2"
    shift 2

    printf '%s=' "$key" >> "$file"
    printf ' %q' "$@" >> "$file"
    printf '\n' >> "$file"
}

write_metadata() {
    local file="$1"
    local target output_dir
    local index=0
    local -a first_argv resume_argv

    : > "$file"
    write_value "$file" "schema" "$METADATA_SCHEMA"
    write_value "$file" "head" "$HEAD_COMMIT"
    write_value "$file" "optimize" "ReleaseSafe"
    write_value "$file" "state_dir" "$STATE_DIR"
    write_value "$file" "repo_path" "$REPO_ROOT"
    write_value "$file" "manifest_sha256" "$MANIFEST_SHA256"
    write_value "$file" "policy.timeout_ms" "$TIMEOUT_MS"
    write_value "$file" "policy.memory_mb" "$MEMORY_MB"
    write_value "$file" "policy.min_input_len" "$MIN_INPUT_LEN"
    write_value "$file" "tool.zig.path" "$ZIG_PATH"
    write_value "$file" "tool.zig.version" "$ZIG_VERSION"
    write_value "$file" "tool.afl_cc.path" "$AFL_CC_PATH"
    write_value "$file" "tool.afl_cc.version" "$AFL_CC_VERSION"
    write_value "$file" "tool.afl_fuzz.path" "$AFL_FUZZ_PATH"
    write_value "$file" "tool.afl_fuzz.version" "$AFL_FUZZ_VERSION"
    write_value "$file" "build.cwd" "$FUZZ_DIR"
    write_argv "$file" "build.argv" "zig" "build" "-Doptimize=ReleaseSafe"
    write_value "$file" "selected.count" "${#SELECTED_TARGETS[@]}"

    for target in "${SELECTED_TARGETS[@]}"; do
        printf -v selected_key 'selected.%02d' "$index"
        write_value "$file" "$selected_key" "$target"
        output_dir="$STATE_DIR/output/$target"
        first_argv=(
            "$AFL_FUZZ_PATH" -i "${TARGET_CMIN[$target]}" -o "$output_dir"
            -t "$TIMEOUT_MS" -m "$MEMORY_MB" -g "$MIN_INPUT_LEN"
            -G "${TARGET_MAX_INPUT_LEN[$target]}"
            -- "${TARGET_EXECUTABLE[$target]}"
        )
        resume_argv=(
            "$AFL_FUZZ_PATH" -i - -o "$output_dir"
            -t "$TIMEOUT_MS" -m "$MEMORY_MB" -g "$MIN_INPUT_LEN"
            -G "${TARGET_MAX_INPUT_LEN[$target]}"
            -- "${TARGET_EXECUTABLE[$target]}"
        )
        write_argv "$file" "worker.first.${target}.argv" "${first_argv[@]}"
        write_argv "$file" "worker.resume.${target}.argv" "${resume_argv[@]}"
        ((index += 1))
    done
}

require_read_only_file() {
    local path="$1"
    local mode

    [[ -f "$path" && ! -L "$path" ]] || die "required state file '$path' is missing or not regular"
    mode="$(stat -c '%a' -- "$path")" || die "could not inspect '$path'"
    [[ "$mode" == "444" ]] || die "state file '$path' is not immutable"
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

prepare_state() {
    local state_existed=false
    local target stats_path

    if [[ -e "$STATE_DIR" ]]; then
        [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "existing state path must be a directory"
        state_existed=true
    fi

    mkdir -p -- "$STATE_PARENT"
    trap cleanup_staging EXIT

    if $state_existed; then
        validate_completion_marker
        require_read_only_file "$STATE_DIR/targets.tsv"
        require_read_only_file "$STATE_DIR/metadata"
        cmp -s -- "$INSTALLED_MANIFEST" "$STATE_DIR/targets.tsv" ||
            die "existing state manifest does not match the installed manifest"
        STAGING_DIR="$(mktemp -- "$STATE_PARENT/.${STATE_BASE}.metadata.XXXXXXXX")"
        write_metadata "$STAGING_DIR"
        cmp -s -- "$STAGING_DIR" "$STATE_DIR/metadata" ||
            die "existing state metadata does not match this invocation"
        for target in "${SELECTED_TARGETS[@]}"; do
            stats_path="$STATE_DIR/output/$target/default/fuzzer_stats"
            [[ -s "$stats_path" ]] || die "existing state is incomplete for target '$target'"
        done
        cleanup_staging
        STAGING_DIR=""
        RESUME=true
        return
    fi

    STAGING_DIR="$(mktemp -d -- "$STATE_PARENT/.${STATE_BASE}.staging.XXXXXXXX")"
    mkdir -p -- "$STAGING_DIR/output"
    cp -- "$INSTALLED_MANIFEST" "$STAGING_DIR/targets.tsv"
    write_metadata "$STAGING_DIR/metadata"
    printf 'complete\n' > "$STAGING_DIR/.initialized"
    chmod 0444 -- "$STAGING_DIR/targets.tsv" "$STAGING_DIR/metadata" "$STAGING_DIR/.initialized"

    mv -T -n -- "$STAGING_DIR" "$STATE_DIR"
    [[ ! -e "$STAGING_DIR" ]] || die "state path appeared during initialization"
    STAGING_DIR=""
    RESUME=false
}

terminate_workers() {
    local pid
    local poll
    local any_alive

    trap - INT TERM
    for pid in "${WORKER_PIDS[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
    done

    for ((poll = 0; poll < SHUTDOWN_POLLS; poll += 1)); do
        any_alive=false
        for pid in "${WORKER_PIDS[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then
                any_alive=true
                break
            fi
        done
        $any_alive || break
        sleep "$SHUTDOWN_POLL_SECONDS"
    done

    for pid in "${WORKER_PIDS[@]}"; do
        kill -KILL -- "-$pid" 2>/dev/null || true
    done
    for pid in "${WORKER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    WORKER_PIDS=()
}

handle_signal() {
    local signal_name="$1"
    local status="$2"

    echo "Received ${signal_name}; stopping fuzz workers" >&2
    terminate_workers
    exit "$status"
}

start_workers() {
    local target output_dir input_dir pid
    local exited_pid=""
    local child_status
    local -a argv

    trap 'handle_signal INT 130' INT
    trap 'handle_signal TERM 143' TERM

    for target in "${SELECTED_TARGETS[@]}"; do
        output_dir="$STATE_DIR/output/$target"
        if $RESUME; then
            input_dir="-"
        else
            input_dir="${TARGET_CMIN[$target]}"
        fi
        argv=(
            "$AFL_FUZZ_PATH" -i "$input_dir" -o "$output_dir"
            -t "$TIMEOUT_MS" -m "$MEMORY_MB" -g "$MIN_INPUT_LEN"
            -G "${TARGET_MAX_INPUT_LEN[$target]}"
            -- "${TARGET_EXECUTABLE[$target]}"
        )
        setsid -- "${argv[@]}" >/dev/null 2>&1 &
        pid=$!
        WORKER_PIDS+=("$pid")
        PID_TARGET["$pid"]="$target"
        echo "Started ${target} (pid ${pid})"
    done

    set +e
    wait -n -p exited_pid "${WORKER_PIDS[@]}"
    child_status=$?
    set -e
    echo "Worker ${PID_TARGET[$exited_pid]:-unknown} (pid ${exited_pid:-unknown}) exited unexpectedly with status ${child_status}" >&2
    terminate_workers
    exit 1
}

main() {
    [[ "$(uname -s)" == "Linux" ]] || die "this controller requires Linux"
    (( BASH_VERSINFO[0] >= 5 )) || die "this controller requires Bash 5 or newer"
    parse_arguments "$@"

    REPO_ROOT="$(realpath -e -- "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)")"
    FUZZ_DIR="$REPO_ROOT/test/fuzz"
    INSTALLED_MANIFEST="$FUZZ_DIR/zig-out/share/lodestar-z-fuzz/targets.tsv"
    STATE_DIR="$(realpath -m -- "$STATE_DIR_RAW")"
    case "$STATE_DIR" in
        "$REPO_ROOT"|"$REPO_ROOT"/*) die "state directory must be outside '$REPO_ROOT'" ;;
    esac
    STATE_PARENT="$(dirname -- "$STATE_DIR")"
    STATE_BASE="$(basename -- "$STATE_DIR")"
    [[ "$STATE_BASE" != "." && "$STATE_BASE" != "/" ]] || die "invalid state directory"

    ZIG_PATH="$(resolve_tool zig)"
    AFL_CC_PATH="$(resolve_tool afl-cc)"
    AFL_FUZZ_PATH="$(resolve_tool afl-fuzz)"
    ZIG_VERSION="$(capture_version "$ZIG_PATH" version)"
    AFL_CC_VERSION="$(capture_version "$AFL_CC_PATH" --version)"
    AFL_FUZZ_VERSION="$(capture_version "$AFL_FUZZ_PATH" --version)"

    build_fuzzers
    validate_manifest
    resolve_selectors
    validate_selected_artifacts
    MANIFEST_SHA256="$(sha256sum -- "$INSTALLED_MANIFEST")"
    MANIFEST_SHA256="${MANIFEST_SHA256%% *}"
    prepare_state

    echo "Targets: ${SELECTED_TARGETS[*]}"
    echo "State: $STATE_DIR"
    start_workers
}

main "$@"
