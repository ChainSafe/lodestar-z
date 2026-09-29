#!/usr/bin/env bash
# Usage: scripts/zig-cross.sh COMMAND [ARGS...]
#
# Runs COMMAND, typically `pnpm zapi build-artifacts`, with Cargo building every zapi target through Zig and from
# quiche's own lockfile. quiche-zig builds quiche and its BoringSSL with Cargo for the Zig target, which needs a C and
# C++ compiler, an archiver and a linker for that target, and it lets Cargo resolve dependencies anew. Each Rust target
# must be installed with `rustup target add`.
set -euo pipefail

if [ "${1-}" = --driver ]; then
  mode=$2
  target=$3
  shift 3
  for arg; do
    shift
    case "$arg" in
      # Zig's `-target` names the target and its minimum OS version.
      --target=* | -mmacosx-version-min=*) continue ;;
      # Only the discarded cdylib that quiche also builds asks for these, and Zig's Mach-O linker accepts neither:
      # it ships no libiconv, and it parses only three-part versions.
      -liconv) continue ;;
      -Wl,*-compatibility_version,*) arg=$(printf '%s' "$arg" | sed -E 's/(-compatibility_version,[0-9]+)$/\1.0.0/') ;;
    esac
    set -- "$@" "$arg"
  done
  exec zig "$mode" -target "$target" "$@"
fi

self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
cargo=$(command -v cargo)
tools=$(mktemp -d "${TMPDIR:-/tmp}/zig-cross.XXXXXX")
trap 'rm -rf "$tools"' EXIT

# CMake finds the archiver, ranlib and install_name_tool by the compiler's name prefix in its directory.
tool() {
  printf '#!/bin/sh\n%s\n' "$2" >"$tools/$1"
  chmod +x "$tools/$1"
}

for pair in \
  aarch64-apple-darwin=aarch64-macos-none \
  aarch64-unknown-linux-gnu=aarch64-linux-gnu \
  aarch64-unknown-linux-musl=aarch64-linux-musl \
  x86_64-apple-darwin=x86_64-macos-none \
  x86_64-unknown-linux-gnu=x86_64-linux-gnu \
  x86_64-unknown-linux-musl=x86_64-linux-musl; do
  rust=${pair%%=*}
  zig=${pair#*=}
  tool "$rust-cc" "exec \"$self\" --driver cc $zig \"\$@\""
  tool "$rust-c++" "exec \"$self\" --driver c++ $zig \"\$@\""
  tool "$rust-ar" 'exec zig ar "$@"'
  tool "$rust-ranlib" 'exec zig ranlib "$@"'
  # BoringSSL builds only static libraries, so CMake requires this Darwin tool but never runs it.
  case "$rust" in
    *-apple-darwin) tool "$rust-install_name_tool" 'echo "install_name_tool is unavailable when cross-building" >&2; exit 1' ;;
  esac
  var=${rust//-/_}
  export "CC_$var=$tools/$rust-cc" "CXX_$var=$tools/$rust-c++" "AR_$var=$tools/$rust-ar"
  export "CARGO_TARGET_$(printf '%s' "$var" | tr '[:lower:]' '[:upper:]')_LINKER=$tools/$rust-cc"
done
# A build fails rather than change quiche's Cargo.lock.
tool cargo "if [ \"\$1\" = build ]; then shift; exec \"$cargo\" build --locked \"\$@\"; fi; exec \"$cargo\" \"\$@\""
export PATH="$tools:$PATH"

"$@"
