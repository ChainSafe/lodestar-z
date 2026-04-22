#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="${1:-lodestar-z:kurtosis}"
ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

if [[ "${LODESTAR_Z_SKIP_BUILD:-0}" == "1" ]]; then
  echo "[build-kurtosis-image] skipping zig build because LODESTAR_Z_SKIP_BUILD=1"
else
  echo "[build-kurtosis-image] building lodestar-z binary (ReleaseSafe)"
  zig build -Doptimize=ReleaseSafe
fi

echo "[build-kurtosis-image] building Docker image ${IMAGE_TAG}"
docker build -f docker/kurtosis/Dockerfile -t "$IMAGE_TAG" .
