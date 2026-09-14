#!/bin/bash
set -euo pipefail
exec "$(dirname "$0")/smoke-network.sh" network_identify
