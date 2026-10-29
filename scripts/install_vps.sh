#!/usr/bin/env bash
# Compatibility wrapper: install/setup via the VPS CLI UI.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/cliui.sh" install "$@"
