#!/usr/bin/env bash
# Safe operator wrapper for the non-secret infrastructure verifier.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

command -v python3 >/dev/null 2>&1 || {
  printf 'ERROR: python3 is required\n' >&2
  exit 1
}

exec python3 "${SCRIPT_DIR}/verify_infrastructure.py" "$@"
