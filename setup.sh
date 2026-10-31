#!/usr/bin/env bash
# Install netsentry, then configure and start it by answering a few questions. Run as root: sudo ./setup.sh
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "error: run as root: sudo $0" >&2; exit 1; }
[[ -t 0 ]] || { echo "error: setup asks questions; run it in a terminal (or use install.sh)" >&2; exit 1; }

NETSENTRY_SKIP_NEXT_STEPS=1 bash "$SRC/install.sh"
echo
exec /usr/local/bin/netsentry setup
