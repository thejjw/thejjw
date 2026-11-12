#!/bin/bash
# Interactive entry point for the aiusage tool that lives in this directory.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PYTHONPATH="$root" exec "${AI_USAGE_PYTHON:-/usr/bin/python3}" -m aiusage "$@"
