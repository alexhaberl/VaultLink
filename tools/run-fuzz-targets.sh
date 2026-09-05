#!/bin/sh
set -eu

# Keep the Make/CI entry point; Python preserves individual exit codes and kills
# the entire process group when a stage exceeds its own wall-clock budget.
exec "${PYTHON:-python3}" "$(dirname "$0")/run-fuzz-targets.py" "$@"
