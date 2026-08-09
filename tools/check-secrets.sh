#!/bin/sh
set -eu

expected_gitleaks_version=8.30.0
gitleaks_bin=${GITLEAKS_BIN:-gitleaks}

if [ -x "$gitleaks_bin" ]; then
    :
elif resolved_gitleaks=$(command -v "$gitleaks_bin" 2>/dev/null); then
    gitleaks_bin=$resolved_gitleaks
else
    echo "secret scan: Gitleaks $expected_gitleaks_version is required" >&2
    exit 1
fi

actual_gitleaks_version=$($gitleaks_bin version 2>/dev/null || true)
if [ "$actual_gitleaks_version" != "$expected_gitleaks_version" ]; then
    echo "secret scan: expected Gitleaks $expected_gitleaks_version, got ${actual_gitleaks_version:-unknown}" >&2
    exit 1
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

if [ ! -f .gitleaksignore ]; then
    echo "secret scan: .gitleaksignore is missing" >&2
    exit 1
fi

exec "$gitleaks_bin" git \
    --redact=100 \
    --no-banner \
    --no-color \
    --max-decode-depth=5 \
    --max-archive-depth=2 \
    --gitleaks-ignore-path .gitleaksignore \
    --log-opts="--all --full-history" \
    .
