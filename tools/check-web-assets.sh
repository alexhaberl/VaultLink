#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
cd "$repository_root"

command -v node >/dev/null 2>&1 || {
    echo "web assets: node is required" >&2
    exit 69
}

asset_directory=assets/web
css_linter=tools/lint-css.mjs

for required_file in \
    "$asset_directory/vaultlink.css" \
    "$asset_directory/app.js" \
    "$asset_directory/upload-queue.js" \
    "$asset_directory/setup.js" \
    "$css_linter"; do
    if [ ! -f "$required_file" ] || [ -L "$required_file" ]; then
        echo "web assets: missing or unsafe regular file: $required_file" >&2
        exit 1
    fi
done

node --check "$css_linter"
for javascript_asset in \
    "$asset_directory/app.js" \
    "$asset_directory/upload-queue.js" \
    "$asset_directory/setup.js"; do
    node --check "$javascript_asset"
done
node "$css_linter" "$asset_directory/vaultlink.css"

lint_fixture_directory=$(mktemp -d "${TMPDIR:-/tmp}/vaultlink-css-lint.XXXXXXXXXX")
trap 'rm -rf -- "$lint_fixture_directory"' EXIT HUP INT TERM
printf '%s\n' '.broken {' >"$lint_fixture_directory/unclosed.css"
if node "$css_linter" "$lint_fixture_directory/unclosed.css" >/dev/null 2>&1; then
    echo "web assets: CSS linter accepted an unclosed block" >&2
    exit 1
fi
