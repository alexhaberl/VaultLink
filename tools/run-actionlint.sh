#!/bin/sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
LANG=C
export PATH LC_ALL LANG

actionlint_version=1.7.12
case "$(uname -m)" in
    x86_64)
        actionlint_arch=amd64
        actionlint_sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
        ;;
    aarch64|arm64)
        actionlint_arch=arm64
        actionlint_sha256=325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
        ;;
    *)
        echo "actionlint: unsupported native architecture: $(uname -m)" >&2
        exit 77
        ;;
esac

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
archive="$work/actionlint.tar.gz"
url="https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_${actionlint_arch}.tar.gz"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 5 --output "$archive" "$url"
printf '%s  %s\n' "$actionlint_sha256" "$archive" | sha256sum -c -
tar -xzf "$archive" -C "$work" actionlint
test "$("$work/actionlint" -version | sed -n '1p')" = "$actionlint_version"
"$work/actionlint" -shellcheck shellcheck
