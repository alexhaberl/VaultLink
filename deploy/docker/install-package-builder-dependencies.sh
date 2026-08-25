#!/bin/sh
set -eu

[ "$#" -eq 6 ] || {
    echo "usage: $0 TARGET_ID DISTRIBUTION VERSION TARGETARCH ARCH_SNAPSHOT_DATE BASE_IMAGE" >&2
    exit 64
}

target_id=$1
distribution=$2
version=$3
target_arch=$4
arch_snapshot_date=$5
builder_base_image=$6

read_os_release_field() {
    os_field=$1
    os_values=$(sed -n "s/^${os_field}=//p" /etc/os-release)
    [ "$(printf '%s\n' "$os_values" | grep -c .)" -eq 1 ] || {
        echo "builder base must define $os_field exactly once" >&2
        exit 77
    }
    case "$os_values" in
        \"*\") os_values=${os_values#\"}; os_values=${os_values%\"} ;;
    esac
    case "$os_values" in
        ''|*[!A-Za-z0-9._+-]*)
            echo "builder base has unsafe $os_field" >&2
            exit 77
            ;;
    esac
    printf '%s\n' "$os_values"
}

[ -r /etc/os-release ] || {
    echo "builder base OS identity is unavailable" >&2
    exit 77
}
actual_distribution=$(read_os_release_field ID)
[ "$actual_distribution" = "$distribution" ] || {
    echo "builder base is $actual_distribution, expected $distribution" >&2
    exit 77
}
if [ "$distribution" = arch ]; then
    [ "$version" = rolling ] || exit 77
else
    actual_version=$(read_os_release_field VERSION_ID)
    [ "$actual_version" = "$version" ] || {
        echo "builder base is $distribution $actual_version, expected $version" >&2
        exit 77
    }
fi

case "$target_arch" in
    amd64 | arm64) ;;
    *) echo "unsupported native builder architecture: $target_arch" >&2; exit 65 ;;
esac
case "$target_arch:$(uname -m)" in
    amd64:x86_64|arm64:aarch64) ;;
    *) echo "builder platform does not match native target $target_arch" >&2; exit 77 ;;
esac

case "$distribution:$version" in
    debian:13 | ubuntu:24.04 | ubuntu:26.04)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            bash binutils build-essential ca-certificates coreutils cpio curl diffutils dpkg \
            dpkg-dev file gh git gzip jq libarchive-tools lintian minisign openssh-client \
            openssl pkg-config python3 rpm rpm2cpio shellcheck sqlite3 systemd tar \
            util-linux xz-utils zstd
        dpkg-query -W -f='${binary:Package}=${Version}\n' \
            | LC_ALL=C sort > /usr/local/share/vaultlink-builder-packages.lock
        rm -rf /var/lib/apt/lists/*
        ;;
    fedora:44)
        dnf --assumeyes --setopt=install_weak_deps=False install \
            bash binutils ca-certificates coreutils cpio curl diffutils file findutils gcc gcc-c++ git \
            gh glibc gzip jq make minisign openssh-clients openssl pkgconf-pkg-config \
            python3 rpm-build rpm2cpio rpmlint shellcheck sqlite systemd tar util-linux zstd
        rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
            | LC_ALL=C sort > /usr/local/share/vaultlink-builder-packages.lock
        dnf clean all
        ;;
    arch:rolling)
        case "$arch_snapshot_date" in
            20??-??-??) ;;
            *) echo "Arch snapshot date is not provisioned" >&2; exit 77 ;;
        esac
        # shellcheck disable=SC2016
        printf 'Server = https://archive.archlinux.org/repos/%s/$repo/os/$arch\n' \
            "$arch_snapshot_date" >/etc/pacman.d/mirrorlist
        # Refresh both databases and permit downgrades so a newer mutable base
        # cannot survive as a mixed state above the selected archive snapshot.
        pacman -Syyuu --noconfirm --needed \
            base-devel bash binutils ca-certificates coreutils curl diffutils file gcc-libs git github-cli \
            gzip jq libarchive minisign namcap openssh openssl python shellcheck sqlite \
            systemd tar util-linux zstd
        pacman -Q | LC_ALL=C sort > /usr/local/share/vaultlink-builder-packages.lock
        pacman -Scc --noconfirm
        ;;
    *)
        echo "unsupported package builder target: $distribution:$version" >&2
        exit 65
        ;;
esac

install -d -m 0755 /usr/local/share
printf '%s\n' \
    "target_id=$target_id" \
    "distribution=$distribution" \
    "distribution_version=$version" \
    "architecture=$target_arch" \
    "builder_base_image=$builder_base_image" \
    "arch_snapshot_date=$arch_snapshot_date" \
    > /usr/local/share/vaultlink-builder.env
chmod 0644 /usr/local/share/vaultlink-builder.env \
    /usr/local/share/vaultlink-builder-packages.lock

test -s /usr/local/share/vaultlink-builder-packages.lock
