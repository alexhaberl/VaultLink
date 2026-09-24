#!/usr/bin/env bash
set -euo pipefail
trap 'printf "rootless smoke failed at line %s\n" "$LINENO" >&2' ERR

image=${VAULTLINK_TEST_IMAGE:-}
if [[ ${VAULTLINK_PROBE_ONLY:-0} != 1 ]]; then
  test -n "$image" || { echo 'Set VAULTLINK_TEST_IMAGE' >&2; exit 1; }
fi
compose_project="vaultlink-rootless-ci-${GITHUB_RUN_ID:-local}"
compose_files=(-f deploy/docker/compose.rootless.yaml -f tools/fixtures/compose.rootless-ci.yaml)
command -v dockerd-rootless.sh >/dev/null || {
  sudo apt-get update
  sudo apt-get install -y uidmap slirp4netns fuse-overlayfs
  docker_key="$RUNNER_TEMP/docker-apt.asc"
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$docker_key"
  fingerprint=$(gpg --show-keys --with-colons "$docker_key" \
    | awk -F: '$1 == "fpr" {print $10; exit}')
  test "$fingerprint" = 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
  sudo install -d -m 0755 /etc/apt/keyrings
  sudo install -m 0644 "$docker_key" /etc/apt/keyrings/vaultlink-docker-ci.asc
  printf 'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: noble\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/vaultlink-docker-ci.asc\n' \
    "$(dpkg --print-architecture)" \
    | sudo tee /etc/apt/sources.list.d/vaultlink-docker-ci.sources >/dev/null
  sudo apt-get update
  mkdir -p "$RUNNER_TEMP/vaultlink-rootless-tools"
  (cd "$RUNNER_TEMP/vaultlink-rootless-tools" \
    && apt-get download 'docker-ce-rootless-extras=5:29.8.1-1~ubuntu.24.04~noble' \
      'docker-ce=5:29.8.1-1~ubuntu.24.04~noble' \
    && for package in docker-ce-rootless-extras_*.deb docker-ce_*.deb; do
      dpkg-deb -x "$package" .
    done)
  export PATH="$RUNNER_TEMP/vaultlink-rootless-tools/usr/bin:$PATH"
}
dockerd --version | grep -q '^Docker version 29\.8\.1,'
command -v newuidmap >/dev/null
command -v newgidmap >/dev/null
next_subid_range() {
  awk -F: 'BEGIN { next_id = 100000 }
    $2 + $3 > next_id { next_id = $2 + $3 }
    END {
      start = int((next_id + 65535) / 65536) * 65536
      printf "%d-%d\n", start, start + 65535
    }' "$1"
}
if ! grep -Eq "^$(id -un):[0-9]+:[0-9]{5,}$" /etc/subuid; then
  sudo usermod --add-subuids "$(next_subid_range /etc/subuid)" "$(id -un)"
fi
if ! grep -Eq "^$(id -un):[0-9]+:[0-9]{5,}$" /etc/subgid; then
  sudo usermod --add-subgids "$(next_subid_range /etc/subgid)" "$(id -un)"
fi
grep -E "^$(id -un):" /etc/subuid /etc/subgid
if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] \
  && [[ $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns) == 1 ]]; then
  rootlesskit_bin=$(command -v rootlesskit)
  test -n "$rootlesskit_bin"
  sudo tee /etc/apparmor.d/vaultlink-ci-rootlesskit >/dev/null <<EOF
abi <abi/4.0>,
include <tunables/global>
"$rootlesskit_bin" flags=(unconfined) {
  userns,
}
EOF
  sudo apparmor_parser -r /etc/apparmor.d/vaultlink-ci-rootlesskit
fi

rootless_run_dir="$RUNNER_TEMP/vaultlink-rootless-run"
rootless_data_dir="$RUNNER_TEMP/vaultlink-rootless-data"
install -d -m 0700 "$rootless_run_dir" "$rootless_data_dir"
export XDG_RUNTIME_DIR="$rootless_run_dir"
unset DOCKER_CONTEXT
export DOCKER_HOST="unix://$rootless_run_dir/docker.sock"
export DOCKER_CONFIG="$RUNNER_TEMP/vaultlink-rootless-cli"
install -d -m 0700 "$DOCKER_CONFIG"
rootful_host=unix:///var/run/docker.sock

cleanup() {
  if [[ ${VAULTLINK_PROBE_ONLY:-0} != 1 ]]; then
    VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
      "${compose_files[@]}" down >/dev/null 2>&1 || true
  fi
  if [[ -n ${daemon_pid:-} ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

XDG_DATA_HOME="$rootless_data_dir" dockerd-rootless.sh \
  --host "$DOCKER_HOST" --storage-driver=fuse-overlayfs \
  --bridge=none --iptables=false --ip6tables=false \
  >"$RUNNER_TEMP/vaultlink-rootless-daemon.log" 2>&1 &
daemon_pid=$!
for attempt in {1..90}; do
  if [[ -S "$rootless_run_dir/docker.sock" ]] \
    && docker info --format '{{json .SecurityOptions}}' >"$RUNNER_TEMP/vaultlink-rootless-info.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$RUNNER_TEMP/vaultlink-rootless-daemon.log"
    exit 1
  fi
  sleep 1
done
if ! grep -q 'rootless' "$RUNNER_TEMP/vaultlink-rootless-info.json"; then
  cat "$RUNNER_TEMP/vaultlink-rootless-info.json"
  cat "$RUNNER_TEMP/vaultlink-rootless-daemon.log"
  exit 1
fi
docker info --format '{{.DockerRootDir}} {{json .SecurityOptions}}'
if [[ ${VAULTLINK_PROBE_ONLY:-0} == 1 ]]; then
  probe_image=docker.io/library/debian@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1
  docker pull "$probe_image"
  docker run --rm --network host --user 10001:10001 \
    --entrypoint /bin/true "$probe_image"
  printf 'Rootless Docker host-network runner probe passed\n'
  exit 0
fi

docker --host "$rootful_host" save "$image" | docker load
VAULTLINK_TEST_EXPECT_ROOTLESS=1 VAULTLINK_TEST_HOST_NETWORK=1 \
  python3 tools/docker-runtime-smoke.py
VAULTLINK_IMAGE="$image" docker compose "${compose_files[@]}" config --quiet
VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  "${compose_files[@]}" run --rm --user 0 \
  --entrypoint bash vaultlink -ec \
  'install -d -o 10001 -g 10001 -m 0700 /var/lib/vaultlink \
   /mnt/storage/shared /mnt/storage/.vaultlink-internal \
   /mnt/storage/.vaultlink-internal/uploads \
   /mnt/storage/.vaultlink-internal/tombstones'
VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  "${compose_files[@]}" up -d
service_container=$(VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  "${compose_files[@]}" ps -q vaultlink)
test "$(docker exec "$service_container" id -u)" = 10001
for ((attempt = 0; attempt < 30; attempt++)); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ || true)
  [[ $code == 401 ]] && break
  sleep 1
done
test "$code" = 401
