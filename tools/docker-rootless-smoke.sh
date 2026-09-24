#!/usr/bin/env bash
set -euo pipefail

image=${VAULTLINK_TEST_IMAGE:?Set VAULTLINK_TEST_IMAGE}
compose_project="vaultlink-rootless-ci-${GITHUB_RUN_ID:-local}"
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
    && apt-get download docker-ce-rootless-extras \
    && dpkg-deb -x docker-ce-rootless-extras_*.deb .)
  export PATH="$RUNNER_TEMP/vaultlink-rootless-tools/usr/bin:$PATH"
}
command -v newuidmap >/dev/null
command -v newgidmap >/dev/null
grep -Eq "^$(id -un):[0-9]+:[0-9]{5,}$" /etc/subuid
grep -Eq "^$(id -un):[0-9]+:[0-9]{5,}$" /etc/subgid

rootless_run_dir="$RUNNER_TEMP/vaultlink-rootless-run"
rootless_data_dir="$RUNNER_TEMP/vaultlink-rootless-data"
install -d -m 0700 "$rootless_run_dir" "$rootless_data_dir"
export XDG_RUNTIME_DIR="$rootless_run_dir"
export DOCKER_HOST="unix://$rootless_run_dir/docker.sock"
export DOCKER_CONFIG="$RUNNER_TEMP/vaultlink-rootless-cli"
install -d -m 0700 "$DOCKER_CONFIG"
rootful_host=unix:///var/run/docker.sock

cleanup() {
  VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
    -f deploy/docker/compose.rootless.yaml down >/dev/null 2>&1 || true
  if [[ -n ${daemon_pid:-} ]]; then
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

XDG_DATA_HOME="$rootless_data_dir" dockerd-rootless.sh \
  --host "$DOCKER_HOST" --storage-driver=fuse-overlayfs \
  >"$RUNNER_TEMP/vaultlink-rootless-daemon.log" 2>&1 &
daemon_pid=$!
for attempt in {1..90}; do
  if docker info --format '{{json .SecurityOptions}}' >"$RUNNER_TEMP/vaultlink-rootless-info.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    cat "$RUNNER_TEMP/vaultlink-rootless-daemon.log"
    exit 1
  fi
  sleep 1
done
grep -q 'rootless' "$RUNNER_TEMP/vaultlink-rootless-info.json"
docker info --format '{{.DockerRootDir}} {{json .SecurityOptions}}'

docker --host "$rootful_host" save "$image" | docker load
VAULTLINK_TEST_EXPECT_ROOTLESS=1 python3 tools/docker-runtime-smoke.py
VAULTLINK_IMAGE="$image" docker compose -f deploy/docker/compose.rootless.yaml config --quiet
VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  -f deploy/docker/compose.rootless.yaml run --rm --user 0 \
  --entrypoint bash vaultlink -ec \
  'install -d -o 10001 -g 10001 -m 0700 /var/lib/vaultlink \
   /mnt/storage/shared /mnt/storage/.vaultlink-internal \
   /mnt/storage/.vaultlink-internal/uploads \
   /mnt/storage/.vaultlink-internal/tombstones'
VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  -f deploy/docker/compose.rootless.yaml up -d
service_container=$(VAULTLINK_IMAGE="$image" docker compose -p "$compose_project" \
  -f deploy/docker/compose.rootless.yaml ps -q vaultlink)
test "$(docker exec "$service_container" id -u)" = 10001
for attempt in {1..30}; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ || true)
  [[ $code == 401 ]] && break
  sleep 1
done
test "$code" = 401
