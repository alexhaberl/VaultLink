#!/usr/bin/env bash
set -euo pipefail

image=${VAULTLINK_TEST_IMAGE:?Set VAULTLINK_TEST_IMAGE}
command -v dockerd-rootless.sh >/dev/null || {
  sudo apt-get update
  sudo apt-get install -y docker-ce-rootless-extras uidmap slirp4netns fuse-overlayfs
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
