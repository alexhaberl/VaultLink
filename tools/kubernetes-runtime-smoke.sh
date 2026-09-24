#!/usr/bin/env bash
set -euo pipefail

image=${VAULTLINK_TEST_IMAGE:?Set VAULTLINK_TEST_IMAGE}
architecture=${VAULTLINK_TEST_ARCH:?Set VAULTLINK_TEST_ARCH}
case "$architecture" in
  amd64) kind_sha=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
  arm64) kind_sha=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
  *) echo "Unsupported architecture: $architecture" >&2; exit 1 ;;
esac

test_root="$RUNNER_TEMP/vaultlink-kind"
bin_dir="$test_root/bin"
mkdir -p "$bin_dir" "$test_root/state" "$test_root/storage"
export PATH="$bin_dir:$PATH"
curl -fsSL "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-$architecture" -o "$bin_dir/kind"
printf '%s  %s\n' "$kind_sha" "$bin_dir/kind" | sha256sum --check -
chmod 0755 "$bin_dir/kind"
kubectl_url="https://dl.k8s.io/release/v1.36.4/bin/linux/$architecture/kubectl"
curl -fsSL "$kubectl_url" -o "$bin_dir/kubectl"
curl -fsSL "$kubectl_url.sha256" -o "$bin_dir/kubectl.sha256"
printf '%s  %s\n' "$(cat "$bin_dir/kubectl.sha256")" "$bin_dir/kubectl" | sha256sum --check -
chmod 0755 "$bin_dir/kubectl"

cleanup() {
  if [[ -n ${forward_pid:-} ]]; then kill "$forward_pid" 2>/dev/null || true; fi
  if [[ -n ${cluster_created:-} ]]; then kind delete cluster --name vaultlink-ci || true; fi
  for name in storage state; do
    if mountpoint -q "$test_root/$name"; then sudo umount "$test_root/$name" || true; fi
  done
}
trap cleanup EXIT

for name in state storage; do
  size=2G
  [[ $name == storage ]] && size=12G
  truncate -s "$size" "$test_root/$name.img"
  mkfs.ext4 -F -q "$test_root/$name.img"
  sudo mount -o loop,nosuid,nodev,noexec "$test_root/$name.img" "$test_root/$name"
  sudo chown 10001:10001 "$test_root/$name"
  sudo chmod 0700 "$test_root/$name"
done
sudo install -d -o 10001 -g 10001 -m 0700 \
  "$test_root/storage/shared" \
  "$test_root/storage/.vaultlink-internal" \
  "$test_root/storage/.vaultlink-internal/uploads" \
  "$test_root/storage/.vaultlink-internal/tombstones"

cat >"$test_root/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
    extraMounts:
      - hostPath: $test_root/state
        containerPath: /mnt/vaultlink-host/state
      - hostPath: $test_root/storage
        containerPath: /mnt/vaultlink-host/storage
EOF
kind create cluster --name vaultlink-ci --config "$test_root/kind.yaml" --wait 5m
cluster_created=1
kind load docker-image "$image" --name vaultlink-ci

cat >"$test_root/pv.yaml" <<'EOF'
apiVersion: v1
kind: PersistentVolume
metadata:
  name: vaultlink-ci-state
spec:
  capacity:
    storage: 1Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local:
    path: /mnt/vaultlink-host/state
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [vaultlink-ci-control-plane]
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: vaultlink-ci-storage
spec:
  capacity:
    storage: 10Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local:
    path: /mnt/vaultlink-host/storage
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [vaultlink-ci-control-plane]
EOF
kubectl apply -f "$test_root/pv.yaml"
sed "s@ghcr.io/alexhaberl/vaultlink:vX.Y.Z@$image@" \
  deploy/kubernetes/vaultlink.yaml >"$test_root/vaultlink.yaml"
kubectl apply -f "$test_root/vaultlink.yaml"
kubectl wait --for=jsonpath='{.status.phase}'=Running pod -l app=vaultlink --timeout=180s

kubectl port-forward deployment/vaultlink 18081:8081 \
  >"$test_root/port-forward.log" 2>&1 &
forward_pid=$!
python3 tools/kubernetes-runtime-smoke.py setup
kill "$forward_pid" 2>/dev/null || true
wait "$forward_pid" 2>/dev/null || true
unset forward_pid

kubectl scale deployment/vaultlink --replicas=0
for attempt in {1..60}; do
  [[ $(kubectl get pods -l app=vaultlink -o name | wc -l) -eq 0 ]] && break
  sleep 2
done
[[ $(kubectl get pods -l app=vaultlink -o name | wc -l) -eq 0 ]]
sudo tar -C "$test_root" -cf "$test_root/paired-backup.tar" state storage
sudo rm "$test_root/state/data.sqlite"
sudo tar -C "$test_root" -xf "$test_root/paired-backup.tar"
test -s "$test_root/state/data.sqlite" || sudo test -s "$test_root/state/data.sqlite"
sudo cp "$test_root/state/data.sqlite" "$test_root/database-check.sqlite"
sudo chown "$(id -u):$(id -g)" "$test_root/database-check.sqlite"
python3 - "$test_root/database-check.sqlite" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
PY
kubectl scale deployment/vaultlink --replicas=1
kubectl wait --for=jsonpath='{.status.phase}'=Running pod -l app=vaultlink --timeout=180s
kubectl port-forward deployment/vaultlink 18081:8081 \
  >"$test_root/port-forward-restart.log" 2>&1 &
forward_pid=$!
python3 tools/kubernetes-runtime-smoke.py verify
kubectl rollout status deployment/vaultlink --timeout=120s
printf 'Kubernetes local-PV setup, transfers, paired restore and restart passed\n'
