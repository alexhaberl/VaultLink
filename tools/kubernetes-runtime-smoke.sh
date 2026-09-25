#!/usr/bin/env bash
set -euo pipefail

image=${VAULTLINK_TEST_IMAGE:?Set VAULTLINK_TEST_IMAGE}
architecture=${VAULTLINK_TEST_ARCH:?Set VAULTLINK_TEST_ARCH}
case "$architecture" in
  amd64)
    kind_sha=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
    kubectl_sha=8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a ;;
  arm64)
    kind_sha=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2
    kubectl_sha=0ecf44450ee6063bf19dd166a103ee6df4a9034455c2abce626e6eea657d73fb ;;
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
printf '%s  %s\n' "$kubectl_sha" "$bin_dir/kubectl" | sha256sum --check -
chmod 0755 "$bin_dir/kubectl"

cleanup() {
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
mkdir -p "$test_root/client-certs"
python3 - "$test_root/client-certs" <<'PY'
import importlib.util, pathlib, sys
path = pathlib.Path('tools/docker-runtime-smoke.py')
spec = importlib.util.spec_from_file_location('vaultlink_smoke', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.make_test_certificates(pathlib.Path(sys.argv[1]))
PY
sudo install -d -o 10001 -g 10001 -m 0700 "$test_root/state/certs"
for name in ca.crt server.crt server.key client.crt client.key; do
  sudo install -o 10001 -g 10001 -m 0600 \
    "$test_root/client-certs/$name" "$test_root/state/certs/$name"
done
export VAULTLINK_KUBE_CERT_DIR="$test_root/client-certs"

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
  name: vaultlink-state
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
  name: vaultlink-storage
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

python3 tools/kubernetes-runtime-smoke.py setup

kubectl scale deployment/vaultlink --replicas=0
for ((attempt = 0; attempt < 60; attempt++)); do
  [[ $(kubectl get pods -l app=vaultlink -o name | wc -l) -eq 0 ]] && break
  sleep 2
done
[[ $(kubectl get pods -l app=vaultlink -o name | wc -l) -eq 0 ]]
sudo test -s "$test_root/state/config.toml"
sudo test -s "$test_root/state/data.sqlite"
sudo test -s "$test_root/state/secrets.keyring"
sudo sha256sum \
  "$test_root/state/config.toml" \
  "$test_root/state/data.sqlite" \
  "$test_root/state/secrets.keyring" \
  "$test_root/storage/shared/readme.txt" \
  "$test_root/storage/shared/uploads/upload.bin" \
  | tee "$test_root/paired-hashes.txt" >/dev/null
sudo tar -C "$test_root" -cf "$test_root/paired-backup.tar" state storage
sudo rm "$test_root/state/data.sqlite"
sudo truncate -s 0 "$test_root/storage/shared/readme.txt"
sudo tar -C "$test_root" -xf "$test_root/paired-backup.tar"
sudo sha256sum --check "$test_root/paired-hashes.txt"
sudo python3 - "$test_root/state/data.sqlite" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
PY
kubectl scale deployment/vaultlink --replicas=1
kubectl wait --for=jsonpath='{.status.phase}'=Running pod -l app=vaultlink --timeout=180s
python3 tools/kubernetes-runtime-smoke.py verify
kubectl rollout status deployment/vaultlink --timeout=120s
printf 'Kubernetes local-PV setup, transfers, paired restore and restart passed\n'
