# Kubernetes deployment (Linux amd64 and arm64)

The first official Kubernetes target is Kubernetes 1.36 with one VaultLink pod,
local ext4 persistent volumes and the same signed, digest-pinned GHCR image as
Docker Engine. The published 0.7.1 release has no runtime image. The native CI
suite tests this manifest in a Kubernetes 1.36 kind cluster on both architectures.
Do not treat a green Kubernetes control-plane status alone as a VaultLink
readiness check.

## Storage and manifests

Provision two distinct local ext4 volumes on the same Linux node. Keep SQLite,
`config.toml` and `secrets.keyring` on the **state** volume, and shared files on
the **storage** volume. The storage root needs private `shared` and
`.vaultlink-internal/{uploads,tombstones}` directories owned by UID/GID 10001
with mode `0700`. Mount the node filesystems with `nosuid,nodev,noexec` before
the kubelet starts the pod. Verify their actual sources with `findmnt`. Never
put SQLite on SMB or use one storage root for two pods. Kubernetes `ReadWriteOnce`
does not enforce VaultLink's single-instance requirement by itself.

Create local PersistentVolumes bound to that node. Replace the node name, paths
and capacities in this example with the real values; the node paths must be
mounted filesystems rather than ordinary directories on the node root:

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: vaultlink-state
spec:
  capacity: {storage: 1Gi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local: {path: /srv/vaultlink/state}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [REPLACE_WITH_NODE_NAME]
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: vaultlink-storage
spec:
  capacity: {storage: 10Gi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  local: {path: /srv/vaultlink/storage}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values: [REPLACE_WITH_NODE_NAME]
```

Apply the PVs, then use `deploy/kubernetes/vaultlink.yaml` from the signed
release tag. Replace its image with the **top-level GHCR index digest** from
that same tag, for example
`ghcr.io/alexhaberl/vaultlink@sha256:REPLACE_WITH_RELEASE_INDEX_DIGEST`.
Keep `replicas: 1` and `strategy: Recreate`. The manifest sets UID/GID 10001,
no service-account token, no capabilities, a read-only root filesystem,
`RuntimeDefault` seccomp, a bounded memory-backed `/tmp`, and separate
startup, liveness and readiness probes. The claims deliberately specify no
dynamic storage class so they cannot silently land on an unverified backend.

```sh
kubectl apply -f vaultlink-pvs.yaml
kubectl apply -f deploy/kubernetes/vaultlink.yaml
kubectl get pv vaultlink-state vaultlink-storage
kubectl get pvc vaultlink-state vaultlink-storage
kubectl get pods -l app=vaultlink
```

If either claim is Pending, correct the local PV binding before proceeding.

## Browser setup and traffic

The pod starts the one-time browser setup before a private config exists. Its
readiness probe intentionally stays false until setup completes. Port-forward
the **pod** directly, since the Service has no ready endpoint yet:

```sh
kubectl logs deployment/vaultlink
pod=$(kubectl get pods -l app=vaultlink -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward "pod/$pod" 18081:8081
```

Open the printed token URL through that local port. If `kubectl` runs on a
remote administration host, use an SSH tunnel to its loopback port. In browser
setup select reverse-proxy mode, `listen_address=127.0.0.1:8080`, the public
`https://` URL, and the exact trusted proxy peer addresses. Set
`root_mount_path=/mnt/storage/shared`,
`internal_directory=/mnt/storage/.vaultlink-internal`, and
`data_directory=/var/lib/vaultlink`. Read the pod's mount record and enter the
literal storage type and source:

```sh
kubectl exec "$pod" -- cat /proc/self/mountinfo | awk \
  '$5 == "/mnt/storage" {for (i=1; i<=NF; i++) if ($i == "-") {
    print "expected_filesystem_type = \"" $(i+1) "\""
    print "expected_mount_source = \"" $(i+2) "\""
    exit
  }}'
kubectl rollout status deployment/vaultlink
```

Expose the `vaultlink` Service only through a TLS ingress or reverse proxy
that preserves the required forwarded headers; see the
[container proxy guide](CONTAINER-SETUP.md). Keep the setup port-forward private.
Before opening public access, check `/api/v2/health/ready`, the image digest,
unprivileged UID, transfer hashes and SQLite integrity. The container update
view directs administrators to the orchestrator rather than offering native
package updates.

## Upgrade and recovery

Build or pull the new digest before the maintenance window. Stop external
ingress, scale the Deployment to zero and wait until no old pod remains. Take a
**paired, stopped** backup or snapshots of both local PVs, including config,
SQLite, keyring, shared files and the image digest/manifests. Run
`PRAGMA integrity_check` on the backed-up database. Update the pinned image,
return to one replica, and check the VaultLink version, readiness, transfer
hashes and SQLite integrity before restoring ingress.

If activation fails, keep ingress closed, scale to zero again, restore **both**
prior PV snapshots and the previous image digest/manifests, then start one pod
and repeat every check. Do not roll back only the Deployment image after a
database migration. Local PVs bind the pod to one node; arrange node backup and
recovery accordingly. The release checklist requires a successful restore on
both architectures before this deployment is advertised as supported.

The initial Kubernetes target uses local ext4 storage. CSI and SMB-backed
volumes need their own mount-identity, permission, and recovery qualification.
