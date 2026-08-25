# GitHub Actions runner strategy

All Actions jobs run on ephemeral GitHub-hosted Ubuntu 24.04 runners:

- amd64: `ubuntu-24.04`
- arm64: `ubuntu-24.04-arm`

GitHub does not provide managed Debian, Fedora, or Arch runners. VaultLink runs
digest-pinned distribution containers and same-architecture QEMU guests on the
two Ubuntu hosts. No workflow targets a persistent self-hosted runner. Every
native job verifies `uname -m` and, where Rust is used, the compiler host triple
before accepting evidence.

The real Debian 13 amd64 staging host and 72-hour soak are not Actions runners.
The manual start and collector workflows use an environment-protected,
host-key-pinned SSH connection to the forced-command bridge described in
[`SOAK-RUNNER.md`](SOAK-RUNNER.md). The host stores no Actions token and never
executes arbitrary workflow shell.

## Target execution model

`release/package-targets.json` is the only supported-target matrix. Workflow
jobs render their matrices from it and fail if a target, package name, runner,
builder digest, guest digest, format, OS version, or architecture is duplicated
or inconsistent.

| Phase | Execution environment | Network policy | Authority |
| --- | --- | --- | --- |
| Rust/package build | Target distro builder container on matching native CPU | immutable build inputs only | authoritative |
| Fast package tests | Target distro container on matching native CPU | package installed offline; runtime network isolated | authoritative |
| Reproducibility | two empty build roots using the same target builder | immutable build inputs only | authoritative |
| Full-system test | target guest booted by QEMU on matching native CPU | isolated host package channel; no free guest Internet | authoritative |
| Local Docker | all x86_64 distro builders/containers | isolated runtime | development evidence only |
| 72-hour soak | dedicated Debian 13 amd64 system | controlled public application path plus collector bridge | final Debian reference evidence |

QEMU never compiles a release binary. KVM may accelerate a job when GitHub
exposes it, but workflows cannot depend on KVM and must pass under software
emulation. Fedora 44 guests keep SELinux `Enforcing`; disabling it invalidates
the gate. The Arch guest and builder use the snapshot date committed for the
candidate, while a separate weekly read-only job probes the current rolling
image.

## Immutable images and refresh

Each target declares `builder_image` and `vm_image` as a complete registry
reference ending in an OCI digest. `UNPROVISIONED`, a mutable tag, a missing
platform, a digest mismatch, or an unavailable image stops the relevant gate
before compilation or guest boot.

The source-independent QEMU harness is locked independently by its multiarch
image digest, exact Ubuntu 24.04 base digest, and complete native `dpkg`
inventory for both amd64 and arm64. Before a guest is provisioned or tested,
the selected harness must match its recorded architecture and OS, its embedded
inventory must match the commit, and a fresh live package-database inventory
must be byte-identical. The four locks may be `UNPROVISIONED` only together;
normal gates fail closed until all four are reviewed and committed.

During bootstrap or a reviewed harness refresh, each guest-image refresh
receives the exact successful QEMU-refresh run ID from the same `main` commit.
GitHub run metadata (commit, branch, workflow path, event, and result) is
checked before that run's immutable four-lock artifact is consumed and
verified on the native runner. Otherwise the guest refresh accepts only the
four locks already committed at its own revision. The final pin pull request
therefore updates those four locks and all nine target records atomically.

The protected manual image-refresh workflow:

1. runs only from an authorized `main` commit;
2. builds each builder and guest image natively for its CPU architecture;
3. verifies the fixed Rust toolchain, builder and QEMU package closures, OS
   identity, QEMU base digest, and required packaging/QEMU test tools;
4. pushes immutable images to GHCR; and
5. emits a complete proposed manifest with resolved digests as an artifact.

It never changes `main` directly. The emitted manifest is reviewed and pinned
in a second pull request. Release jobs install no mutable distro or Cargo tools
at runtime.

## Package, VM, and load gates

Every one of the nine targets performs:

- two clean native builds with byte-identical payload, SBOM, and package;
- `lintian`, `rpmlint`, or `namcap` plus the common path/owner/mode/dependency/
  scriptlet/unit allowlist;
- an offline fresh install with no service or timer autostart;
- setup, systemd analysis, API smoke, migration, backup, upgrade, rollback,
  reinstall, and state-preserving remove tests;
- a full guest boot with OS, kernel, package database, active-binary hash,
  systemd, journal, readiness, and SQLite evidence; and
- the 100-user profile with p95 below two seconds, no 5xx response or
  corruption, and the established RSS limit.

Native arm64 jobs are the only authoritative arm64 evidence. Architecture-
independent security, policy, aggregation, signing, and publication work stays
on `ubuntu-24.04`. Fuzz parallelism remains bounded by the runner resources.

Three aggregate, commit-bound checks are published:

- `vaultlink/packages`
- `vaultlink/package-reproducibility`
- `vaultlink/distro-vms`

Candidate, soak-start, and tag workflows require all three in addition to the
existing CI, fuzz, security, and release checks. No missing or skipped matrix
row is treated as success.

## Release assembly

Unsigned target jobs upload only short-lived packages, target SBOMs, hashes,
and evidence. The protected signing job independently validates the complete
nine-target set, signs each package and the global `SHA256SUMS`, and creates a
draft containing exactly the 21 assets defined in
[`PACKAGING.md`](PACKAGING.md). It downloads the draft from GitHub, repeats all
hash/signature/package/key/count checks, and only then publishes it.

The signing secret is not exposed to package, container, QEMU, load, soak, or
pull-request jobs. Starting with 0.6.0, published package assets are immutable
operational rollback inputs and must not be deleted.
