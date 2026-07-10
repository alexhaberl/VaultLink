# Self-hosted GitHub Actions runner

VaultLink CI runs on a repository-scoped Debian 13 x86-64 runner with the
labels `self-hosted`, `Linux`, `X64`, and `vaultlink`. Release jobs remain on a
GitHub-hosted runner so that tagged release builds use a fresh environment.

## Host baseline

- Debian 13, 8 vCPU, 8 GiB RAM, and at least 100 GiB SSD storage
- Docker Engine from Docker's official Debian repository
- `build-essential`, `clang`, `git`, `libssl-dev`, `make`, `pkg-config`,
  `python3`, `shellcheck`, `sqlite3`, and `util-linux`
- a dedicated `github-runner` service account in the `docker` group
- GitHub Actions runner installed in `/opt/actions-runner` as a systemd service

The Docker group is root-equivalent. The VM must therefore be dedicated to CI,
must not contain unrelated secrets or services, and must only run trusted
private-repository changes. Do not route pull requests from untrusted forks to
this runner.

## Workflow behavior

The CI workflow uses one job so that Cargo artifacts are reused by formatting,
Clippy, tests, fuzz compilation, and audit checks within a run. Docker setup,
API, upgrade, and rollback smoke tests run afterwards on the same host.
Superseded pull-request runs are cancelled automatically.

The weekly and manually dispatched fuzz gate also uses one runner job. It runs
all seven ten-minute fuzz targets concurrently (`FUZZ_JOBS=7`), so its expected
wall-clock runtime is about 10-15 minutes after toolchain and build setup. A
single registered runner service serializes the CI and fuzz jobs, preventing
the two CPU-intensive workloads from competing for the same VM.

The Docker smoke image validates the systemd units inside the container. This
avoids granting the runner general `sudo` access merely to inspect paths under
`/root`.

## Operations

Check the service and recent logs:

```sh
systemctl list-unit-files 'actions.runner.*.service'
sudo systemctl status 'actions.runner.*.service'
sudo journalctl --unit='actions.runner.*.service' -n 100
```

Check disk usage periodically because Rust and Docker caches are persistent:

```sh
df -h /
docker system df
```

The runner application updates itself automatically. Operating-system and
Docker security updates remain the administrator's responsibility. Rebuild the
VM instead of restoring cached work directories from backup; register a new
repository runner after rebuilding.
