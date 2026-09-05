# Performance evidence

The v0.7.0 baseline is commit
`a390dd9a2210a2e227655a562c541b2b4ebd493c`. Baseline and candidate each
require exactly five real measurements from the same pinned runner, including
native storage and CIFS. `tools/check-performance-evidence.py` enforces all
19 metrics, runner equality, absolute thresholds and median/p95 regression
limits. Missing metrics, schema-v1 files and edited summaries fail closed.

## Measurement identity and protected collection

Each schema-v2 run contains `commit`, `binary_sha256`, `package_target`
(`debian13-amd64`), positive `packages_run_id`, `candidate_preflight_run_id`,
`producer_sha256`, `run_index` (1 through 5), `runner` and `metrics`.
The baseline's candidate preflight ID is null. Measure and record
`binary_sha256_before` and `binary_sha256_after` from the actual package binary;
both must equal `binary_sha256`. Use the same producer revision for baseline
and candidate measurements. Obtain its digest from:

```sh
python3 tools/release-evidence.py producer-digest
```

The runner object records `id`, immutable image digest, `cpu_model`, `cpu_set`,
`memory_bytes`, and `storage`. The complete metric keys and numerical limits
are defined in `REQUIRED_METRICS` and `ABSOLUTE_LIMITS` in the checker.
The collector imports completed measurements; it does not synthesize missing
ZIP, CIFS, allocation, startup, SQLite or HTTP measurements from load-test logs.

Provision the reviewed `tools/collect-performance-evidence.py` as a root-owned,
non-writable executable on the measurement host. Use a dedicated SSH key with
`restrict,command="/usr/bin/python3 /usr/local/libexec/vaultlink-performance-collect.py"`.
All path components must be root-owned and not writable by group/others. Store
five root-owned regular files, `run-1.json` through `run-5.json`, in:

```
/var/lib/vaultlink-performance/COMMIT/BINARY_SHA256/
```

Install complete measured runs atomically. The SSH identity may read them but
cannot write them or obtain a shell. The forced command accepts only
`performance-collect COMMIT BINARY_SHA256`; it exports the original JSON bytes.
Symlinks, writable files, non-regular files and files over 1 MiB are rejected.

Configure the `release-performance` GitHub environment with a main-only
branch policy and reviewers, and these environment secrets:
`PERFORMANCE_SSH_HOST`, `PERFORMANCE_SSH_PORT`, `PERFORMANCE_SSH_USER`,
`PERFORMANCE_SSH_PRIVATE_KEY`, `PERFORMANCE_SSH_HOST_KEYS`.
Host keys are pinned; the existing restricted SSH configuration tool is reused.

## Release sequence without changing the qualified commit

1. Measure the baseline, then dispatch `performance-evidence.yml` from main with
   kind `baseline`, its historical commit, real binary hash and successful
   Packages run ID. The workflow verifies the exact downloaded package binary
   and archives a complete immutable bundle with a producer receipt.
2. Register and review that successful artifact before freezing a candidate:

   ```sh
   export GITHUB_REPOSITORY=alexhaberl/VaultLink
   python3 tools/release-evidence.py lock-baseline --run-id BASELINE_RUN_ID \
     --workflow-sha BASELINE_PRODUCER_COMMIT \
     --output release/performance/baseline.lock.json
   ```

   Commit the resulting reviewed lock, source fixes and release date (if known).
   The lock binds the baseline aggregate, artifact digest, repository, run,
   attempt and producer workflow commit. No placeholder lock is provided.
3. Freeze the candidate. Run the existing native, packages, fuzz,
   reproducibility and VM gates and the release candidate preflight. The
   candidate phase defers only QUAL-001 and QUAL-006; other open findings block.
4. Measure the exact candidate package binary five times. Dispatch the protected
   producer with kind `candidate`, the frozen commit, binary hash and Packages
   run ID. It verifies the candidate preflight, all identity fields and the
   reviewed baseline before uploading its artifact and publishing
   `vaultlink/performance`. Artifacts include commit, run and attempt in names.
5. Soak start independently downloads and verifies that performance artifact
   against the extracted candidate binary before activating the existing soak.
   This phase requires performance and defers only the soak qualification.
6. After the full 72-hour soak, release evidence/tag phases independently verify
   both artifacts against that same commit and binary. Effective qualification
   is archived externally; no candidate evidence or closed flags are committed.
   The legacy `--require-ready` option remains strict and cannot bypass proof.

Changing main or the package/producer/baseline identity requires a new candidate
qualification. A final tag must point to the qualified main commit; commit its
release date before starting the soak. An expired artifact must be regenerated
and qualified, never replaced by a caller-supplied assertion. Performance
artifacts are retained for 90 days; the reviewed baseline must still be
available throughout the qualification cycle.

## Portable bundles and local validation

The aggregate command validates every run, copies its unchanged bytes to
hash-derived adjacent filenames and publishes the aggregate last:

```sh
python3 tools/check-performance-evidence.py aggregate --kind candidate \
  --output /tmp/performance/candidate.json \
  run-1.json run-2.json run-3.json run-4.json run-5.json
```

Move/archive the whole output directory. Comparison re-hashes and recomputes
all five source runs for both aggregates and requires all six independently
trusted expected identity arguments; see `compare --help`. Existing conflicting
files and symlink destinations fail closed. Unit test fixture values are
synthetic test inputs and never constitute release evidence.

QUAL-001 and QUAL-006 remain open in source until real runner evidence exists;
the phase validator resolves their effective status only from verified Actions
artifacts. Native package smoke and local Rust tests do not replace these gates.
