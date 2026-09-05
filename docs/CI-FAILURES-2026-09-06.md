# CI startup and mixed-load regressions

The failures below have separate causes. PR #162 starts from main
`a8ef6b93df32161b3066942907c24f98e9343426`, which already contains the
transfer-admission and hosted-runner load-profile corrections.

| Failed run | Observed failure | Correction |
| --- | --- | --- |
| [ARM64 native CI](https://github.com/alexhaberl/VaultLink/actions/runs/33996609478/job/101388138875) | Two CLI tests failed opening a database with `Pool(Error(None))`. | Initialize the complete pool against a shared ten-second startup deadline; retain one-second runtime checkout and admission budgets. |
| [Debian 13 amd64 package smoke](https://github.com/alexhaberl/VaultLink/actions/runs/33931364844/job/101211999504) | Metadata requests received HTTP 503 during the old 100/40/10 load profile. | Serialize transfer writers before general database admission, leaving capacity for reads (`675ab3d`, already on main). |
| [Ubuntu 24.04 amd64 package smoke](https://github.com/alexhaberl/VaultLink/actions/runs/33934131261/job/101219987611) | Metadata requests and two upload readbacks received HTTP 503; the upload POSTs themselves succeeded with HTTP 303. | The same transfer-admission correction, plus the explicit hosted-runner smoke profile (`a709438`, already on main). |

The current [package workflow on main](https://github.com/alexhaberl/VaultLink/actions/runs/33996609499)
passed all nine distribution/architecture targets. Hosted package CI uses
50 metadata clients, 20 range downloads and five uploads. The full 100/40/10
profile remains required for VM/soak validation, with strict performance
qualification on the dedicated soak host. See
[the runner strategy](GITHUB-HOSTED-RUNNERS.md).

## Regression coverage

- A real SQLite exclusive lock held beyond one second reproduces the original
  startup failure. The corrected startup waits for the lock, warms all four
  connections, preserves WAL and foreign keys, and retains the one-second
  timeout for exhausted runtime checkouts.
- Partial pool initialization fails at its startup deadline and releases
  already-acquired connections.
- `mixed_transfer_load_preserves_reads_while_sqlite_writer_is_active` holds a
  real `BEGIN IMMEDIATE` transaction while forty download-lease finalizers
  and ten upload-reservation finalizers queue. One hundred concurrent reads
  must complete before the writer is released. The test also checks that
  three connections and three runtime permits remain available for reads,
  and that all finalizers and permits recover after release. Restoring the
  former general-admission path only in the disposable test container makes
  this test fail with zero available reader permits; the current path passes.

The mixed-load regression is an admission correctness test. It does not
replace the end-to-end HTTP workload, upload checksum verification, or the
release performance gates, and it adds no retries or longer runtime budgets.
