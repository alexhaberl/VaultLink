# Fuzzing and corpus coverage

VaultLink's targets exercise production parsers, request policy, bounded file
operations, and recovery. The target list comes from `fuzz/Cargo.toml`; the runner,
corpus tools, and coverage report all use that list. Fuzzing complements the
deterministic integration, concurrency, and Docker smoke tests. Middleware
scheduling, SQLite transaction interleavings, Tokio cancellation, and live
filesystem races still require those tests.

## Target matrix

| Target | Production surface and checks | Boundary |
| --- | --- | --- |
| `path_normalization` | Public path normalization and containment policy | No filesystem lookup |
| `byte_range` | HTTP byte-range parsing and bounds | No response streaming |
| `filename` | Public/admin filename and reserved namespace policy | No directory mutation |
| `zip_search_preview_paths` | ZIP, search, and preview path policy | No archive I/O |
| `upload_overwrite_policy` | `SecureRoot` no-replace/replace publication, reserved names, internal upload cleanup | Temporary local filesystem |
| `upload_request_state` | `UploadFormState` transitions, duplicate/order rejection, `FolderPath`, filename, extension, and upload size limits | No DB quota or asynchronous finalizer |
| `share_request_policy` | Share path, alias, password, permission, and overwrite policy | No HTTP adapter or password hashing |
| `file_mutation_policy` | File mutation paths and namespace rules | No concurrent handler scheduling |
| `multipart_guard` | Fragmented envelope parsing, acceptance/rejection, byte preservation, and compatibility with Axum multipart parsing | Bounded bodies; no DB or upload finalizer |
| `directory_cursor` | Base64/JSON cursor decoding, canonical round trips, sort order, bounded heap selection, forward/backward pages against a reference sort | In-memory directory snapshots |
| `zip_preview` | Real ZIP bytes, independent CRC-32 and archive structure checks, data limits, preview reads and HTML escaping | Small temporary files; no network streaming |
| `auth_headers` | Cookie/Bearer parsing, duplicate and mixed credential rejection, token encoding, header-order invariance | Credential selection; no DB token lookup or password hashing |
| `recovery_journal` | Raw journal decoding, interrupted rename/delete phases, replacement inode preservation and repeatable recovery | Local temporary filesystem; simulated restart states, not power-loss injection |

## CI campaigns

`fuzz-smoke.yml` runs on every pull request and push to `main`. It validates the
corpus tooling, restores the current Git seeds, replays them, and fuzzes every
target for 30 seconds on native AMD64. It does not publish a reusable corpus or
the release fuzz status.

`fuzz.yml` runs weekly and on demand. Native AMD64 and ARM64 jobs each replay the
restored corpus, fuzz every target for 600 seconds, and minimize the result. Build
parallelism is separate from runtime parallelism: the workflows use two Cargo
build jobs and two or four fuzz workers according to runner capacity. The native
600-second statuses remain bound to the exact tested commit.

Replay and minimization each have their own wall-clock budget. A crash, assertion,
build error, or timeout fails the campaign; a successful mutation phase cannot
hide a failed replay or minimization. The runner stops later stages for the failed
target, lets other targets complete, records each command's exit code, and returns
a failing target's code. On Linux, a timeout kills the command's process group,
including Cargo and the fuzz binary.

All outcomes retain per-stage logs, crash artifacts when present, runtime corpus,
and JSON/Markdown statistics as evidence for 30 days. A failed target's corpus is
evidence for diagnosis and is never selected automatically for later campaigns.

## Fixed seeds and accumulated corpus

`fuzz/corpus/<target>/` contains reviewed regression seeds. Every target has valid
inputs, boundaries, and rejection cases. These bytes are binary artifacts in Git;
line-ending conversion is disabled. Tuple targets use the actual `arbitrary`
encoding, including its trailing length selectors. Plain text is not a substitute
for a tuple encoding. `tools/generate-fuzz-seeds.py` documents and reproduces the
curated inputs of the original nine targets, including multipart control records:

```sh
python3 tools/generate-fuzz-seeds.py --check
python3 tools/generate-fuzz-seeds.py --check --verify-rust
```

The second command also checks tuple decoding with the locally cached Rust
`arbitrary` crate. The four additional targets (`directory_cursor`, `zip_preview`,
`auth_headers`, and `recovery_journal`) have separately maintained raw-byte
fixtures. Their control bytes are documented in each target's helper module;
the seed generator does not regenerate or verify those four fixture sets. The
corpus policy check and actual fuzz replay cover all thirteen targets.

The writable corpus lives in `FUZZ_CORPUS_DIR`, normally a runner temporary
directory or `.tmp/fuzz-corpus`. Git seeds are never passed as a writable corpus.
Restore combines both prior architecture corpora with current Git seeds and
deduplicates by SHA-256. Each local runner invocation also adds current seeds, so
a new regression seed is included when reusing an existing local corpus.

After a successful campaign, each architecture publishes an immutable artifact
named `fuzz-corpus-amd64-<attempt>` or `fuzz-corpus-arm64-<attempt>`, retained for 90 days. A snapshot
contains `manifest.json` plus `corpus/<target>/<sha256>` input files. Its manifest
records the producing commit, run ID, run attempt, architecture, pinned toolchain,
complete producer target list, input-schema versions, file sizes, and hashes.
Snapshot creation requires a successful result for replay, fuzzing, and
minimization for every current target.

Restore searches successful `main` runs of this repository's `fuzz.yml`. It selects
the newest available artifact for each architecture from the same producer run,
verifies that architecture's job succeeded in its producing attempt, verifies their provenance,
checks their target/schema metadata against the files at that historical commit,
and verifies every input hash. Pull-request, foreign-repository, and failed-run
artifacts are not trusted. ZIP extraction rejects traversal, symlinks, duplicate
entries, and oversized archives. The safety ceilings are 100,000 input files and
512 MiB per snapshot; a corpus exceeding those limits needs investigation or an
explicit limit change.

Attempt suffixes prevent immutable-artifact collisions on full reruns. If only a
failed ARM64 job is rerun, restore can combine the successful AMD64 snapshot from
attempt 1 with the successful ARM64 snapshot from attempt 2. Each manifest must
match its own producing attempt, as well as the shared run ID and commit.

If no retained successful corpus exists, restore visibly reports `bootstrap` and
starts with Git seeds. Missing artifacts from runs that predate this infrastructure
and fully expired pairs allow that fallback. A partially missing/expired pair,
corrupt input, or incomplete manifest fails restore. An explicitly requested run
ID never falls back to a different run or to seeds.

`fuzz/corpus-versions.json` versions each target's input format separately from its
implementation. Bump a target's version when changing tuple fields or raw-byte
framing incompatibly. Restore skips that target's incompatible historic inputs
and records the reason; the current Git seeds remain available. New targets start
from seeds. Ordinary production-code changes keep the corpus. An existing local
runtime directory with a recorded incompatible schema is rejected; restore into
a fresh directory to migrate it. The current upload-state tuple and multipart
control format are version 2.

Minimization runs `cargo fuzz cmin` against a disposable copy. It replaces the
runtime target corpus only on success, then retains all pinned regression seeds
even if they are redundant for measured coverage. A timeout or failure leaves the
original campaign corpus available in evidence. The default 120-second replay and
minimization budgets may need deliberate increases as corpora grow; timeout
failures remain visible rather than silently skipping part of the corpus.

## Local commands

Use native Linux with Python 3.11+, Rustup, Make, and the pinned tools:

```sh
rustup toolchain install nightly-2026-07-01 --profile minimal --component rust-src --component llvm-tools-preview
cargo install --locked cargo-fuzz --version 0.13.2
python3 tools/test-fuzz-corpus.py
make fuzz-parallel
```

For a short run of one target using a fresh seed corpus:

```sh
export FUZZ_CORPUS_DIR="$PWD/.tmp/fuzz-local-short"
export FUZZ_LOG_DIR="$PWD/.tmp/fuzz-local-short-logs"
python3 tools/fuzz-corpus.py restore --seed-only --destination "$FUZZ_CORPUS_DIR"
FUZZ_MAX_TOTAL_TIME=30 sh tools/run-fuzz-targets.sh upload_request_state
```

Restore requires an empty destination to avoid mixing unchecked or stale files.
Subsequent runner invocations can reuse the restored directory. To fetch the
trusted prior corpus, use an authenticated `gh` CLI with repository contents/actions
read access:

```sh
python3 tools/fuzz-corpus.py restore \
  --repository alexhaberl/VaultLink \
  --destination "$PWD/.tmp/fuzz-restored"
```

Add `--run-id 123456789` to require a particular successful producer. For offline
inspection of already extracted snapshots, replace `--repository` with one or
more `--snapshot /absolute/path/to/snapshot` arguments. Local snapshots receive
the same manifest/hash checks; repository/run authorization comes from the GitHub
restore path.

| Environment variable | Default in the runner | Purpose |
| --- | --- | --- |
| `FUZZ_NIGHTLY_TOOLCHAIN` | `nightly-2026-07-01` | Rustup toolchain |
| `FUZZ_MAX_TOTAL_TIME` | `600` | Mutation seconds per target, excluding replay and cmin |
| `FUZZ_JOBS` | `1` (`make` uses `4`) | Parallel targets; independent of `CARGO_BUILD_JOBS` |
| `FUZZ_BUILD_TIMEOUT` | `1800` | Initial build wall-clock seconds; campaign/smoke CI uses `2400` |
| `FUZZ_REPLAY_TIMEOUT` | `120` | Replay wall-clock seconds; also campaign startup allowance |
| `FUZZ_CMIN_TIMEOUT` | `120` | Corpus minimization wall-clock seconds |
| `FUZZ_CORPUS_DIR` | `.tmp/fuzz-corpus` | Writable accumulated inputs |
| `FUZZ_LOG_DIR` | `.tmp/fuzz-logs` (`make` uses `/tmp/vaultlink-fuzz-logs`) | Logs and campaign summaries |
| `FUZZ_COVERAGE_DIR` | `.tmp/fuzz-coverage` | Coverage report output |
| `FUZZ_COVERAGE_TIMEOUT` | `900` | Coverage build and replay wall-clock seconds per target; the first target also gets `FUZZ_BUILD_TIMEOUT` (coverage default `2400`) |

All timeout/worker values must be positive integers. The campaign wall-clock
allowance is mutation time plus `FUZZ_REPLAY_TIMEOUT`; the mutation budget remains
the requested number of seconds. Cargo-fuzz itself may wrap a binary's exit
status; the runner preserves the command status it receives and keeps the full
underlying diagnostic in the stage log.

## Statistics and source coverage

`FUZZ_LOG_DIR/summary.json` and `summary.md` report per-target corpus file and byte
counts before the campaign, after mutation, and after minimization, plus executed
inputs, executions/second, libFuzzer edges/features, and peak RSS when reported.
Missing metrics remain unknown, not zero. `restore.json` and the summary identify
the corpus source and any schema migrations. Successful CI runs retain the same
logs as failures. Compare these metrics when checking whether a target reaches
new behavior or spends most executions rejecting input.

libFuzzer edge/feature counts are feedback metrics, not source-line coverage.
`fuzz-coverage.yml` is a separate reporting workflow, triggered by a successful
`main` campaign or manually with its run ID. It verifies the producer, checks out
that exact commit, combines both architecture input corpora, and generates fresh
native AMD64 profiles with `cargo fuzz coverage`. It does not merge profiles from
different architectures and does not publish or block the release fuzz statuses.

The report uses the matching toolchain's `llvm-cov`, includes dead code, and emits
per-target HTML, LCOV, JSON, text, and per-module summaries. Its source scope is
Rust files under `src/`, excluding fuzz-only helper modules, dedicated test files
and directories, the fuzz harnesses, and dependencies. It is explicitly an AMD64 measurement even when ARM64 inputs
contribute. Reports are retained for 30 days. There is initially no global
percentage threshold; use module-level gaps to choose meaningful seeds and
assertions before adding targeted requirements.

Only source files represented in the instrumented binary appear in the report;
uninstantiated generic code and application startup outside that binary are not
measured by this target's coverage.

To generate the same report locally after restoring a corpus:

```sh
export FUZZ_CORPUS_DIR="$PWD/.tmp/fuzz-restored"
sh tools/run-fuzz-coverage.sh
```

Open `.tmp/fuzz-coverage/index.html`. Passing target names limits the local report
to those targets. Coverage does not replace the independent test-coverage job or
the deterministic tests of concurrency and durable filesystem behavior.
