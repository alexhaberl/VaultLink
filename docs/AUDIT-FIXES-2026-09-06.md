# Audit fixes — 2026-09-06

Implemented on `vaultlink/audit-fixes`, based on current main
`440346dc41c21811393029a180e29f713efe5193` (PR #160). Main was fetched again
before final validation and still identified this commit. The original main
checkout and operational instances were left untouched. Docker containers used
copies of the worktree or a read-only source mount and isolated test data.

## Finding coverage

| # | Finding | Implementation and regression coverage |
|---|---|---|
| 1 | Cancelled HTML scans released admission early | `ScanAdmission` keeps client/global permits inside blocking workers across search, snapshot loading and fallback. Deterministic cancellation, release and panic tests cover worker lifetime. |
| 2 | Login counters exposed account existence | Web/API share one origin budget for valid, invalid, known and unknown usernames. Defaults are 5 attempts per 300 seconds per IP or IPv6 /64, plus 25 per account. Churn, parallel admission, overflow/expiry and account-denial tests cover the policy. |
| 3 | Oversized login/audit data | Invalid names become a fixed actor plus byte length and SHA-256. Central audit validation enforces UTF-8 byte limits; required contexts and predictable file-publication fields are checked before mutation. Historical reads use bounded SQL projections without rewriting history. HTML cursors emit v2 id-only tokens, accept bounded v1 tokens and reset missing anchors. Tests include 900,000-byte Web/API inputs, audit rollback, historical sorted traversal and cursor compatibility. |
| 4 | Transient `openat2` contention surfaced incorrectly | Retry EAGAIN at most eight times with 1 ms between attempts and unchanged confinement flags. Exhaustion maps to HTTP 503, Retry-After 1 and API `storage_busy`. Other errors retain their semantics. Tests cover retry count, eventual success, non-EAGAIN termination and response headers. |
| 5 | Transfer cleanup scanned counted grants | Schema 9 adds `idx_transfer_grants_pending_id WHERE counted=0`; cleanup uses separate expired-lease, expired-grant and orphan statements. Heartbeat exclusions remain. Tests verify atomic migration rollback, corrupted-index rejection, mixed cleanup behavior and actual statement counters at 100,000/300,000 grants. |
| 6 | Nullable cursor conditions defeated keyset seeks | Share/monitoring first and later pages use distinct predicates. FTS5 receives its own rowid bounds and order, avoiding a full hit-list sort. Both directions, deleted cursors, short search and FTS are checked at 300,000 shares using production SQL and SQLite work counters. |
| 7 | Performance evidence was not bound to the candidate | Schema-v2 runs bind commit, before/after binary hash, package target, Packages run, candidate preflight and producer digest. A protected SSH importer and Actions producer validate the actual package and immutable artifact metadata. Consumers re-download and verify repository, workflow, commit, run, current attempt, expiry and artifact SHA-256 against a reviewed baseline lock. Offline negative tests plus a read-only check against a real GitHub artifact passed. |
| 8 | Circular release/soak qualification | Explicit candidate, soak and evidence/tag phases defer only their downstream qualification. Soak requires verified performance; final phases additionally require the exact-binary 72-hour soak. Effective qualification is archived as an external artifact, including both receipts, without a post-soak source change. Legacy require-ready remains strict. |
| 9 | Aggregates referenced files outside the bundle | Aggregation validates all inputs, copies unchanged bytes to adjacent hash-derived files and atomically publishes the aggregate last. Comparisons re-hash and recompute all source runs. Tests cover relocated bundles, corrupt inputs, identity mismatches and incomplete publication. |
| 10 | WebAuthn encryption documentation was inaccurate | SECURITY.md now distinguishes serialized public verification records from encrypted TOTP/share-token secrets and authenticator-held private keys. No credential-format migration. |

## Validation

- Rust 1.98.0 on Debian 13: **700 library tests and 25 executable tests passed**;
  one existing release timing diagnostic is intentionally ignored by the normal suite.
- `cargo fmt --all -- --check` and strict all-target/all-feature Clippy passed,
  including perf, redundant-clone and needless-pass-by-value checks. Changed
  include-based Rust files were formatted explicitly as well.
- The optimized release binary built successfully. All 13 fuzz targets compile;
  corpus/workflow policies and curated seed validation pass. Long fuzz campaigns
  on both native release architectures remain part of release qualification.
- Architecture, refactoring-contract, release-state, performance-evidence and
  release-evidence regression checks pass. The intentional schema/auth/query
  changes are reflected in the reviewed contract digests; historical schema
  fingerprints, secret AAD and route inventory remain intact.
- Pinned Actionlint 1.7.12, complete ShellCheck and the supply-chain policy pass.
  JavaScript syntax and CSS checks pass.
- Cargo Audit 0.22.2 scanned 345 locked dependencies using the current advisory
  database, with the repository's unchanged RUSTSEC-2023-0071 exception.
- Gitleaks 8.30.0, verified against its official release digest, found no leaks
  in **271 commits** or the complete worktree source snapshot. Existing history
  ignore rules were unchanged.
- The final binary passed unprivileged API/setup smoke tests. A populated API
  database was downgraded only inside an isolated test container to the exact
  schema-8 fixture, then successfully migrated by the real startup path to
  schema 9; readiness, index definition, history and integrity were checked.
- Existing upgrade/rollback fault injection and signed-package update safety
  tests pass; the latter exercise all nine target formats/identities.
- A real Debian 13 amd64 package and normalized SBOM were built and its payload
  was verified against the tested binary. Package lifecycle and API migration
  checks pass. The complete offline Debian package smoke also passes with
  CPUs 0–3, a separate 4-GiB load-client tmpfs and an empty server volume,
  including the 50/20/5 load profile, real migration and upgrade/rollback checks.

The local release binary SHA-256 is
`49d4afc655a3a1ec3eff14307f65b24ebd251a820154439cd4a003981934a580`.
Build/test logs are retained locally under `.tmp/audit-results/`; they are
implementation validation, not protected release qualification artifacts.

## Database work measurements

Production cleanup statements required 14–21 SQLite VM steps and zero full-scan
steps with both 100,000 and 300,000 counted live grants. Production share and
monitoring queries returned 101 rows at first and deep pages with bounded work:
about 3,646–4,664 VM steps across the checked variants. The FTS regression test
also requires zero sorting operations. These are isolated SQL probes, not HTTP
or CIFS performance qualification.

## Remaining operational release qualification

The source fixes do not constitute a published release. Before freezing a
release candidate, configure the protected `release-performance` environment,
install the reviewed read-only collector, measure the real five-run historical
baseline and register/review its `baseline.lock.json`. Then qualify the frozen
candidate through native/package/VM/fuzz gates, exact-binary performance and the
72-hour CIFS soak. See `release/performance/README.md` for the executable sequence.

No fabricated baseline lock, candidate measurements or success status was
created. QUAL-001 and QUAL-006 remain open in the source manifest; final release
phases resolve them only from verified external evidence. Native ARM and the
remaining distribution package/VM jobs were not run locally. No workflow was
dispatched, no operational service was changed and no release was published.

GitHub artifact fields were checked against the
[official Actions artifact API](https://docs.github.com/en/rest/actions/artifacts)
and verified against an existing immutable artifact without modifying GitHub.
