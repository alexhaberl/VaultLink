# Audit regression checks

These changes start from main `34b3569` and address the four audit findings:
blocking preview ownership, indexed Share listing, shared display counts, and
complete Rust formatting. Authorization, expiry checks and transfer quotas still
read current database state. Only displayed counts accept a one-second delay.

## Running the checks

`make format-check` runs Cargo formatting and explicitly checks every tracked
Rust file with the pinned toolchain and package/workspace edition. This includes
`include!` fragments that Cargo fmt does not visit. Its negative fixture first
passes Cargo fmt, then fails the complete checker; formatting it makes both pass.
Use `python3 tools/check-rust-format.py --fix` to apply the same formatting locally.
New Rust files must be staged so Git includes them in the inventory.

The normal `cargo test --locked --all-targets` suite includes actual TCP aborts
for Web/API/Admin text previews, retained memory and transfer reservations,
read failures, panic, oversize and discarded response bodies. ZIP planning,
materialization and direct-stream cancellation/error scenarios run through both
Web and API adapters. The API has separate archive/header/cookie, permission and
capacity assertions. Admin raw previews cover GET/HEAD, valid/invalid ranges,
lengths, media headers, empty/missing files, size limits and authentication.
Global test hooks are serialized where their paths overlap; their blocking waits
and asynchronous completion probes have deadlines.

`VAULTLINK_BIN="$PWD/target/debug/vaultlink" python3 tools/runtime-smoke.py`
exercises the real process, readiness, reopening, invalid configuration, an
occupied port, valid/invalid TLS files, and clean SIGTERM shutdown. It requires
Linux, OpenSSL and findmnt. TLS uses the real production configuration rules,
including audited local filesystem identity for storage and SQLite. Native CI
uses its local filesystem. In Docker, provide an isolated ext4 volume through
`VAULTLINK_TLS_FIXTURE_DIR`, writable by the account running the smoke. Container
overlay storage is deliberately rejected by the production mount policy.

## Coverage

Install `llvm-tools-preview` and the pinned `cargo-llvm-cov` **0.8.6**, then run
`make coverage`. The script follows the tool's
[external-test procedure](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.8.6/README.md#get-coverage-of-external-tests):

1. Select `target/coverage`, evaluate `cargo llvm-cov show-env --sh`, and clean
   that coverage workspace.
2. Run all package test targets/features and build the instrumented server.
3. Write `coverage/unit.lcov` and temporarily set aside its raw profiles.
4. Run runtime, setup and API process-smokes with the instrumented `VAULTLINK_BIN`
   and unique process/module profile names; write `coverage/process.lcov`.
5. Restore the unit profiles and write `coverage/combined.lcov` with the unchanged
   **81% global line floor**. CI uploads all three reports, including on failure.

`release/module-coverage.json` records the achieved, rounded-down line and
function floors for the four critical modules and the changed/new production
helpers. The checker uses LCOV's `LF/LH/FNF/FNH` summaries; individual `FNDA`
entries include instantiation groups and must not be counted as distinct source
functions. Missing files, zero coverage, malformed floors and local regressions
fail. `tools/test-module-coverage.py` verifies those failure cases.

The initial local combined measurement is **37,181/44,045 lines (84.42%)** and
**3,832/4,561 functions (84.02%)**. Unit coverage alone is **83.56% lines**;
process coverage alone is **26.63%**. The reports have the same source scope.
Branch coverage remains separate because the pinned tool requires Nightly for
that mode; no toolchain pin was changed for this implementation.

| Critical module | Combined lines | Required floor |
| --- | ---: | ---: |
| `src/server/runtime.rs` | 56.87% | 56% |
| `src/web/preview_zip.rs` | 72.16% | 72% |
| `src/api/public_transfer/zip.rs` | 90.67% | 90% |
| `src/web/files/preview.rs` | 81.32% | 81% |

## Correctness and performance evidence

The new TCP preview regressions failed for all three adapters against the
original main production code, then passed with the resource-ownership fix.
Database tests compare optimized candidate selection with an independent,
simple reference query at 100,000 and 300,000 Shares, across every status, both
orders, deleted/deep cursors and dense/rare/missing FTS combinations.

In the reproduced no-match cases, protected and exhausted status queries take
13 VM steps at either database size. Expired no-match queries take 10,535 steps
at either size; their nearby probe examines at most 404 candidates for a
100-row page. Dense FTS plus no-match status filters also retain constant work.
The existing deep-page limits remain enforced (under 8,000 VM steps, at most
101 scan steps, no sort for the previously optimized all-status paths).

Run the full HTML timing fixture explicitly in release mode:

```sh
cargo test --release --locked --lib html_share_display_benchmark -- --ignored --nocapture
```

It creates correctly encrypted Shares outside the timing interval and consumes
the entire HTML response. Three cold/warm pairs per page gave these local ranges
in the 8-CPU Docker test environment; cold means an expired count snapshot,
not a cold operating-system page cache:

| Shares | Page | Cold snapshot | Warm snapshot |
| ---: | --- | ---: | ---: |
| 100,000 | Shares | 13.8–15.4 ms | 1.06–1.11 ms |
| 100,000 | Files | 13.1–13.9 ms | 0.20–0.27 ms |
| 300,000 | Shares | 39.1–44.7 ms | 1.00–1.05 ms |
| 300,000 | Files | 36.8–38.3 ms | 0.24–0.32 ms |

These measurements cover application behavior, not release qualification of a
specific CIFS deployment. Native package/update gates, CIFS validation and the
72-hour release qualification retain their existing distinct roles. Schema 10
and rollback requirements are documented in `UPGRADE-ROLLBACK.md`.
