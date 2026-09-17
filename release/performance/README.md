# Retired comparative performance qualification

On **2026-09-17**, the maintainer retired the comparative **19-metric performance
test for every release from 0.7.0 onward**, including 0.7.1 and future patch,
minor and major releases. [`policy.json`](policy.json) is authoritative.
This decision replaces the 2026-09-06 deferral that applied only to 0.7.0;
it does not postpone the test to another release.

## Release behavior

Candidate, soak, final evidence and tag phases do not require a baseline lock,
five baseline/candidate measurements, a `vaultlink/performance` status or a
performance receipt for these versions. The supported-release manifest lists
the eleven remaining release gates and rejects a comparative performance gate
as an extra entry. No baseline or measured comparative pass is fabricated.

QUAL-001 records the accepted retirement decision. Effective qualification
reports use schema 2, include `performance_retirement`, leave
`performance_receipt` null and list QUAL-001 as accepted rather than resolved
by measurement. The archived 0.7.0 candidate ledger and published release
records retain their historical decision and evidence.

The following qualification is still required against one frozen commit and
the exact package binary:

- Native amd64/arm64 CI, both full fuzz campaigns and all nine native packages.
- Package reproducibility, all nine full-system VM gates and candidate preflight.
- Existing native/VM load, admission, latency, RSS, integrity and transfer checks.
- A fresh security audit before soak start, the complete 72-hour soak, and
  final evidence/tag verification, including the fresh publication audit.

See the [0.7.1 release checklist](../../docs/RELEASE-CHECKLIST-0.7.1.md) and
[soak-runner procedure](../../docs/SOAK-RUNNER.md). Removing the comparison does
not replace or shorten the 72-hour soak.

## Historical tools and records

The original reference commit was
`a390dd9a2210a2e227655a562c541b2b4ebd493c`. Its binary rejected signed CIFS
mounts, and the complete executable measurement suite was never implemented.
No replacement baseline is registered.

The offline checker, collector and producer code remain for historical
analysis and evidence-boundary regression tests. Their synthetic unit-test
fixtures are not measurements. The manual performance workflow checks policy
before entering its protected environment: for retired versions it skips
collection and verification and publishes no performance status. Existing
SSH secrets and host files are not used by the remaining release gates.

A missing or malformed policy and a non-release package version fail closed.
Numeric version comparison covers all releases at or above 0.7.0; there is no
CLI or environment switch that can silently change the committed decision.
