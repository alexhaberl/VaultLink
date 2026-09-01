# v0.7.0 native-package release checklist

This checklist is intentionally separate from the withdrawn 0.5.0 historical
record and the in-progress 0.6.0 release checklist. It applies to the
unreleased 0.7.0 monitoring feature line, which must not be merged or published
before the signed `v0.6.0` package release is public. Every item remains
fail-closed until checked against the exact release commit.

## Feature and schema contract

- [ ] A fresh database is schema 7 and records migrations 2 through 7.
- [ ] Every supported schema 1 through 6 migrates transactionally to schema 7;
  the injected 6→7 failure leaves a complete, valid schema-6 database.
- [ ] Schema validation rejects missing/extra service-token objects, malformed
  hashes, unsupported scope bits, corrupt history/fingerprint state, future
  schemas, and non-empty unversioned databases.
- [ ] Service-token persistence contains only the SHA-256 hash and metadata;
  no plaintext, ciphertext, keyring entry, or token fragment exists.
- [ ] Token creation enforces trimmed unique names, 1–80 characters, 256-bit
  runtime entropy, the versioned format, optional expiry, and the global
  64-entry cap including expired tokens.
- [ ] Creation, single revocation, and revoke-all each roll back completely
  when their required Security-priority audit cannot be written.
- [ ] Secret/keyring rotation leaves service-token rows unchanged and existing
  tokens valid.

## Authentication and redaction

- [ ] Only `/api/v2/monitoring/summary` and
  `/api/v2/monitoring/shares` accept `monitoring:read` bearer credentials;
  both also accept a currently active MFA-confirmed administrator session.
- [ ] Duplicate, comma-joined, malformed, wrong-length, wrong-character, query,
  cookie, alternate-header, and mixed cookie/bearer credentials fail closed
  with the documented uniform errors.
- [ ] Unknown, expired, and revoked credentials are indistinguishable `401`
  responses; missing scope is `403`; 120 requests per effective client IP per
  minute produces `429` plus `Retry-After`.
- [ ] The complete negative route matrix proves that service tokens cannot use
  existing Share, file, administrator, settings, audit, session, public, or
  HTML routes, including the credential-bearing `/api/v2/shares` response.
- [ ] Monitoring SQL projections and DTOs cannot contain Share token/hash/
  ciphertext, path, alias, URL, or password hash. JSON, HTML, error, audit,
  diagnostics, trace, journald, and proxy-log probes contain neither token
  values nor Authorization headers.
- [ ] Share status counters use the mutually exclusive priority inactive →
  expired → download-limit-reached → available; `protected` overlaps. A failed
  capacity probe returns `storage: null` without losing other measurements.
- [ ] Redacted Share pagination is newest-ID-first, enforces limit 1–200 and the
  five documented filters, and remains stable under concurrent revocation and
  last-use updates.

## Administrator and recovery surfaces

- [ ] Service-token JSON and HTML administration require an active
  MFA-confirmed cookie session and CSRF; creation also atomically verifies the
  unchanged current password hash.
- [ ] German and English UI tests cover navigation, escaping, default one-year
  expiry, explicit unlimited-token warning, token inventory/status, CSRF,
  password reauthentication, one-time no-store display, copy behavior, and
  revocation by another active administrator.
- [ ] `revoke-all-service-tokens (--config PATH | --database PATH) --all`
  rejects ambiguous input, runs only against the selected local database,
  audits as `local_recovery`, and prints only the deleted count.
- [ ] The manual-restore drill keeps traffic closed, restores the old unit,
  revokes all restored tokens with VaultLink stopped, issues replacements,
  updates clients, and reopens traffic only after old-token rejection.
- [ ] A normal verified upgrade rollback preserves service-token hashes and
  does not revoke tokens automatically.

## Regression, package, and release evidence

- [ ] `cargo fmt --check`, Clippy, locked unit/integration tests, coverage,
  dependency audits, fuzz compilation/campaigns, secret scan, and policy checks
  pass at the exact candidate commit.
- [ ] Route inventory and API smoke include all new routes, token creation,
  monitoring reads, redaction, negative route access, restart persistence,
  revocation, and log leak checks.
- [ ] Every offline native-package gate performs a real populated schema-6→7
  migration and checks empty service-token state plus history 7; its separate
  upgrade-safety suite verifies backup and rollback behavior. Every full-system
  distro VM gate additionally verifies the populated schema-6 backup, rolls it
  back, and returns cleanly to schema 7.
- [ ] Upgrade, backup, automatic recovery, explicit rollback, runtime guard,
  package lifecycle, and load/soak gates remain green for all nine targets.
- [ ] `Cargo.toml`, `Cargo.lock`, health/monitoring version output, README,
  SECURITY, threat model, packaging, upgrade/restore documentation, SBOMs,
  changelog, and release metadata all identify 0.7.0/schema 7.
- [ ] No static realistic service token is committed; test credentials are
  assembled from runtime randomness or non-secret components and the unchanged
  full-history secret scan passes.
- [ ] Home Assistant code and HACS metadata remain exclusively in the separate
  `alexhaberl/vaultlink-home-assistant` repository and are not part of this
  release artifact.
