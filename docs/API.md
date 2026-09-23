# HTTP routes and JSON API

[Back to README](../README.md)

This reference covers the supported **0.7.1** release. Monitoring and
service-token routes are new in **0.7.0** and are unavailable in the
superseded **0.6.0** release. The Share-search change is marked separately.
Health probes and the `/api/v2` prefix are already available in 0.6.0.

## Browser routes and authentication

| Route | Method | Purpose |
|---|---:|---|
| `/login`, `/mfa` | GET/POST | two-stage administrator authentication |
| `/logout` | POST | end the administrator session |
| `/locale` | POST | store German/English selection in the hardened locale cookie |
| `/admin` | GET | root-confined file browser |
| `/admin/account` | GET | current user and own credential actions |
| `/admin/account/password` | POST | change own password after reauthentication |
| `/admin/account/mfa/start`, `/admin/account/mfa/confirm` | POST | staged TOTP replacement |
| `/admin/account/security-keys/register/start`, `/admin/account/security-keys/register/finish` | POST | register WebAuthn/FIDO2 security keys |
| `/admin/preview`, `/admin/preview/raw` | GET/HEAD | administrator preview page/raw media |
| `/admin/shares` | GET/POST | list and create Shares |
| `/admin/admins` | GET/POST | list and create administrators |
| `/admin/service-tokens` | GET/POST | **Since 0.7.0.** List/create monitoring tokens and revoke them through the per-token POST route |
| `/admin/settings` | GET/POST | runtime settings |
| `/admin/audit` | GET | audit events |
| `/v/:token`, `/s/:alias` | GET | public Share landing page |
| `/v/:token/unlock` | POST | unlock a password-protected Share |
| `/v/:token/download`, `/v/:token/download.zip` | GET/HEAD | streamed file or ZIP transfer |
| `/v/:token/upload` | POST | streamed public upload |
| `/admin/files/upload/operations`, `/v/:token/upload/operations` | POST/GET `/:upload_id` | create and inspect an upload operation |

`max_downloads` counts completed content transfers (download, ZIP, counted preview), not public metadata/landing requests or uploads. `HEAD` returns metadata only when the equivalent `GET` could begin under the current transfer session and does not itself consume quota.

The JSON API under `/api/v2` normally uses the same secure cookies, MFA sessions, CSRF rules, SecureFS access, SQLite operations, and audit events as the HTML UI. Mutating administrator API routes require `X-CSRF-Token`. Since 0.7.0, the only bearer-token exception is read-only access to `/api/v2/monitoring/summary` and `/api/v2/monitoring/shares` with an instance-wide `monitoring:read` token. Every `/api/v2` error message is English regardless of locale cookie or `Accept-Language`.

For those 0.7.0 monitoring routes, bearer authentication is deliberately narrow: send exactly one `Authorization: Bearer <token>` header, never a query parameter or cookie. Supplying both an administrator session cookie and a bearer credential is rejected as ambiguous. Unknown, expired, and revoked credentials share the same `401 unauthorized` response; missing scope is `403 insufficient_scope`; the monitoring limit is 120 requests per effective client IP per minute and `429` includes `Retry-After`. VaultLink does not enable CORS for these routes. Successful polling reads are not written to the audit log.

After `/api/v2/session/mfa`, clients must retain both the rotated `Set-Cookie` value and returned `csrf_token`; the pre-MFA token becomes invalid. Before a password-protected Share is unlocked, public metadata returns only `{"locked":true}`. The unlock response returns an upload CSRF token sent as multipart field `csrf` by browser forms or `X-VaultLink-Upload-CSRF` by API clients.

## JSON API routes

| Route | Method | Purpose |
|---|---:|---|
| `/api/v2/health` | GET | compatible process/version liveness alias |
| `/api/v2/health/live` | GET | cheap process/version liveness |
| `/api/v2/health/ready` | GET | database and descriptor-bound storage readiness |
| `/api/v2/session/login`, `/api/v2/session/mfa`, `/api/v2/session/logout` | POST | session lifecycle |
| `/api/v2/session/me` | GET | current session |
| `/api/v2/files` | GET/PATCH/DELETE | JSON file browser and mutations |
| `/api/v2/shares` | GET/POST | list and create Shares |
| `/api/v2/shares/:id` | PATCH/DELETE | update and delete a Share |
| `/api/v2/monitoring/summary` | GET | **Since 0.7.0.** Redacted instance, Share, transfer, and storage summary; MFA session or `monitoring:read` token |
| `/api/v2/monitoring/shares` | GET | **Since 0.7.0.** Redacted, cursor-paginated Share monitoring data; MFA session or `monitoring:read` token |
| `/api/v2/service-tokens` | GET/POST | **Since 0.7.0.** List/create tokens; MFA/CSRF administrator-only; plaintext is returned only by create |
| `/api/v2/service-tokens/:id` | DELETE | **Since 0.7.0.** Revoke a token; MFA/CSRF administrator-only |
| `/api/v2/admins` | GET/POST | administrator lifecycle |
| `/api/v2/settings` | GET/PUT | runtime settings |
| `/api/v2/audit` | GET | paginated audit events |
| `/api/v2/public/shares/:token` | GET | public Share metadata |
| `/api/v2/public/shares/:token/unlock` | POST | unlock protected Share |
| `/api/v2/public/shares/:token/download` | GET/HEAD | safe streamed download |
| `/api/v2/public/shares/:token/upload` | POST | safe streamed upload |
| `/api/v2/public/shares/:token/upload/operations` | POST/GET `/:upload_id` | create and inspect an upload operation |
| `/api/v2/public/shares/:token/preview` | GET | safe preview |
| `/api/v2/public/shares/:token/download.zip` | GET | safe ZIP transfer |

`GET /api/v2/shares` accepts `limit` (default 50, range 1–200), `cursor`, `q`,
`status=all|active|protected|expired|limit|inactive`, and
`sort=newest|oldest`. It returns
`{"shares":[...],"next_cursor":<id|null>}`. There is no v1 compatibility router.

**Since 0.7.0:** `q` is trimmed and must contain at least three
Unicode characters when nonempty; an omitted, empty, or whitespace-only query
lists Shares without a search filter. Queries exceeding 256 UTF-8 bytes are
rejected. Invalid queries return HTTP `400 bad_request`. The same minimum
length applies to the administrator Share search; it does not describe file search.

JSON errors have this envelope:

```json
{ "error": { "code": "forbidden", "message": "..." } }
```

### Upload operation IDs (breaking change)

Every new logical upload, including API uploads, must first create an operation with `POST` to the corresponding `/upload/operations` route. The response is HTTP `201` with `upload_id`, `expires_at`, and `status_url`. Administrator creation requires an MFA session and `X-CSRF-Token`; a password-protected public Share requires its unlock session and `X-VaultLink-Upload-CSRF`. Each status `GET` rechecks the current session or Share permission and unlock state.

Send the returned ID as `Idempotency-Key` on the existing upload route, or as multipart `upload_id` before the file field. When both are sent, they must match. Missing or conflicting IDs return `400`; unknown, foreign, or expired IDs return `410`. Clients of earlier versions that POST directly to `/api/v2/public/shares/:token/upload` must change to this two-step flow. IDs do not replace authentication, Share authorization, or CSRF proof.

`GET status_url` returns `state` (`ready`, `processing`, `retryable`, `completed`, `rejected`, or `outcome_unknown`), `expires_at`, and, for completed or rejected operations, `result`. Rejected results contain a stable reason code rather than localized response text. A simultaneous upload with a processing ID returns `409 upload_in_progress`, `status_url`, and `Retry-After: 1`. A repeated completed upload with identical file bytes, filename, path, and overwrite choice returns its original result without republishing or charging quota. A differing request returns `409 upload_id_conflict`. Compare content using a streamed SHA-256 and length; multipart boundaries and CSRF values are immaterial. A terminal `outcome_unknown` cannot be resent. If an upload response is lost or malformed, read `status_url` before offering a retry. Resend the exact same request and ID only after status confirms `ready` or `retryable` and the user requests it.

Completed results remain queryable for 24 hours after completion. Unused and safely retryable IDs expire 24 hours after creation. Upload JSON has a canonical optional `warnings` array in storage-then-audit order: `storage_durability_uncertain`, `audit_durability_uncertain`. The legacy singular `warning` field is deprecated. Classic redirect responses also provide `X-VaultLink-Upload-Warnings`; older durability headers retain their previous meaning. `directory_uncertain` means that a directory may be partial and does not claim the file was uploaded.

Internal absolute paths, password hashes, session/unlock/preview/transfer hashes, and TOTP secrets are not returned. TOTP secrets are shown once after administrator creation or MFA reset.

**Since 0.7.0:** create service tokens from **Service tokens** in the administrator navigation. Names are trimmed and unique, the inventory is capped at 64 entries including expired entries, and the default UI expiry is one year. An unlimited token requires the explicit no-expiry warning option. Store the one-time value in the monitoring client's secret store and rotate it by creating a replacement, updating the client, and revoking the old entry. The complete response and authentication contract is in [docs/MONITORING-API.md](MONITORING-API.md). Home Assistant belongs in the separate `alexhaberl/vaultlink-home-assistant` HACS repository; no integration code is bundled with VaultLink.

All three health routes are unauthenticated. Liveness does not touch SQLite or storage. Readiness returns `503` with `{"ok":false,"version":"..."}` when either dependency is unavailable, while details are written only to structured logs. Operators and orchestrators should use `/api/v2/health/live` for liveness and `/api/v2/health/ready` for traffic admission and upgrade checks.
