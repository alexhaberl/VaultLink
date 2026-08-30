# Monitoring API

VaultLink 0.7.0 exposes two read-only resources for local monitoring clients.
The intended first client is the separate Home Assistant HACS integration;
VaultLink itself contains no Home Assistant code.

## Authentication boundary

Both monitoring routes accept either one currently active MFA-confirmed
administrator session cookie or one service token with the fixed
`monitoring:read` scope. They never accept both on one request. Service tokens
are sent only as exactly one HTTP header:

```text
Authorization: Bearer <one-time-service-token-value>
```

The scheme is ASCII-case-insensitive and is followed by exactly one ASCII
space. Duplicate or comma-joined Authorization values and mixed cookie/bearer
authentication return `400 ambiguous_authentication`. Malformed, unknown,
expired, and revoked credentials return the same `401 unauthorized`; a token
without the required scope returns `403 insufficient_scope`. There is no CORS
opt-in and no query, cookie, or alternate-header token transport.

Monitoring is limited to 120 requests per effective client IP per minute.
`429 rate_limited` includes a `Retry-After` header. Successful reads are not
audited; service-token `last_used_at` is updated at most once every five
minutes.

## Instance summary

`GET /api/v2/monitoring/summary` returns:

```json
{
  "generated_at": "2026-08-30T12:00:00Z",
  "version": "0.7.0",
  "shares": {
    "total": 10,
    "available": 6,
    "inactive": 1,
    "expired": 2,
    "download_limit_reached": 1,
    "protected": 3
  },
  "transfers": {
    "month": "2026-08",
    "download": 42,
    "zip_download": 3,
    "preview": 11,
    "statistics_started_at": "2026-08-01T00:00:00Z"
  },
  "storage": {
    "free_bytes": 1000000000,
    "total_bytes": 2000000000
  }
}
```

Status counters are mutually exclusive in the order inactive, expired,
download-limit-reached, available. `protected` overlaps those counters. If the
capacity probe fails, `storage` is `null` and the remaining measurements are
still returned.

## Redacted Shares

`GET /api/v2/monitoring/shares` accepts `limit` (default 50, range 1–200), an
exclusive numeric `cursor`, and
`status=all|available|inactive|expired|download_limit_reached`. Results are
always sorted by descending Share ID:

```json
{
  "generated_at": "2026-08-30T12:00:00Z",
  "shares": [
    {
      "id": 17,
      "status": "available",
      "permission": "download_only",
      "is_directory": true,
      "password_protected": false,
      "created_at": "2026-08-01T00:00:00Z",
      "expires_at": null,
      "download_count": 4,
      "max_downloads": 20,
      "max_upload_size_bytes": null,
      "uploaded_bytes": 0,
      "max_upload_total_size_bytes": null,
      "uploaded_files": 0,
      "max_upload_files": null
    }
  ],
  "next_cursor": null
}
```

The SQL projection and response type do not contain a Share token or
ciphertext, path, alias, URL, or password hash. The existing
`GET /api/v2/shares` remains administrator-session-only because it returns
capability-bearing management data.

## Administrator lifecycle

These endpoints accept only an active MFA-confirmed administrator cookie;
mutations also require `X-CSRF-Token`:

- `GET /api/v2/service-tokens` returns
  `{"service_tokens":[{id,name,created_by,scope,created_at,expires_at,last_used_at,status}]}`.
- `POST /api/v2/service-tokens` accepts `name`, RFC 3339 `expires_at` or `null`,
  and `current_password`. It returns `201` with the same flattened metadata
  plus one-time `token`, and `Cache-Control: no-store`.
- `DELETE /api/v2/service-tokens/{id}` returns `204` after atomic revocation
  and required audit.

No list or later response contains the plaintext or hash. The inventory is
capped at 64 rows including expired rows; revoke old entries before creating
more. Token creation and revocation are atomic with their Security-priority
audit records.

## Errors

Errors use the normal v2 envelope:

```json
{"error":{"code":"unauthorized","message":"Authentication required"}}
```

Clients must treat the code and HTTP status as authoritative, must not include
the credential in diagnostics, and must honor `Retry-After` after `429`.
