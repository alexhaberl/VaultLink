# Fuzz coverage matrix

VaultLink's fuzz targets call production parsers and policy components. They do
not claim to cover middleware scheduling, SQLite transaction interleavings,
Tokio cancellation, or filesystem races; those boundaries are covered by the
deterministic integration and Docker smoke tests in the release gates.

| Target | Production surface exercised | Deliberate boundary |
| --- | --- | --- |
| `path_normalization` | public path normalization | no filesystem lookup |
| `byte_range` | HTTP byte-range parser | no response streaming |
| `filename` | public/admin filename policy | no directory mutation |
| `zip_search_preview_paths` | ZIP, search, and preview path policy | no archive I/O |
| `upload_overwrite_policy` | `SecureRoot` no-replace/replace publish policy | temporary local filesystem only |
| `upload_request_state` | `UploadFormState`, upload path/name/extension/size policy | no Axum multipart, DB quota, or async finalizer |
| `share_request_policy` | share path, alias, password, permission, and overwrite production policy | no HTTP adapter or password hashing |
| `file_mutation_policy` | file mutation path and namespace rules | no concurrent handler scheduling |
| `multipart_guard` | streaming multipart envelope guard | no handler field I/O |

The weekly/manual campaign runs every target for 600 seconds. Pull-request and
release CI additionally compile every target; the release checklist separately
requires the full campaign and the integration tests for async/DB/filesystem
race coverage.
