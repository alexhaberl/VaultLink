# v0.3.0 release checklist

Stand: 2026-07-10 nach Security-/Reliability-Hardening für SecureFS, Runtime-Transaktionen, Transfer-Limits, Streaming-ZIP, Setup-Recovery sowie Build-/Deploy-Gates.

Ziel: privates GitHub-Release für Debian 13 amd64. Arbeiten erfolgen direkt auf `main`; ein Tag wird ausschließlich bei sauberem Worktree und vollständig grünen Gates gesetzt.

## Feature-Scope für 0.3.0

- [x] Admin Login, TOTP-MFA, Sessions, Logout, CSRF.
- [x] Session-basierte JSON-API unter `/api/v1`; keine API-Tokens in 0.3.0.
- [x] API und UI teilen Auth-, Session-, CSRF-, SecureFS-, SQLite-, Runtime-Settings- und Audit-Logik.
- [x] API-Fehler werden als JSON normalisiert; Streaming-Routen liefern nur bei Erfolg Binärdaten.
- [x] Root-begrenzter Dateibrowser mit Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der Oberfläche.
- [x] Linkverwaltung für Datei-/Ordnerlinks mit `download_only`, `upload_only`, `download_upload`.
- [x] Passwortgeschützte Shares mit Argon2id, Unlock-Cookies und Rate-Limit.
- [x] Optionaler Kurzlink-Alias.
- [x] Download-Streaming mit `HEAD`, `Accept-Ranges`, einzelnem Byte-Range, `206` und `416`; feste Transfer-Grants zählen erst vollständige Antworten und fassen Range-Resumes ohne Sliding-Expiry zusammen.
- [x] Sichere Uploads mit temporärer Datei, `fsync`, atomarem No-Replace-Publish, globalem und optionalem per-Share-Uploadlimit.
- [x] Optionales Upload-Überschreiben pro Upload-Ordnerlink; Default bleibt No-Replace und Public-Uploader müssen Replace pro Upload bestätigen.
- [x] Upload in navigierten Unterordnern für `download_upload`-Ordnerlinks.
- [x] Upload-only-Freigaben listen keine Ordnerinhalte und erlauben keine Preview/Downloads.
- [x] Inkrementeller ZIP-Download für Ordnerfreigaben mit Datei-, Scan- und Größenlimits, gecappten Quelldateien, Temp-Budget und backpressured Direct-Stream-Fallback.
- [x] Begrenzte case-insensitive Dateinamensuche; Listing, Suche und ZIP zählen auch gefilterte rohe Verzeichniseinträge und setzen Scans ohne Offset-Rescan fort.
- [x] Sichere Browser-Textvorschau für allowlistete Endungen; escaped HTML in `<pre>`, kein Inline-User-MIME.
- [x] Sichere Browser-Vorschau für allowlistete Rasterbilder und PDFs über Raw-Preview-Routen mit `inline`, `nosniff`, `HEAD`, `206` und `416`.
- [x] Admin-UI für zusätzliche Admins; TOTP-Secret wird genau einmal angezeigt. Initial-Setup kann ein noch nicht bestätigtes Secret lokal und passwortgebunden wiederanzeigen.
- [x] Runtime-editierbare Policy-Settings in SQLite, nicht in `/etc/vaultlink/config.toml`.
- [x] Audit-Dashboard mit Pagination und Action-Filter.
- [x] Loopback-only Setup-UI: `vaultlink setup --config <path> --listen 127.0.0.1:8090`.
- [x] Setup überschreibt keine bestehende Konfiguration; Config-ohne-Admin und committed Admin vor verlorener TOTP-Antwort sind wiederaufnehmbar.
- [x] Pro-Share SecureFS-Capabilities verhindern Symlink-Wechsel in Sibling-Shares für Listing, Preview, Download, ZIP und Upload.
- [x] Gepufferte Form-/JSON-Bodies sind klein begrenzt; ausschließlich Uploadrouten erhalten den großen Streaming-Rahmen. Ein konstanter Streaming-Guard begrenzt Präambel und jeden Multipart-Headerblock, zusätzlich sind Feldanzahl und Metadaten klein begrenzt.
- [x] Reverse-Proxy-Modus, Standalone-TLS-Modus, SIGHUP-Zertifikatsreload für PEM-Dateien.
- [x] Optionaler Built-in-Let's-Encrypt-Standalone-TLS-Modus über `tls-alpn-01` und `rustls-acme`.
- [x] ZeroSSL/acme.sh Renewal-Dokumentation und systemd-Beispiele.
- [x] UI-/UX-Polish mit getrennten Auth/Public/Admin-Shells, Logo/Favicon, deutschem Date-Time-Picker, dezimalen MB/GB-Einheiten und konsistenten Buttons/Switches.
- [x] Public Upload-Fehlerseiten für validierbare Fehler inklusive blockierter Dateitypen, Konflikte, Größenlimits, fehlende Dateinamen und Speicherfehler.
- [x] Fuzzing für Pfade, Byte-Ranges, Dateinamen, ZIP/Search/Preview-Pfade, Upload-Overwrite, Upload-Validierung und API-Request-Policy.

## Bewusste Nicht-Ziele für 0.3.0

- DEB-Paket.
- ARM64-Build.
- Öffentliches Repository.
- API-Tokens oder externe API-Clients als stabile Public Contract Garantie.
- Inline-Preview für alle anderen Dateitypen.
- Built-in ACME hinter Nginx/Caddy; Auto-TLS ist ausschließlich für echten Standalone-Port-443-Betrieb.
- Unbegrenzte ZIPs, ZIP64 und Kompression; ZIP wird inkrementell erzeugt, bleibt aber hart limitiert und wird bei Überschreitung abgelehnt.
- Admin-Löschen; Admins können deaktiviert/reaktiviert werden.

## Lokal in dieser Arbeitskopie grün

- [x] `cargo check --locked`
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [x] `cargo test --locked --all-targets`
  - Ergebnis: 107 Tests unter Windows bestanden; der finale Linux-/Containerlauf folgt nach Abschluss dieses Updates erneut.
  - Enthalten: API Login/MFA/Session/CSRF, API-URL-/Listen-Restart-Sicherheit, API-scoped Unlock/Media-Preview, Share-Erstellung, Secret-Redaction, Admin-/Settings-API, delegierte API-Uploadfehler als JSON, Setup-UI/-Recovery, transaktionale Admin-/Runtime-Pfade, Text-/Bild-/PDF-Preview, Transfer-Grant/Abort/Range-Resume einschließlich HTTP/1-`Content-Length`, Raw-Preview-Token, inkrementelles ZIP, rohe Scanbudgets, Multipart-Präambel/-Header, Body-Limits, `%`-Dateinamens-Roundtrip, Upload-No-Replace/-Replace/-Durability, Share-Rechte, Migrationen und resumierbares Upload-Cleanup.
- [x] `cargo check --manifest-path fuzz/Cargo.toml --locked`
  - Fuzz-Crate inklusive `zip_search_preview_paths`, `upload_overwrite_policy`, `upload_validation_policy` und `api_request_policy` kompiliert.
- [x] `cargo audit --deny warnings` und `cargo audit --deny warnings --file fuzz/Cargo.lock`
  - Beide Lockfiles (`Cargo.lock`, `fuzz/Cargo.lock`) ohne bekannte Vulnerabilities/Warnings.
- [x] `make policy-check`
  - Externe Actions auf volle Commit-SHAs und Container auf Digests gepinnt; Cargo-CI-Tools versioniert; Docker-Secret-Ausschlüsse vorhanden.
- [x] `make docker-smoke`
  - Ergebnis vor dem letzten Source-Hardening: digest-gepinntes Debian/Rust-Image gebaut; Setup-UI, API Login/MFA/CSRF/Files/Share/Public-Upload-JSON-Fehler sowie isolierte Upgrade-/Rollback-Fehlerpfade erfolgreich und ohne externes Runtime-Netzwerk geprüft. Der erneute finale Lauf bleibt bis zur unten dokumentierten Verifikation offen.

## Bereits auf Debian 13 geprüft, vor finalem Runtime-Deploy erneut auszuführen

- [ ] Debian-13-amd64-Testsystem, temporärer Build in einem nicht versionierten Arbeitsverzeichnis:
  - `cargo fmt --all -- --check`
  - `cargo test --locked --all-targets`
  - `cargo clippy --locked --all-targets -- -D warnings`
  - `cargo build --release --locked`
  - `cargo check --manifest-path fuzz/Cargo.toml --locked`
- [ ] Nach diesem Feature-Update erneut auf dem Reverse-Proxy-Testsystem bauen/deployen und Public-Smoke ausführen.
- [ ] Standalone-Testsystem erneut bauen/deployen und Public-HTTPS-Smoke ausführen.

## Noch auszuführende Release-Gates

- [ ] Fuzz-Gate jeweils zehn Minuten:
  - Pfadnormalisierung,
  - Byte-Range-Parser,
  - Dateinamen,
  - ZIP/Search/Preview-Pfadfälle inklusive Media-Preview,
  - Upload-Overwrite-Policy,
  - Upload-Validierungslogik,
  - API-Request-Policy.
  - Der Workflow läuft zusätzlich wöchentlich als parallele Sieben-Target-Matrix; der manuelle Lauf auf dem finalen Commit bleibt das Release-Gate.
- [ ] Dependency-Gate mit `cargo-audit 0.22.2 --deny warnings` final wiederholen.
- [ ] Dabei `Cargo.lock` und `fuzz/Cargo.lock` prüfen.
- [ ] GitHub Actions CI auf finalem `main` grün.
- [ ] Release-Dry-Run im digest-gepinnten Rust-1.96.1-/Debian-13-amd64-Container mit `--locked` grün.
- [ ] Artefakte prüfen:
  - Binary,
  - README,
  - LICENSE,
  - Beispielkonfigurationen,
  - systemd/deploy-Dateien,
  - SHA-256-Prüfsummen,
  - CycloneDX-SBOM,
  - deterministisches `tar.gz`,
  - Minisign-Signatur nur beim Tag-Release.

## Staging- und Public-Gates vor finalem Soak

- [ ] Finalen Release-Candidate auf dem Staging-System bauen/deployen.
- [ ] SQLite-Backup vor Upgrade bei gestopptem Dienst erstellen.
- [ ] Upgrade-Test durchführen.
- [ ] Rollback-Test durchführen:
  - Dienst stoppen,
  - vorheriges Binary und SQLite-Backup wiederherstellen,
  - Dienst starten,
  - Smoke-Test ausführen.
- [ ] Debian-13-amd64 Lastprofil erneut:
  - 100 parallele Nutzer,
  - 40 Downloadstreams,
  - Sparse-Datei mit 50 GiB,
  - parallele Uploadstreams,
  - keine 5xx,
  - keine korrupten Dateien,
  - p95 Metadatenseiten < 750 ms,
  - maximal 256 MiB zusätzlicher RSS bei 40 Streams.
- [ ] Konfigurierten öffentlichen Reverse-Proxy-Endpunkt erneut prüfen:
  - TLS und HTTP->HTTPS Redirect,
  - Security Header,
  - Secure/SameSite/HttpOnly Cookies,
  - Login, MFA, Logout,
  - Admins,
  - Settings,
  - Audit,
  - Linkerstellung mit Passwort und per-Share-Uploadlimit,
  - Suche,
  - ZIP,
  - Textpreview,
  - Bildpreview,
  - PDFpreview,
  - Raw-Preview Range/HEAD,
  - Upload in Subfolder,
  - Upload-Replace nur bei Linkrecht plus Public-Bestätigung,
  - Download/Range/HEAD,
  - Upload-only darf nicht listen/downloaden/previewen,
  - Revoke/Expiry/Downloadlimit,
  - JSON-API Login/MFA/CSRF/Files/Shares/Admins/Settings/Audit/Public-Share-Flows.
- [ ] Standalone Auto-TLS nur mit Let's-Encrypt-Staging auf einem direkt erreichbaren Standalone-Testendpunkt prüfen; nicht hinter einem Reverse Proxy.

## Finaler 72h-Soak

- [ ] Erst nach dem letzten Runtime-Deploy starten.
- [ ] Gate:
  - keine ungeplanten Restarts,
  - `PRAGMA integrity_check = ok`,
  - kein kontinuierliches RSS-Wachstum > 15 %,
  - keine auffälligen 5xx-/Panic-/DB-Fehler im Journal.
- [ ] Lange Soaks werden nach reinen Doku-/CI-/Deploy-Skript-Änderungen ohne neues Binary nicht neu gestartet; geänderte Upgrade-/Rollback-Skripte müssen ihre Staging-Gates trotzdem erneut bestehen. Jedes neue Binary-Deploy setzt den Soak zurück.

## Tag-Freigabe

- [ ] Sauberer Worktree.
- [ ] Grüner CI-Run auf finalem `main`.
- [ ] Release-Dry-Run und `cargo-audit` weiterhin grün.
- [ ] `make policy-check` grün; alle Dependabot-Pin-Updates gegen die jeweiligen Upstream-Repositories geprüft.
- [ ] Staging- und Public-Gates grün.
- [ ] 72h-Soak bestanden.
- [ ] Annotierten Tag `v0.3.0` erstellen.
- [ ] Tag-Release-Workflow prüfen:
  - GitHub Release ist privat,
  - Artefakte stammen ausschließlich aus CI,
  - Binary und `SHA256SUMS` verifizieren mit Minisign gegen `release/minisign.pub`.
