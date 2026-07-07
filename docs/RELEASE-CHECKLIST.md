# v0.1.0-beta.1 release checklist

Stand: 2026-07-07 nach PDF-/Bildpreview und Built-in-Let's-Encrypt-Standalone-TLS.

Ziel: privates GitHub-Prerelease fuer Debian 13 amd64. Arbeiten erfolgen direkt auf `main`; ein Tag wird ausschliesslich bei sauberem Worktree und vollstaendig gruenen Gates gesetzt.

## Feature-Scope fuer beta1

- [x] Admin Login, TOTP-MFA, Sessions, Logout, CSRF.
- [x] Root-begrenzter Dateibrowser mit Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der Oberflaeche.
- [x] Linkverwaltung fuer Datei-/Ordnerlinks mit `download_only`, `upload_only`, `download_upload`.
- [x] Passwortgeschuetzte Shares mit Argon2id, Unlock-Cookies und Rate-Limit.
- [x] Optionaler Kurzlink-Alias.
- [x] Download-Streaming mit `HEAD`, `Accept-Ranges`, einzelnem Byte-Range, `206` und `416`.
- [x] Sichere Uploads mit temporaerer Datei, `fsync`, atomarem No-Replace-Publish, globalem und optionalem per-Share-Uploadlimit.
- [x] Upload in navigierten Unterordnern fuer `download_upload`-Ordnerlinks.
- [x] Upload-only-Freigaben listen keine Ordnerinhalte und erlauben keine Preview/Downloads.
- [x] ZIP-Download fuer Ordnerfreigaben mit Datei- und Groessenlimits.
- [x] Begrenzte case-insensitive Dateinamensuche.
- [x] Sichere Browser-Textvorschau fuer allowlistete Endungen; escaped HTML in `<pre>`, kein Inline-User-MIME.
- [x] Sichere Browser-Vorschau fuer allowlistete Rasterbilder und PDFs ueber Raw-Preview-Routen mit `inline`, `nosniff`, `HEAD`, `206` und `416`.
- [x] Admin-UI fuer zusaetzliche Admins; TOTP-Secret wird genau einmal angezeigt.
- [x] Runtime-editierbare Policy-Settings in SQLite, nicht in `/etc/vaultlink/config.toml`.
- [x] Audit-Dashboard mit Pagination und Action-Filter.
- [x] Loopback-only Setup-UI: `vaultlink setup --config <path> --listen 127.0.0.1:8090`.
- [x] Reverse-Proxy-Modus, Standalone-TLS-Modus, SIGHUP-Zertifikatsreload fuer PEM-Dateien.
- [x] Optionaler Built-in-Let's-Encrypt-Standalone-TLS-Modus ueber `tls-alpn-01` und `rustls-acme`.
- [x] ZeroSSL/acme.sh Renewal-Dokumentation und systemd-Beispiele.

## Bewusste Nicht-Ziele fuer beta1

- DEB-Paket.
- ARM64-Build.
- Oeffentliches Repository.
- Oeffentliche JSON-API.
- Inline-Preview fuer HTML, SVG, Office-Dateien, Audio oder Video.
- Built-in ACME hinter Nginx/Caddy; Auto-TLS ist ausschliesslich fuer echten Standalone-Port-443-Betrieb.
- Unbounded/streaming ZIP fuer sehr grosse Ordner; ZIP wird limitiert und bei Ueberschreitung abgelehnt.
- Admin-Loeschen.

## Lokal in dieser Arbeitskopie gruen

- [x] `cargo check --locked`
- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [x] `cargo test --locked --all-targets`
  - Ergebnis: 45 Tests bestanden.
  - Enthalten: Setup-UI, Admin-Anlage, Runtime-Settings, Text-/Bild-/PDF-Preview, Raw-Preview-Token, ZIP, Suche, Upload in Unterordner, Share-Rechte, Auth, Migrationen, Upload-Cleanup.
- [x] `cargo check --manifest-path fuzz/Cargo.toml --locked`
  - Fuzz-Crate inklusive `zip_search_preview_paths` kompiliert.
- [x] `cargo audit --deny warnings`
  - `cargo-audit 0.22.2`, keine bekannten Vulnerabilities/Warnings.

## Bereits auf Debian-13-VM geprueft, vor finalem Runtime-Deploy erneut auszufuehren

- [x] Debian-13-VM `192.168.1.240`, temporaerer Build in `/tmp/vaultlink-feature-check`
  - OS: Debian GNU/Linux 13.5, amd64, Kernel 6.12.
  - `cargo fmt --all -- --check`: gruen.
  - `cargo test --locked --all-targets`: gruen, inklusive Linux-`openat2`/Symlink-Tests.
  - `cargo clippy --locked --all-targets -- -D warnings`: gruen.
  - `cargo build --release --locked`: gruen.
  - `cargo check --manifest-path fuzz/Cargo.toml --locked`: gruen.
- [ ] Nach diesem Feature-Update erneut auf `192.168.1.240` bauen/deployen und Public-Nginx-Smoke ausfuehren.

## Noch auszufuehrende Release-Gates

- [ ] Fuzz-Gate jeweils zehn Minuten:
  - Pfadnormalisierung,
  - Byte-Range-Parser,
  - Dateinamen,
  - ZIP/Search/Preview-Pfadfaelle inklusive Media-Preview.
- [ ] Dependency-Gate mit `cargo-audit 0.22.2 --deny warnings` final wiederholen.
- [ ] GitHub Actions CI auf finalem `main` gruen.
- [ ] Release-Dry-Run im gepinnten Debian-13-amd64-Container mit `--locked` gruen.
- [ ] Artefakte pruefen:
  - Binary,
  - README,
  - LICENSE,
  - Beispielkonfigurationen,
  - systemd/deploy-Dateien,
  - SHA-256-Pruefsummen,
  - CycloneDX-SBOM,
  - deterministisches `tar.gz`,
  - Minisign-Signatur nur beim Tag-Release.

## VM-/Public-Gates vor finalem Soak

- [ ] Finalen Release-Candidate auf der Debian-VM bauen/deployen.
- [ ] SQLite-Backup vor Upgrade bei gestopptem Dienst erstellen.
- [ ] Upgrade-Test durchfuehren.
- [ ] Rollback-Test durchfuehren:
  - Dienst stoppen,
  - vorheriges Binary und SQLite-Backup wiederherstellen,
  - Dienst starten,
  - Smoke-Test ausfuehren.
- [ ] Debian-13-amd64 Lastprofil erneut:
  - 100 parallele Nutzer,
  - 40 Downloadstreams,
  - Sparse-Datei mit 50 GiB,
  - parallele Uploadstreams,
  - keine 5xx,
  - keine korrupten Dateien,
  - p95 Metadatenseiten < 750 ms,
  - maximal 256 MiB zusaetzlicher RSS bei 40 Streams.
- [ ] Oeffentlicher Nginx-Pfad `vaultlink.haberl.tech` erneut pruefen:
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
  - Download/Range/HEAD,
  - Upload-only darf nicht listen/downloaden/previewen,
  - Revoke/Expiry/Downloadlimit.
- [ ] Standalone Auto-TLS nur mit Let's-Encrypt-Staging auf direkt erreichbarer Test-IP/Domain pruefen; nicht auf der aktuellen Nginx-VM.

## Finaler 72h-Soak

- [ ] Erst nach dem letzten Runtime-Deploy starten.
- [ ] Gate:
  - keine ungeplanten Restarts,
  - `PRAGMA integrity_check = ok`,
  - kein kontinuierliches RSS-Wachstum > 15 %,
  - keine auffaelligen 5xx-/Panic-/DB-Fehler im Journal.
- [ ] Lange Soaks werden nach reinen Doku-/CI-Aenderungen nicht neu gestartet; jedes neue Binary-Deploy setzt den Soak zurueck.

## Tag-Freigabe

- [ ] Sauberer Worktree.
- [ ] Gruener CI-Run auf finalem `main`.
- [ ] Release-Dry-Run und `cargo-audit` weiterhin gruen.
- [ ] VM- und Public-Gates gruen.
- [ ] 72h-Soak bestanden.
- [ ] Annotierten Tag `v0.1.0-beta.1` erstellen.
- [ ] Tag-Release-Workflow pruefen:
  - GitHub Release ist privat/prerelease,
  - Artefakte stammen ausschliesslich aus CI,
  - Binary und `SHA256SUMS` verifizieren mit Minisign gegen `release/minisign.pub`.
