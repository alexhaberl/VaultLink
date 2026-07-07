# v0.1.0-beta.1 release checklist

Stand: 2026-07-07 nach Feature-Complete-Implementierung.

Ziel: privates GitHub-Prerelease für Debian 13 amd64. Arbeiten erfolgen direkt auf `main`; ein Tag wird ausschließlich bei sauberem Worktree und vollständig grünen Gates gesetzt.

## Feature-Scope für beta1

- [x] Admin Login, TOTP-MFA, Sessions, Logout, CSRF.
- [x] Root-begrenzter Dateibrowser mit Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der Oberfläche.
- [x] Linkverwaltung für Datei-/Ordnerlinks mit `download_only`, `upload_only`, `download_upload`.
- [x] Passwortgeschützte Shares mit Argon2id, Unlock-Cookies und Rate-Limit.
- [x] Optionaler Kurzlink-Alias.
- [x] Download-Streaming mit `HEAD`, `Accept-Ranges`, einzelnem Byte-Range, `206` und `416`.
- [x] Sichere Uploads mit temporärer Datei, `fsync`, atomarem No-Replace-Publish, globalem und optionalem per-Share-Uploadlimit.
- [x] Upload in navigierten Unterordnern für `download_upload`-Ordnerlinks.
- [x] Upload-only-Freigaben listen keine Ordnerinhalte und erlauben keine Preview/Downloads.
- [x] ZIP-Download für Ordnerfreigaben mit Datei- und Größenlimits.
- [x] Begrenzte case-insensitive Dateinamensuche.
- [x] Sichere Browser-Textvorschau für allowlistete Endungen; escaped HTML in `<pre>`, kein Inline-User-MIME.
- [x] Admin-UI für zusätzliche Admins; TOTP-Secret wird genau einmal angezeigt.
- [x] Runtime-editierbare Policy-Settings in SQLite, nicht in `/etc/vaultlink/config.toml`.
- [x] Audit-Dashboard mit Pagination und Action-Filter.
- [x] Loopback-only Setup-UI: `vaultlink setup --config <path> --listen 127.0.0.1:8090`.
- [x] Reverse-Proxy-Modus, Standalone-TLS-Modus, SIGHUP-Zertifikatsreload.
- [x] ZeroSSL/acme.sh Renewal-Dokumentation und systemd-Beispiele.

## Bewusste Nicht-Ziele für beta1

- DEB-Paket.
- ARM64-Build.
- Öffentliches Repository.
- Öffentliche JSON-API.
- Inline-Preview für HTML, SVG, PDF, Bilder, Office-Dateien oder Medien.
- Unbounded/streaming ZIP für sehr große Ordner; ZIP wird limitiert und bei Überschreitung abgelehnt.
- Admin-Löschen.

## Lokal in dieser Arbeitskopie grün

- [x] `cargo check --locked`
- [x] `cargo test --locked --all-targets`
  - Ergebnis: 41 Tests bestanden.
  - Enthalten: Setup-UI, Admin-Anlage, Runtime-Settings, Preview, ZIP, Suche, Upload in Unterordner, Share-Rechte, Auth, Migrationen, Upload-Cleanup.
- [x] `cargo check --manifest-path fuzz/Cargo.toml --locked`
  - Fuzz-Crate inklusive `zip_search_preview_paths` kompiliert.
- [x] `cargo audit --deny warnings`
  - `cargo-audit 0.22.2`, keine bekannten Vulnerabilities/Warnings.
- [x] Debian-13-VM `192.168.1.240`, temporärer Build in `/tmp/vaultlink-feature-check`
  - OS: Debian GNU/Linux 13.5, amd64, Kernel 6.12.
  - `cargo fmt --all -- --check`: grün.
  - `cargo test --locked --all-targets`: 43 Tests bestanden, inklusive Linux-`openat2`/Symlink-Tests.
  - `cargo clippy --locked --all-targets -- -D warnings`: grün.
  - `cargo build --release --locked`: grün.
  - `cargo check --manifest-path fuzz/Cargo.toml --locked`: grün.

## Erneut auszuführen, weil Runtime-Code geändert wurde

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked --all-targets` final wiederholen.
- [ ] Fuzz-Gate jeweils zehn Minuten:
  - Pfadnormalisierung,
  - Byte-Range-Parser,
  - Dateinamen,
  - ZIP/Search/Preview-Pfadfälle.
- [x] Dependency-Gate mit `cargo-audit 0.22.2 --deny warnings`.
- [ ] GitHub Actions CI auf finalem `main` grün.
- [ ] Release-Dry-Run im gepinnten Debian-13-amd64-Container mit `--locked` grün.
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

## VM-/Public-Gates vor finalem Soak

- [ ] Finalen Release-Candidate auf der Debian-VM bauen/deployen.
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
- [ ] Öffentlicher Nginx-Pfad `vaultlink.haberl.tech` erneut prüfen:
  - TLS und HTTP→HTTPS Redirect,
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
  - Upload in Subfolder,
  - Download/Range/HEAD,
  - Upload-only darf nicht listen/downloaden/previewen,
  - Revoke/Expiry/Downloadlimit.

## Finaler 72h-Soak

- [ ] Erst nach dem letzten Runtime-Deploy starten.
- [ ] Gate:
  - keine ungeplanten Restarts,
  - `PRAGMA integrity_check = ok`,
  - kein kontinuierliches RSS-Wachstum > 15 %,
  - keine auffälligen 5xx-/Panic-/DB-Fehler im Journal.
- [ ] Lange Soaks werden nach reinen Doku-/CI-Änderungen nicht neu gestartet; jedes neue Binary-Deploy setzt den Soak zurück.

## Tag-Freigabe

- [ ] Sauberer Worktree.
- [ ] Grüner CI-Run auf finalem `main`.
- [ ] Release-Dry-Run und `cargo-audit` weiterhin grün.
- [ ] VM- und Public-Gates grün.
- [ ] 72h-Soak bestanden.
- [ ] Annotierten Tag `v0.1.0-beta.1` erstellen.
- [ ] Tag-Release-Workflow prüfen:
  - GitHub Release ist privat/prerelease,
  - Artefakte stammen ausschließlich aus CI,
  - Binary und `SHA256SUMS` verifizieren mit Minisign gegen `release/minisign.pub`.
