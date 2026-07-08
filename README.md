# VaultLink

VaultLink ist eine serverseitig gerenderte Webanwendung, die einen bereits gemounteten Linux-Ordner sicher über öffentliche Download- und Upload-Links freigibt. Zielplattform ist Debian Linux; Entwicklung und Tests funktionieren auch unter Debian/Ubuntu in WSL.

Status: `0.2.0`-Kandidat für ein privates Debian-13-amd64-Release. Ein Tag wird erst nach den Gates in [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) gesetzt.

GitHub-Projektbeschreibung: **VaultLink - secure, self-hosted file and folder sharing for an existing Linux mountpoint, built in Rust.**

## 1. Architekturentscheidung: Rust

Rust wurde Go vorgezogen. Beide liefern einzelne Linux-Binaries und gute HTTP-Server. Für VaultLinks kritischste Bereiche - Pfad- und Dateiverarbeitung, nebenläufige Zähler, Multipart-Streaming und langlebige Sessions - bietet Rust zusätzliche Speicher- und Typensicherheit ohne Garbage-Collector.

Stack: Rust stable, Axum/Tokio, Tower-Middleware, Rusqlite/SQLite, Argon2id, RFC-6238-TOTP, Rustls, `rustls-acme`, `tracing`. HTML wird bewusst serverseitig erzeugt; es gibt keine Frontend-Buildchain.

## 2. Sicherheitskonzept

- Dateizugriffe sind Linux descriptor-relativ. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` bindet Listing, Metadaten, Download, ZIP und Upload an den beim Start geöffneten Root-Descriptor. Ein Kernel ohne `openat2` wird mit verständlichem Startfehler abgewiesen.
- Relative Nutzpfade verbieten absolute Pfade, `..`, Backslashes, NUL, doppelte Prozentkodierung und ungültiges UTF-8.
- Uploads werden als zufällige `0600`-Temporärdateien im Zielordner geschrieben, geflusht und per `fsync` gesichert. Default ist atomarer No-Replace-Publish mit `renameat2(RENAME_NOREPLACE)`; optional kann pro Upload-Ordnerlink ein explizit bestätigtes atomisches Ersetzen erlaubt werden.
- Adminpasswörter verwenden Argon2id. Nach dem Passwort ist TOTP zwingend. Sessions sind zufällige serverseitige Bearer-Tokens, deren Hash in SQLite liegt.
- Cookies sind `HttpOnly`, `SameSite=Strict` und in Production `Secure`.
- Mutierende Adminaktionen verlangen CSRF. Login und Share-Unlock sind rate-limitiert.
- Forwarded-Header werden nur im Reverse-Proxy-Modus und nur von `trusted_proxies` akzeptiert.
- Security Header: CSP, `X-Content-Type-Options: nosniff`, Frame-Schutz, Referrer-Policy, Permissions-Policy und HSTS nur bei HTTPS.
- Audit liegt in SQLite und wird strukturiert an journald gespiegelt. Passwörter, TOTP-Secrets, Sessiontokens und Share-Tokens werden nicht geloggt.

Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner. VaultLink ersetzt vorhandene Dateien nur, wenn ein Admin dies für den konkreten Upload-Link erlaubt und der Public-Uploader das Ersetzen beim Upload aktiv bestätigt. Ordnerfreigaben unterstützen ZIP-Download mit Limits, Suche, Upload in navigierten Unterordnern und Preview bei Downloadrecht. Upload-only-Freigaben listen keine Inhalte und erlauben keine Preview/Downloads.

## 3. Projektstruktur

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, Serverstart, TLS/ACME
│   ├── config.rs           TOML und Startvalidierung
│   ├── auth.rs             Argon2id, TOTP, Rate Limit
│   ├── db.rs               Schema, Sessions, Shares, Audit
│   ├── path_security.rs    Pfadvalidierung
│   ├── secure_fs.rs        openat2/renameat2 und atomare Uploads
│   ├── range.rs            einzelner HTTP-Byte-Range-Parser
│   ├── proxy.rs            vertrauenswürdige Proxy-Header
│   ├── runtime.rs          SQLite-Overrides für Policy-Settings
│   ├── setup.rs            lokales Bootstrap-Setup-UI
│   └── web.rs              Routen, HTML, Upload/Download/ZIP/Preview
├── config/                 Beispielkonfigurationen
├── deploy/                 systemd, Caddy, ACME-Hook
├── docs/                   Upgrade, Rollback, Release-Gates
├── fuzz/                   Pfad-, Range-, Dateinamen-, Preview- und Upload-Fuzzing
├── Makefile
└── Cargo.toml
```

## 4. Daten- und Persistenzmodell

SQLite ist bewusst gewählt: eindeutige Aliase, parallele Sessions, atomare Downloadlimits und crash-feste Transaktionen sind Kernanforderungen. WAL ist aktiv. Tabellen: `admins`, `sessions`, `shares`, `public_unlock_sessions`, `public_preview_sessions`, `runtime_settings`, `audit`.

`shares.max_upload_size` ist optional; `NULL` nutzt das globale Runtime-Limit. Migrationen laufen transaktional über `PRAGMA user_version`; unbekannte neuere Schemas verweigern den Start. Die Datenbank liegt standardmäßig in `/var/lib/vaultlink/data.sqlite` und muss `vaultlink:vaultlink 0600` gehören.

Upgrade mit Backup bei gestopptem Dienst:

```sh
sudo deploy/vaultlink-upgrade.sh /pfad/zum/neuen/vaultlink
```

Restore und Rollback: [docs/UPGRADE-ROLLBACK.md](docs/UPGRADE-ROLLBACK.md).

## 5. Konfigurationsmodell

Beispiele:

- [config/development.toml](config/development.toml)
- [config/production-reverse-proxy.toml](config/production-reverse-proxy.toml)
- [config/production-standalone-tls.toml](config/production-standalone-tls.toml)
- [config/production-standalone-letsencrypt.toml](config/production-standalone-letsencrypt.toml)

Startregeln:

- `development`: nur Loopback, HTTP, kein HSTS.
- `reverse_proxy`: Production, HTTPS-`public_base_url`, `reverse_proxy.enabled = true`, mindestens ein Trusted Proxy, kein App-TLS.
- `standalone_tls` + `certificate_source = "files"`: Production, HTTPS-URL, TLS aktiv, Zertifikat und Key vorhanden; optionaler SIGHUP-Reload.
- `standalone_tls` + `certificate_source = "letsencrypt"`: Production, HTTPS-URL, TLS aktiv, Reverse Proxy aus, DNS-Domain in `public_base_url`, Kontakt-E-Mail und sicherer ACME-Cache innerhalb `data_directory`.

Runtime-editierbar über `/admin/settings`: `public_base_url`, globales Uploadlimit, blockierte Endungen, Share-Passwortpolitik, Unlock-Dauer, ZIP-/Search-/Text-/Media-Preview-Limits, Text-/Bild-Preview-Endungen und PDF-Preview-Status. Servermodus, Bind-Adresse, TLS-Pfade, Trusted Proxies, Root-Mount, Data-Dir und ACME-Modus bleiben file-/restart-basiert.

## 6. Routen- und API-Design

| Route | Methode | Zweck |
|---|---:|---|
| `/login`, `/mfa`, `/logout` | GET/POST | zweistufige Adminauthentifizierung |
| `/admin` | GET | Root-begrenzter Dateibrowser |
| `/admin/preview` | GET | Admin-Preview-Seite |
| `/admin/preview/raw` | GET/HEAD | Raw-Bild/PDF-Preview für Admins |
| `/admin/shares` | GET/POST | Links auflisten/erstellen |
| `/admin/shares/:id/toggle` | POST | aktivieren/deaktivieren |
| `/admin/shares/:id/password` | POST | Share-Passwort setzen/entfernen |
| `/admin/shares/:id/delete` | POST | Share löschen |
| `/admin/admins` | GET/POST | Admins anzeigen und anlegen |
| `/admin/settings` | GET/POST | Runtime-Policy |
| `/admin/audit` | GET | paginiertes Audit-Dashboard |
| `/v/:token` | GET | öffentliche Datei-/Ordnerseite |
| `/v/:token/unlock` | POST | passwortgeschützte Freigabe entsperren |
| `/v/:token/preview` | GET | öffentliche Preview, zählt als Downloadzugriff |
| `/v/:token/preview/raw` | GET/HEAD | kurzlebig tokenisierte Raw-Bild/PDF-Preview |
| `/v/:token/download` | GET/HEAD | Streaming, einzelner Byte-Range, `206`/`416` |
| `/v/:token/download.zip` | GET | limitierter ZIP-Download für Ordner |
| `/v/:token/upload` | POST | exklusiver Ordnerupload |
| `/s/:alias` | GET | validierter Kurzlink |

Es gibt absichtlich keine öffentliche JSON-API. Interne absolute Pfade werden nie gerendert.

## 7. UI und UX

Die Admin-UI bietet Login, MFA, Dateibrowser, Linkverwaltung, Admin-Anlage, Einstellungen und Audit. Der Dateibrowser hat Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der aktuellen Auswahl.

Öffentliche Ordnerfreigaben mit Downloadrecht bieten Breadcrumbs, Suche, ZIP, Download und Preview. `download_upload` erlaubt Upload in den aktuell navigierten Unterordner. `upload_only` zeigt keine Dateinamen.

Preview:

- Text: nur allowlistete Endungen (`txt`, `log`, `md`, `csv`, `json`, `toml`, `yaml`, `yml`, `ini`, `conf` per Default), escaped HTML in `<pre>`.
- Bilder: nur allowlistete Rasterformate (`jpg`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `avif` per Default), feste Content-Types, `nosniff`.
- PDF: `application/pdf`, `inline`, `nosniff`, kein serverseitiges Rendering.
- HTML, SVG, Office, Audio und Video bleiben blockiert.
- Public Media-Raw-Preview benötigt einen kurzlebigen, share- und pfadgebundenen Preview-Token. Die Preview-Seite zählt genau einmal als Downloadzugriff; PDF-Range-Requests umgehen Downloadlimits nicht mehrfach.

## 8. HTTPS- und Betriebsmodi

### Development

Nur `127.0.0.1`, HTTP, kein Secure-Cookie und kein HSTS. Dies ist kein Internetmodus.

### Reverse Proxy (empfohlen)

VaultLink lauscht lokal, z. B. auf `127.0.0.1:8080`; Caddy oder Nginx terminiert HTTPS. Forwarded-Header werden nur aus `trusted_proxies` akzeptiert. Für Nginx/Nginx Proxy Manager bei großen Uploads:

```nginx
client_max_body_size 1g;
proxy_request_buffering off;
proxy_buffering off;
```

Die aktuelle Staging-VM `192.168.1.240` läuft hinter Nginx; Built-in-ACME darf dort nicht aktiviert werden, solange Nginx Port 443 terminiert.

### Standalone TLS mit PEM-Dateien

`certificate_source = "files"` liest `cert_file` und `key_file`. Mit `reload_on_cert_change = true` lädt `systemctl reload vaultlink` die PEM-Dateien per SIGHUP neu. Fehlerhafte neue PEMs lassen die alte TLS-Konfiguration aktiv.

Für Port 443 ohne Root:

```sh
sudo install -m 0644 deploy/vaultlink-standalone-capability.conf /etc/systemd/system/vaultlink.service.d/standalone-capability.conf
sudo systemctl daemon-reload
sudo systemctl restart vaultlink
```

### Standalone TLS mit Built-in Let's Encrypt

`certificate_source = "letsencrypt"` nutzt `rustls-acme` mit `tls-alpn-01` auf Port 443. Es gibt keine OS-Abhängigkeit auf certbot, acme.sh oder Nginx. Der ACME-Cache liegt unter `data_directory`, z. B. `/var/lib/vaultlink/acme`, und enthält Account-/Zertifikatsdaten.

Minimal:

```toml
[server]
mode = "standalone_tls"
listen_address = "0.0.0.0:443"
public_base_url = "https://files.example.com"
production_mode = true

[reverse_proxy]
enabled = false

[tls]
enabled = true
certificate_source = "letsencrypt"
hsts_enabled = false
reload_on_cert_change = false
letsencrypt_contact_email = "admin@example.com"
letsencrypt_cache_dir = "acme"
letsencrypt_staging = true
```

Erst mit `letsencrypt_staging = true` und `hsts_enabled = false` testen. Staging-Zertifikate sind absichtlich nicht browser-vertrauenswürdig; HSTS darf dabei nicht aktiv sein. Für Production auf `letsencrypt_staging = false` setzen und danach `hsts_enabled = true` aktivieren. Dieser Modus funktioniert nur, wenn VaultLink selbst aus dem Internet auf Port 443 erreichbar ist.

### ZeroSSL Auto-Renewal Setup

ZeroSSL/acme.sh bleibt als externe Alternative dokumentiert und ist vor allem für Reverse-Proxy- oder PEM-Standalone-Betrieb sinnvoll. EAB-Credentials gehören in `/etc/vaultlink/zerossl.env` mit `0600`, niemals in Logs oder systemd-Argumente.

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/vaultlink/zerossl.env
sudoedit /etc/vaultlink/zerossl.env
```

Beispielinhalt:

```sh
ZEROSSL_EAB_KID='...'
ZEROSSL_EAB_HMAC_KEY='...'
VAULTLINK_DOMAIN='files.example.com'
```

Timer:

```sh
sudo install -m 0644 deploy/vaultlink-cert-renew.{service,timer} /etc/systemd/system/
sudo install -o root -g root -m 0755 deploy/vaultlink-cert-deploy.sh /usr/local/libexec/vaultlink-cert-deploy.sh
sudo systemctl daemon-reload
sudo systemctl enable --now vaultlink-cert-renew.timer
```

Der Hook installiert PEMs nach `/etc/vaultlink/tls/` mit `root:vaultlink 0640` und ruft `systemctl reload-or-restart vaultlink` auf.

## 9. Testkonzept

Unit- und HTTP-Integrationstests decken Argon2, TOTP, Login/MFA/Logout, Session/CSRF, Rate-Limits, Security Headers, Setup-UI, Admin-Anlage, Runtime-Settings, Passwort-Unlock, Share-Rechte, Suche, ZIP, Text-/Bild-/PDF-Preview, Raw-Preview-Token, Range/HEAD, Migrationserhalt, atomare Downloadlimits, Upload-Noclobber/-Replace/-Cleanup/-Parallelität, Upload in Unterordner, Traversal/Encoding, Proxy-Vertrauen und Config-Modi ab. Fuzz-Targets decken Pfadnormalisierung, Byte-Ranges, Dateinamen, ZIP/Search/Preview-Pfade, Upload-Overwrite und Upload-Validierungslogik ab.

```sh
make test
make security-test
make lint
```

Aktueller lokaler Stand am 2026-07-07:

- `cargo check --locked`: grün
- `cargo fmt --all -- --check`: grün
- `cargo clippy --locked --all-targets --all-features -- -D warnings`: grün
- `cargo test --locked --all-targets`: 45 Tests bestanden

Fuzz-, VM-, Public-Nginx-, Last- und 72h-Soak-Gates stehen in [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md).

## 10. Debian-Deployment

```sh
sudo apt update && sudo apt install -y build-essential pkg-config
cargo build --release --locked

sudo useradd --system --home /var/lib/vaultlink --shell /usr/sbin/nologin vaultlink
sudo install -d -o root -g vaultlink -m 0750 /opt/vaultlink /etc/vaultlink /etc/vaultlink/tls
sudo install -d -o vaultlink -g vaultlink -m 0750 /var/lib/vaultlink /var/log/vaultlink
sudo install -o root -g root -m 0755 target/release/vaultlink /opt/vaultlink/vaultlink
sudo install -o root -g vaultlink -m 0640 config/production-reverse-proxy.toml /etc/vaultlink/config.toml
sudo install -o root -g root -m 0644 deploy/vaultlink.service /etc/systemd/system/vaultlink.service
sudo systemctl daemon-reload
```

`ReadWritePaths=/mnt/storage` in [deploy/vaultlink.service](deploy/vaultlink.service) an den echten Mount anpassen. Admin initialisieren:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink init-admin --config /etc/vaultlink/config.toml --username admin
sudo systemctl enable --now vaultlink
```

Firewall: bei Reverse Proxy nur 80/443 für Caddy/Nginx öffnen und VaultLink auf Loopback lassen. Bei Standalone nur 443 öffnen.

## 11. WSL-Entwicklung

```sh
sudo apt update && sudo apt install -y build-essential curl pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
make dev-setup
cargo run -- init-admin --config config/development.toml --username admin
make run
```

`make sample-data` erzeugt `dev/mount` und `dev/data`. WSL braucht kein systemd und kein TLS.

## Troubleshooting

- Start verweigert: Config-Modus, HTTPS-URL, Loopback/Trusted Proxies, PEM/ACME-Einstellungen und Storage-Root prüfen.
- Built-in ACME scheitert: DNS muss auf den Server zeigen, VaultLink muss selbst Port 443 terminieren, Nginx/Caddy darf nicht davor laufen.
- 403 bei Datei: Pfadvalidierung oder Symlink-Grenze greift.
- Upload 409: Standard ist no-overwrite. Falls Ersetzen gewünscht ist, muss der Admin es pro Upload-Link erlauben und der Uploader die Replace-Checkbox setzen.
- TLS nach Renewal alt: `systemctl status vaultlink`, PEM-Rechte und Journal prüfen.

## Lizenz

MIT.
