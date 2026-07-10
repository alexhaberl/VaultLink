# VaultLink

VaultLink ist eine serverseitig gerenderte Webanwendung, die einen bereits gemounteten Linux-Ordner sicher über öffentliche Download- und Upload-Links freigibt. Zielplattform ist Debian Linux; Entwicklung und Tests funktionieren auch unter Debian/Ubuntu in WSL.

Status: `0.3.1`-Kandidat für ein privates Debian-13-amd64-Release. Ein Tag wird erst nach den Gates in [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) gesetzt.

GitHub-Projektbeschreibung: **VaultLink - secure, self-hosted file and folder sharing for an existing Linux mountpoint, built in Rust.**

## 1. Sicherheitskonzept

- Dateizugriffe sind Linux descriptor-relativ. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` bindet Adminzugriffe an den Storage-Root und öffentliche Zugriffe zusätzlich an eine pro Freigabe verengte Directory-/File-Capability. Sibling-Shares bleiben damit auch über Symlinks getrennt. Ein Kernel ohne `openat2` wird mit verständlichem Startfehler abgewiesen.
- Relative Nutzpfade werden nach genau einer HTTP-Dekodierung geprüft und verbieten absolute Pfade, `..`, Backslashes und NUL. Uploadnamen folgen zusätzlich einer plattformübergreifenden Policy, damit Windows-Prefixe und reservierte Namen nie aus dem Zielordner aufgelöst werden.
- Uploads werden als zufällige `0600`-Temporärdateien im Zielordner geschrieben, geflusht und per `fsync` gesichert. Default ist atomarer No-Replace-Publish mit `renameat2(RENAME_NOREPLACE)`; optional kann pro Upload-Ordnerlink ein explizit bestätigtes atomisches Ersetzen erlaubt werden.
- Abgebrochene private Uploadfragmente werden in fortsetzbaren Hintergrund-Batches entfernt; eine synchronisierte Active-Registry verhindert dabei Kollisionen mit Uploads des laufenden Prozesses. Listing, Suche und ZIP budgetieren jedes rohe Verzeichniselement, auch wenn es später als intern oder unsicher gefiltert wird.
- Adminpasswörter verwenden Argon2id. Nach dem Passwort ist TOTP zwingend. Sessions sind zufällige serverseitige Bearer-Tokens, deren Hash in SQLite liegt.
- Cookies sind `HttpOnly`, `SameSite=Strict` und in Production `Secure`.
- Mutierende Adminaktionen verlangen CSRF. Login und Share-Unlock sind rate-limitiert.
- Forwarded-Header werden nur im Reverse-Proxy-Modus und nur von `trusted_proxies` akzeptiert.
- Security Header: CSP, `X-Content-Type-Options: nosniff`, Frame-Schutz, Referrer-Policy, Permissions-Policy und HSTS nur bei HTTPS.
- Audit liegt in SQLite und wird strukturiert an journald gespiegelt. Passwörter, TOTP-Secrets, Sessiontokens und Share-Tokens werden nicht geloggt.

Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner. VaultLink ersetzt vorhandene Dateien nur, wenn ein Admin dies für den konkreten Upload-Link erlaubt und der Public-Uploader das Ersetzen beim Upload aktiv bestätigt. Ordnerfreigaben unterstützen begrenzt und inkrementell erzeugte ZIP-Downloads, Suche, Upload in navigierten Unterordnern und Preview bei Downloadrecht. Kleine Standardlimits schützen gepufferte Form-/JSON-Routen; nur Uploadrouten erhalten den großen, weiterhin gestreamten Body-Rahmen. Davor begrenzt ein konstanter Streaming-Guard Multipart-Präambel und jeden Headerblock, ohne Dateiinhalte zu sammeln. Upload-only-Freigaben listen keine Inhalte und erlauben keine Preview/Downloads.

## 2. Projektstruktur

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, Serverstart, TLS/ACME
│   ├── config.rs           TOML und Startvalidierung
│   ├── api.rs              session-basierte JSON-API unter /api/v1
│   ├── auth.rs             Argon2id, TOTP, Rate Limit
│   ├── db.rs               Schema, Sessions, Shares, Audit
│   ├── http_auth.rs        gemeinsame Session-, Cookie-, CSRF- und Audit-Helfer
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
├── fuzz/                   Pfad-, Range-, Dateinamen-, Preview-, Upload- und API-Policy-Fuzzing
├── Makefile
└── Cargo.toml
```

## 3. Daten- und Persistenzmodell

SQLite ist bewusst gewählt: eindeutige Aliase, parallele Sessions, atomare Downloadlimits und crash-feste Transaktionen sind Kernanforderungen. WAL ist aktiv. Tabellen: `admins`, `sessions`, `shares`, `public_unlock_sessions`, `public_preview_sessions`, `public_transfer_grants`, `public_transfer_leases`, `runtime_settings`, `audit`.

`shares.max_upload_size` ist optional; `NULL` nutzt das globale Runtime-Limit. Migrationen laufen transaktional über `PRAGMA user_version`; unbekannte neuere Schemas verweigern den Start. Die Datenbank liegt standardmäßig in `/var/lib/vaultlink/data.sqlite` und muss `vaultlink:vaultlink 0600` gehören.

Upgrade mit Backup bei gestopptem Dienst:

```sh
sudo deploy/vaultlink-upgrade.sh /pfad/zum/neuen/vaultlink
```

Das Upgrade-Skript ist ausschließlich für eine bestehende Installation mit Binary und Datenbank gedacht. Es bereitet Binary und Backup-Verzeichnis vor der Downtime vor, veröffentlicht nur ein erfolgreich geprüftes SQLite-Backup und startet bei frühen Fehlern den zuvor laufenden Dienst wieder. Scheitert Aktivierung oder Health-Check, werden Binary und Datenbank aus dem verifizierten Backup restauriert.

Restore und Rollback: [docs/UPGRADE-ROLLBACK.md](docs/UPGRADE-ROLLBACK.md).

## 4. Konfigurationsmodell

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

`public_base_url` verwendet kanonische `http://`- beziehungsweise `https://`-Authority-Syntax und darf weder Zugangsdaten noch Query oder Fragment enthalten.

Runtime-editierbar über `/admin/settings`: `public_base_url`, globales Uploadlimit, blockierte Endungen, Share-Passwortpolitik, Unlock-Dauer, ZIP-/Search-/Text-/Media-Preview-Limits, Text-/Bild-Preview-Endungen und PDF-Preview-Status. Servermodus, Bind-Adresse, TLS-Pfade, Trusted Proxies, Root-Mount, Data-Dir und ACME-Modus bleiben file-/restart-basiert.

Runtime-Settings werden als ein validierter Snapshot in SQLite geschrieben und erst danach atomar im Arbeitsspeicher ausgetauscht. Beim Start wird ebenfalls der vollständige Snapshot validiert; gültige gekoppelte Werte hängen nicht von der alphabetischen Schlüsselreihenfolge ab.

## 5. Routen- und API-Design

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
| `/v/:token/preview` | GET | öffentliche Text-/Media-Preview-Seite |
| `/v/:token/preview/raw` | GET/HEAD | kurzlebig tokenisierte Raw-Bild/PDF-Preview; erfolgreicher GET zählt |
| `/v/:token/download` | GET/HEAD | Streaming, einzelner Byte-Range, `206`/`416` |
| `/v/:token/download.zip` | GET | limitierter ZIP-Download für Ordner |
| `/v/:token/upload` | POST | exklusiver Ordnerupload |
| `/s/:alias` | GET | validierter Kurzlink |

Zusätzlich gibt es eine session-basierte JSON-API unter `/api/v1`. Sie nutzt dieselben sicheren Cookies, MFA-Sessions, CSRF-Regeln, SecureFS-Zugriffe, SQLite-Operationen und Audit-Events wie die HTML-UI. In `0.3.x` gibt es bewusst keine API-Tokens; mutierende Admin-API-Routen verlangen den Header `X-CSRF-Token`.

Wichtige API-Routen:

| Route | Methode | Zweck |
|---|---:|---|
| `/api/v1/health` | GET | Health/Version |
| `/api/v1/session/login` | POST | Passwortprüfung, setzt Session-Cookie |
| `/api/v1/session/mfa` | POST | TOTP-Verifikation |
| `/api/v1/session/logout` | POST | Session löschen |
| `/api/v1/session/me` | GET | aktuelle Session |
| `/api/v1/files` | GET | Dateibrowser als JSON |
| `/api/v1/shares` | GET/POST | Freigaben listen/erstellen |
| `/api/v1/shares/:id` | PATCH/DELETE | Freigabe ändern/löschen |
| `/api/v1/admins` | GET/POST | Admins listen/anlegen |
| `/api/v1/settings` | GET/PUT | Runtime-Settings lesen/schreiben |
| `/api/v1/audit` | GET | Audit-Events paginiert |
| `/api/v1/public/shares/:token` | GET | Public-Freigabe-Metadaten |
| `/api/v1/public/shares/:token/unlock` | POST | passwortgeschützte Freigabe entsperren |
| `/api/v1/public/shares/:token/download` | GET/HEAD | delegiert auf sichere Streaming-Downloadlogik |
| `/api/v1/public/shares/:token/upload` | POST | delegiert auf sichere Uploadlogik |
| `/api/v1/public/shares/:token/preview` | GET | delegiert auf sichere Previewlogik |
| `/api/v1/public/shares/:token/download.zip` | GET | delegiert auf sichere ZIP-Logik |

JSON-Fehler haben die Form:

```json
{ "error": { "code": "forbidden", "message": "..." } }
```

Auch delegierte API-Routen für Download, Upload, Preview und ZIP normalisieren Fehler auf dieses JSON-Format. Erfolgreiche Streaming-Antworten bleiben Binärdaten.

Interne absolute Pfade, Passwort-Hashes, Session-Hashes, Unlock-/Preview-/Transfer-Hashes und TOTP-Secrets werden nicht über die API ausgegeben. TOTP-Secrets erscheinen bei Admin-Erstellung oder MFA-Reset einmalig. Beim ersten lokalen Setup bleibt das initiale Secret bis zum expliziten Klick auf „Secret sicher gespeichert“ mit Setup-Token und Adminpasswort wiederherstellbar; danach wird der Pending-Marker gelöscht.

## 6. UI und UX

Die Admin-UI bietet Login, MFA, Dateibrowser, Linkverwaltung, Admin-Anlage, Einstellungen und Audit. Der Dateibrowser hat Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der aktuellen Auswahl.

Öffentliche Ordnerfreigaben mit Downloadrecht bieten Breadcrumbs, Suche, ZIP, Download und Preview. `download_upload` erlaubt Upload in den aktuell navigierten Unterordner. `upload_only` zeigt keine Dateinamen.

Preview:

- Text: nur allowlistete Endungen (`txt`, `log`, `md`, `csv`, `json`, `toml`, `yaml`, `yml`, `ini`, `conf` per Default), escaped HTML in `<pre>`.
- Bilder: nur allowlistete Rasterformate (`jpg`, `jpeg`, `png`, `gif`, `webp`, `bmp`, `avif` per Default), feste Content-Types, `nosniff`.
- PDF: `application/pdf`, `inline`, `nosniff`, kein serverseitiges Rendering.
- Alle anderen Dateitypen bleiben blockiert.
- Public Media-Raw-Preview benötigt einen kurzlebigen, share- und pfadgebundenen Preview-Token. Textpreview zählt nach vollständig ausgelieferter HTML-Antwort; bei Bild/PDF zählt erst der vollständig ausgelieferte Raw-GET. Abgebrochene Antworten zählen nicht. Range-Requests teilen innerhalb eines festen 15-Minuten-Resume-Fensters einen Transfer-Grant, ohne dieses Fenster durch Wiederholungen unbegrenzt zu verlängern.

## 7. HTTPS- und Betriebsmodi

### Reverse Proxy (empfohlen)

VaultLink lauscht lokal, z. B. auf `127.0.0.1:8080`; Caddy oder Nginx terminiert HTTPS. Forwarded-Header werden nur aus `trusted_proxies` akzeptiert. Für Nginx/Nginx Proxy Manager bei großen Uploads:

```nginx
client_max_body_size 1g;
proxy_request_buffering off;
proxy_buffering off;
```

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

## 8. Debian-Deployment

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

## 9. WSL-Entwicklung

```sh
sudo apt update && sudo apt install -y build-essential curl pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
make dev-setup
cargo run -- init-admin --config config/development.toml --username admin
make run
```

`make sample-data` erzeugt `dev/mount` und `dev/data`. WSL braucht kein systemd und kein TLS. Wenn Docker verfügbar ist, baut `make docker-smoke` einmalig das digest-gepinnte Debian-13/Rust-Testimage und führt ohne externes Containernetzwerk Setup-, API- sowie isolierte Upgrade-/Rollback-Fehlertests aus. `make docker-setup-smoke`, `make docker-api-smoke` und `make docker-upgrade-safety-test` bleiben als einzelne Ziele verfügbar. `make policy-check` verhindert mutable Action-/Image-Referenzen, ungepinnte Cargo-CI-Tools und fehlende Docker-Secret-Ausschlüsse.

## Troubleshooting

- Start verweigert: Config-Modus, HTTPS-URL, Loopback/Trusted Proxies, PEM/ACME-Einstellungen und Storage-Root prüfen.
- Built-in ACME scheitert: DNS muss auf den Server zeigen, VaultLink muss selbst Port 443 terminieren, Nginx/Caddy darf nicht davor laufen.
- 403 bei Datei: Pfadvalidierung oder Symlink-Grenze greift.
- Upload 409: Standard ist no-overwrite. Falls Ersetzen gewünscht ist, muss der Admin es pro Upload-Link erlauben und der Uploader die Replace-Checkbox setzen.
- TLS nach Renewal alt: `systemctl status vaultlink`, PEM-Rechte und Journal prüfen.

## Lizenz

MIT.
