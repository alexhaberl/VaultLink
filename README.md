# VaultLink

VaultLink ist eine serverseitig gerenderte Rust-Webanwendung, die einen bereits gemounteten Linux-Ordner sicher über öffentliche Download- und Upload-Links freigibt. Unterstützte Hostplattformen sind Linux x86_64 und aarch64; Windows-Hostsupport ist ab 0.4.1 entfernt. Windows-, macOS- und Linux-Clients bleiben über einen externen Standard-SMB-Server interoperabel.

Status: `0.4.1`-Kandidat für ein privates Debian-13-amd64-/arm64-Release. amd64 läuft auf dem lokalen Self-hosted-Runner, arm64 vorerst nativ auf `ubuntu-24.04-arm`. Ein Tag wird erst nach den Gates in [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) gesetzt.

GitHub-Projektbeschreibung: **VaultLink - secure, self-hosted file and folder sharing for an existing Linux mountpoint, built in Rust.**

## 1. Sicherheitskonzept

- Dateizugriffe sind Linux descriptor-relativ. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` bindet Adminzugriffe an den Storage-Root und öffentliche Zugriffe zusätzlich an eine pro Freigabe verengte Directory-/File-Capability. Im Co-Writer-Modus kommt `RESOLVE_NO_SYMLINKS` hinzu, damit externe Writer keinen gespeicherten Share-Pfad umbiegen können. Ein Kernel ohne die benötigten APIs wird mit verständlichem Startfehler abgewiesen.
- Relative Nutzpfade werden nach genau einer HTTP-Dekodierung geprüft und verbieten absolute Pfade, `..`, Backslashes und NUL. Uploadnamen folgen zusätzlich einer plattformübergreifenden Policy, damit Windows-Prefixe und reservierte Namen nie aus dem Zielordner aufgelöst werden.
- Uploads werden als zufällige `0600`-Temporärdateien im geschützten internen Upload-Staging geschrieben, geflusht und per `fsync` gesichert. Die Veröffentlichung in den sichtbaren Baum erfolgt atomar mit `renameat2(RENAME_NOREPLACE)`. Bei `external_writers = true` ist Überschreiben in UI, API und Uploadpfad ausnahmslos deaktiviert.
- Abgebrochene Uploadfragmente und ausschließlich als committed markierte Lösch-Tombstones werden in fortsetzbaren Hintergrund-Batches entfernt. Uncommitted Pending-Löschungen und Rollback-Konflikte bleiben als Recovery-Einträge erhalten, statt beim Neustart Daten zu verlieren.
- Adminpasswörter verwenden Argon2id. Nach dem Passwort ist TOTP oder ein registrierter WebAuthn/FIDO2-Sicherheitsschlüssel (zum Beispiel YubiKey) erforderlich. Sessions sind zufällige serverseitige Bearer-Tokens, deren Hash in SQLite liegt.
- Cookies sind `HttpOnly`, `SameSite=Strict` und in Production `Secure`.
- Mutierende Adminaktionen verlangen CSRF. Login und Share-Unlock sind rate-limitiert.
- Forwarded-Header werden nur im Reverse-Proxy-Modus und nur von `trusted_proxies` akzeptiert.
- Security Header: CSP, `X-Content-Type-Options: nosniff`, Frame-Schutz, Referrer-Policy, Permissions-Policy und HSTS nur bei HTTPS.
- Audit liegt in SQLite und wird strukturiert an journald gespiegelt. Passwörter, TOTP-Secrets, Sessiontokens und Share-Tokens werden nicht geloggt.

Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner. Ohne externe Writer kann VaultLink vorhandene Dateien nur ersetzen, wenn ein Admin dies für den konkreten Upload-Link erlaubt und der Public-Uploader das Ersetzen aktiv bestätigt. Ordnerfreigaben unterstützen begrenzt und inkrementell im ZIP64-Format erzeugte ZIP-Downloads, Suche, Upload in navigierten Unterordnern und Preview bei Downloadrecht. Kleine Standardlimits schützen gepufferte Form-/JSON-Routen; nur Uploadrouten erhalten den großen, weiterhin gestreamten Body-Rahmen. Davor begrenzt ein konstanter Streaming-Guard Multipart-Präambel und jeden Headerblock, ohne Dateiinhalte zu sammeln. Upload-only-Freigaben listen keine Inhalte und erlauben keine Preview/Downloads.

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
sudo deploy/vaultlink-upgrade.sh /pfad/zum/neuen/vaultlink /pfad/zur/neuen-config.toml
```

Das Upgrade-Skript ist ausschließlich für eine bestehende Installation mit Binary, Konfiguration und Datenbank gedacht. Die neue Konfiguration bleibt bis zur gestoppten Aktivierungsphase getrennt von der Live-Konfiguration. Jeder verifizierte Backup-Satz und jeder automatische Restore umfasst immer das zusammengehörige Tripel aus Binary, `config.toml` und SQLite-Datenbank. Altes und neues Binary/Config-Paar werden vor der Downtime als unprivilegierter `vaultlink`-Benutzer geprüft.

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

Jeder Production-Modus verlangt `require_mount = true`, ein pre-provisioniertes privates Geschwisterverzeichnis sowie die exakte aktive Mount-Quelle und den Dateisystemtyp. Damit startet auch eine alte Production-Konfiguration nicht auf einem leeren lokalen Fallback, wenn ihr eigentliches Mount ausgefallen ist. Für lokalen Storage kann die Policy beispielsweise so aussehen:

```toml
[storage]
root_mount_path = "/srv/vaultlink/shared"
data_directory = "/var/lib/vaultlink"
internal_directory = "/srv/vaultlink/.vaultlink-internal"
require_mount = true
external_writers = false
expected_filesystem_type = "ext4"
expected_mount_source = "/dev/mapper/vaultlink"
```

`expected_mount_source` muss exakt dem Source-Feld der aktiven Zeile in `/proc/self/mountinfo` entsprechen; ein `UUID=`-Eintrag aus `/etc/fstab` ist nicht automatisch derselbe Wert. Für auditierten lokalen Storage sind ext2/3/4, XFS, Btrfs, F2FS, Bcachefs und ZFS zugelassen. Root, internes Verzeichnis und Data Directory gehören dem `vaultlink`-Dienstbenutzer und dürfen weder über Gruppen-/Other-Modusbits noch über die POSIX-ACL-Maske schreibbar sein; lokale Co-Writer sind bei `external_writers = false` nicht unterstützt. SQLite darf dabei auf demselben lokalen Mount liegen, aber niemals innerhalb des sichtbaren Baums. Bei CIFS/SMB muss SQLite zusätzlich auf einem getrennten lokalen Dateisystem liegen.

`public_base_url` verwendet kanonische `http://`- beziehungsweise `https://`-Authority-Syntax ohne abschließenden Slash. Basispfade, Zugangsdaten, Query und Fragment sind nicht unterstützt.

### Externer SMB-Server mit Standardclients

VaultLink hostet keinen SMB-Server. Es mountet als Linux-SMB-Client einen bestehenden Server-Baum; Windows-, macOS- und Linux-Clients greifen weiterhin direkt und ohne VaultLink-Zusatzsoftware auf den Ordner `shared/` dieses Servers zu:

```text
//fileserver.example/vaultlink  ->  /mnt/storage
├── shared/                     -> root_mount_path, normale SMB-Clients schreibbar
└── .vaultlink-internal/        -> internal_directory, nur VaultLink-SMB-Konto
    ├── uploads/
    └── tombstones/
```

Die drei internen Verzeichnisse müssen **vor dem ersten Start serverseitig** provisioniert werden. Ihre Server-ACL erlaubt ausschließlich dem separaten VaultLink-SMB-Dienstkonto Lesen, Schreiben, Löschen und Umbenennen. Co-Writer erhalten Modify-Rechte ausschließlich unter `shared/`, aber keine administrativen Rechte auf Share-Root oder Mount-Basis. Für `.vaultlink-internal` müssen Lesen, Schreiben, Löschen, Umbenennen, Parent-`DELETE_CHILD`, ACL-/Owner-Änderungen (`WRITE_DAC`/`WRITE_OWNER`) sowie `chmod`/`chown`/`setfacl`-Äquivalente verweigert sein. Die lokal sichtbaren CIFS-Modi `0700`/`0600` sind nur eine zusätzliche Prüfung und kein Beweis für diese Server-ACL.

Für den auditierten Co-Writer-Modus gelten:

- `require_mount = true`, `external_writers = true`, `expected_filesystem_type = "cifs"` und die erwartete UNC-Quelle sind Pflicht.
- Der Kernel muss `statx`-Mount-IDs unterstützen (Linux 5.8 oder neuer). Root und interner Geschwisterpfad müssen dieselbe geprüfte Mount-ID nutzen; nur so bleiben Cross-Directory-Renames atomar.
- VaultLink prüft `vers=3.1.1`, `seal`, `cache=strict`, `serverino`, `nosuid`, `nodev`, `noexec`, Read-write-Status und verbietet unter anderem `cache=loose`, `nostrictsync`, `noperm`, `noserverino` und `multiuser`.
- Userpfade dürfen weder Symlinks noch verschachtelte Mounts/DFS-Submounts durchqueren.
- `data_directory` und SQLite/WAL bleiben auf einem separaten, explizit unterstützten lokalen Dateisystem; CIFS/NFS für SQLite wird abgewiesen.
- Externe Writer gelten als vertrauenswürdige Publisher des sichtbaren Inhalts. Sie können Dateien verändern oder ersetzen, die ein bestehender VaultLink-Link ausliefert. Diese direkten SMB-Aktionen umgehen VaultLink-Audit, Share-Limits und Web-Policy und müssen deshalb am SMB-Server selbst auditiert werden.
- VaultLinks Linux-Mount erzwingt Transportverschlüsselung per SMB `seal`. Zusätzlich muss der externe SMB-Server SMB 3.1.1 Signing und Encryption für **jede** direkte Windows-, macOS- und Linux-Co-Writer-Session verpflichtend machen; VaultLink kann diese separaten Sessions nicht erzwingen. Verschlüsselung ruhender Daten ist Aufgabe des SMB-Servers. Transparenter Zugriff mit Standard-SMB-Clients ist nicht mit einer ausschließlich von VaultLink kontrollierten clientseitigen Inhaltsverschlüsselung vereinbar.

Andere Netzwerkdateisysteme mit externen Schreibern sind in 0.4.1 nicht freigegeben. Ein erkanntes Remote-Dateisystem ohne explizite Mount-Policy wird beim Start abgewiesen. Production verlangt die Policy unabhängig vom gerade erkannten Dateisystem, sodass auch ein ausgefallener CIFS-Mount mit lokal sichtbarem Fallback-Verzeichnis fail-closed bleibt.

Runtime-editierbar über `/admin/settings`: `public_base_url`, globales Uploadlimit, blockierte Endungen, Share-Passwortpolitik, Unlock-Dauer, ZIP-/Search-/Text-/Media-Preview-Limits, Text-/Bild-Preview-Endungen und PDF-Preview-Status. Servermodus, Bind-Adresse, TLS-Pfade, Trusted Proxies, Root-Mount, Data-Dir und ACME-Modus bleiben file-/restart-basiert.

Runtime-Settings werden als ein validierter Snapshot in SQLite geschrieben und erst danach atomar im Arbeitsspeicher ausgetauscht. Beim Start wird ebenfalls der vollständige Snapshot validiert; gültige gekoppelte Werte hängen nicht von der alphabetischen Schlüsselreihenfolge ab.

ZIP-Downloads werden durchgehend im ZIP64-Format erzeugt. `max_zip_size` begrenzt die Summe der Quelldaten und `max_zip_files` die Dateianzahl; der Wert `0` deaktiviert die jeweilige separate Grenze. Die Prüfung des freien temporären Speicherplatzes, der Überlaufschutz und das auch für ZIP-Scans geltende `max_search_entries` bleiben unabhängig davon aktiv.

## 5. Routen- und API-Design

| Route | Methode | Zweck |
|---|---:|---|
| `/login`, `/mfa`, `/logout` | GET/POST | zweistufige Adminauthentifizierung |
| `/locale` | POST | Deutsch/Englisch-Auswahl im gehärteten Locale-Cookie speichern |
| `/admin` | GET | Root-begrenzter Dateibrowser |
| `/admin/account` | GET | aktuellen Benutzer und eigene Credential-Aktionen anzeigen |
| `/admin/account/password` | POST | eigenes Passwort nach erneuter Passwortprüfung ändern |
| `/admin/account/mfa/start`, `/admin/account/mfa/confirm` | POST | TOTP-Wechsel beginnen und mit dem neuen Code bestätigen |
| `/admin/account/security-keys/register/start`, `/admin/account/security-keys/register/finish` | POST | WebAuthn/FIDO2-Sicherheitsschlüssel registrieren |
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
| `/v/:token/download` | GET/HEAD | Streaming, einzelner Byte-Range, `206`/`416`; HEAD prüft die Transferquote, zählt und reserviert aber nicht |
| `/v/:token/download.zip` | GET | limitierter ZIP-Download für Ordner |
| `/v/:token/upload` | POST | exklusiver Ordnerupload |
| `/s/:alias` | GET | rate-limitierter Kurzlink; neue Aliase haben 12–32 Zeichen |

`max_downloads` begrenzt abgeschlossene Inhaltsübertragungen (Download, ZIP und gezählte Vorschau), nicht den Aufruf der öffentlichen Metadaten-/Landingpage oder Uploads. `HEAD` liefert nur dann Metadaten, wenn derselbe logische `GET` mit der aktuellen Transfer-Session beginnen dürfte, verbraucht selbst aber keine Quote.

Zusätzlich gibt es eine session-basierte JSON-API unter `/api/v1`. Sie nutzt dieselben sicheren Cookies, MFA-Sessions, CSRF-Regeln, SecureFS-Zugriffe, SQLite-Operationen und Audit-Events wie die HTML-UI. In `0.4.1` gibt es bewusst keine API-Tokens; mutierende Admin-API-Routen verlangen den Header `X-CSRF-Token`.

Bei passwortgeschützten öffentlichen Shares liefert die Metadatenroute vor dem Unlock ausschließlich `{"locked":true}`. Clients müssen nach erfolgreichem Unlock mit dem gesetzten API-Cookie erneut abfragen; Pfad, Berechtigung und Transferzähler werden vorher nicht offengelegt.

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
| `/api/v1/public/shares/:token/download` | GET/HEAD | delegiert auf sichere Streaming- und HEAD-Quotenlogik |
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

Die Admin-UI bietet Login, MFA, Dateibrowser, Linkverwaltung, Admin-Anlage, Einstellungen, Audit und „Mein Konto“. Dort kann der angemeldete Benutzer nach erneuter Passwortprüfung das eigene Passwort ändern, TOTP zweistufig ersetzen und mehrere WebAuthn/FIDO2-Sicherheitsschlüssel registrieren. Hardware-MFA wird erst ab zwei registrierten Schlüsseln aktiviert; der Bestand darf nicht von zwei auf einen reduziert werden. TOTP und der lokale SSH-Recovery-Pfad bleiben als Wiederherstellung verfügbar.

WebAuthn-Credentials sind fest an RP-ID und Browser-Origin gebunden. Die Registrierung muss deshalb über die endgültige öffentliche HTTPS-URL erfolgen. Der Setup-Tunnel auf `127.0.0.1:8090` ist nur für Bootstrap/TOTP gedacht und kann keinen Schlüssel für die spätere öffentliche Domain registrieren. Die WebAuthn-Origin wird beim Prozessstart aus `server.public_base_url` übernommen; eine Änderung der Domain erfordert die erneute Registrierung aller Sicherheitsschlüssel.

Setup, Login, Admin- und Public-Seiten sind auf Deutsch und Englisch verfügbar. Eine explizite Auswahl im `vaultlink_locale`-Cookie hat Vorrang vor `Accept-Language`; für unbekannte oder fehlende Browser-Sprachen ist Englisch der Fallback. Dynamische Benutzernamen, Dateinamen, Aliase und Auditwerte werden dabei nicht übersetzt.

Der Dateibrowser hat Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der aktuellen Auswahl.

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
sudo apt update && sudo apt install -y build-essential cifs-utils coreutils curl libssl-dev pkg-config sqlite3 util-linux
cargo build --release --locked

sudo useradd --system --home /var/lib/vaultlink --shell /usr/sbin/nologin vaultlink
sudo install -d -o root -g vaultlink -m 0750 /opt/vaultlink /etc/vaultlink /etc/vaultlink/tls
sudo install -d -o vaultlink -g vaultlink -m 0750 /var/lib/vaultlink /var/log/vaultlink
sudo install -o root -g root -m 0755 target/release/vaultlink /opt/vaultlink/vaultlink
sudo install -o root -g root -m 0644 deploy/vaultlink.service /etc/systemd/system/vaultlink.service
sudo systemctl daemon-reload
```

`ReadWritePaths=/mnt/storage` in [deploy/vaultlink.service](deploy/vaultlink.service) an die geprüfte Mount-Basis anpassen. Für SMB außerdem [deploy/mnt-storage.mount.example](deploy/mnt-storage.mount.example) als `/etc/systemd/system/mnt-storage.mount` und [deploy/vaultlink-external-storage.conf](deploy/vaultlink-external-storage.conf) als systemd-Drop-in installieren. `What`, Credentials, UID/GID und UNC-Quelle müssen zur Konfiguration passen. Die Credential-Datei gehört `root:root` mit Modus `0600`.

### Erstkonfiguration im Browser über SSH-Tunnel

Das Setup lauscht absichtlich nur auf Loopback. Auf einem Server ohne grafische Oberfläche läuft der Browser auf dem eigenen Rechner; der SSH-Tunnel transportiert die Verbindung verschlüsselt zum lokalen Setup-Listener. Zuerst eine normale SSH-Sitzung zum Server öffnen:

```sh
ssh admin@server.example.com
```

In dieser Sitzung das Setup als späteren Dienstbenutzer starten. Die Konfiguration wird zunächst in einem privaten Staging-Verzeichnis abgelegt, weil `/etc/vaultlink` bewusst nicht für den Dienstbenutzer schreibbar ist:

```sh
sudo install -d -o vaultlink -g vaultlink -m 0700 /var/lib/vaultlink/setup
sudo -u vaultlink /opt/vaultlink/vaultlink setup \
  --config /var/lib/vaultlink/setup/config.toml \
  --listen 127.0.0.1:8090
```

Das Setup gibt einen expliziten IPv4-Tunnel aus. Diesen in einem zweiten Terminal auf dem eigenen Rechner öffnen und offen lassen; `-4` erzwingt IPv4 auch für die SSH-Verbindung:

```sh
ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 admin@server.example.com
```

Danach die ausgegebene lokale URL `http://127.0.0.1:8090/?token=...` auf dem eigenen Rechner öffnen. Für den empfohlenen Reverse-Proxy-Modus sind `127.0.0.1:8080` als **VaultLink-Dienstadresse nach dem Setup**, die öffentliche HTTPS-URL, der sichtbare Storage-Unterordner und `/var/lib/vaultlink` als Data Directory passende Werte. Production verlangt zusätzlich das private Geschwisterverzeichnis, den exakten Dateisystemtyp und die aktive Mount-Quelle. Für direkte Standard-SMB-Co-Writer wird „Externe SMB-Schreiber“ aktiviert. Root, internes Verzeichnis und Data Directory müssen vorher provisioniert sein; das Setup prüft die aktive Mount-Identität und schreibt bei einem Alias, Fallback oder Netzwerk-SQLite weder Konfiguration noch Admin-Secrets. Der SSH-Tunnel gilt nur für das Setup; die spätere öffentliche URL läuft über den konfigurierten Reverse Proxy.

Nach dem Speichern des TOTP-Secrets auf der Bestätigungsseite nicht den direkten Serverstart wählen, sondern den Setup-Prozess im Serverterminal mit `Strg+C` beenden. Anschließend die erzeugte Konfiguration mit restriktiven Rechten installieren, das Staging-Verzeichnis entfernen und den Systemdienst starten:

Das Browser-Setup schreibt die vollständige `[storage]`-Policy. Die angezeigte Mount-Quelle muss vor dem Speichern mit `/proc/self/mountinfo` abgeglichen werden; bei SMB sind außerdem die serverseitigen ACLs aus dem Abschnitt oben vorab mit dem VaultLink-Konto und jedem Co-Writer-Konto zu testen.

```sh
sudo install -o root -g vaultlink -m 0640 \
  /var/lib/vaultlink/setup/config.toml /etc/vaultlink/config.toml
sudo -u vaultlink rm /var/lib/vaultlink/setup/config.toml
sudo rmdir /var/lib/vaultlink/setup
sudo -u vaultlink test -r /etc/vaultlink/config.toml
sudo systemctl enable --now vaultlink
```

So bleiben Konfiguration und TLS-Pfade unter Kontrolle von `root`, während Datenbank und Laufzeitdaten von Anfang an `vaultlink` gehören. Das Setup darf nicht mit `--listen 0.0.0.0:8090` ins LAN gestellt werden; eine Nicht-Loopback-Ausnahme gibt es bewusst nicht.

### Alternative: Konfiguration ohne Web-Setup

Wer die Beispielkonfiguration manuell anpasst, installiert sie direkt und legt den ersten Admin im Terminal an:

```sh
sudo install -o root -g vaultlink -m 0640 config/production-reverse-proxy.toml /etc/vaultlink/config.toml
sudo -u vaultlink /opt/vaultlink/vaultlink init-admin --config /etc/vaultlink/config.toml --username admin
sudo systemctl enable --now vaultlink
```

### Lokale Admin-Wiederherstellung

Wenn Passwort oder MFA des einzigen Admins verloren wurden, erfolgt die Wiederherstellung bewusst über den bereits vorausgesetzten SSH-/Hostzugriff. Den Befehl immer als Dienstbenutzer `vaultlink` ausführen, damit SQLite-Datenbank sowie WAL-/SHM-Dateien nicht versehentlich dem Benutzer `root` gehören:

```sh
# Nur das Passwort neu setzen
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password

# Nur MFA neu einrichten
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-mfa

# Passwort und MFA gemeinsam und atomar ersetzen
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --config /etc/vaultlink/config.toml \
  --username admin \
  --reset-password \
  --reset-mfa
```

Der Passwortwert wird interaktiv und ohne Kommandozeilenargument abgefragt. Bei einem MFA-Reset folgt nach dem erfolgreichen Datenbank-Commit ein einmaliger Ausgabeblock mit dem neuen TOTP-Secret und der zugehörigen `otpauth://`-URI. Jede Wiederherstellung widerruft alle Sessions und noch nicht abgeschlossene MFA-Neuregistrierungen dieses Admins und schreibt ein Audit-Ereignis ohne Credential-Inhalte.

Falls die normale Konfiguration beschädigt oder wegen fehlender TLS-Dateien nicht mehr validierbar ist, kann der Notfallpfad direkt auf die Datenbank zeigen:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink recover-admin \
  --database /var/lib/vaultlink/data.sqlite \
  --username admin \
  --reset-password \
  --reset-mfa
```

Ein stillgelegter Admin bleibt auch nach der Credential-Wiederherstellung stillgelegt. Ein dauerhaft öffentlicher Passwort-/MFA-Reset-Endpunkt ist absichtlich nicht vorhanden.

Firewall: bei Reverse Proxy nur 80/443 für Caddy/Nginx öffnen und VaultLink auf Loopback lassen. Bei Standalone nur 443 öffnen.

## 9. Linux-Entwicklung, optional in WSL

```sh
sudo apt update && sudo apt install -y build-essential coreutils curl libssl-dev pkg-config sqlite3 util-linux
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
- Upload 409: Standard ist no-overwrite. Ohne externe Writer kann Ersetzen pro Upload-Link freigegeben und pro Upload bestätigt werden; im Co-Writer-Modus bleibt es gesperrt.
- SMB-Start verweigert: Mount-Quelle/-Typ und Optionen in `/proc/self/mountinfo`, vorhandene sibling-Verzeichnisse, Modus `0700`, Server-ACL sowie das lokale SQLite-Dateisystem prüfen.
- TLS nach Renewal alt: `systemctl status vaultlink`, PEM-Rechte und Journal prüfen.

## Lizenz

MIT.
