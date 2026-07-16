# VaultLink

VaultLink ist eine serverseitig gerenderte Rust-Webanwendung, die einen bereits gemounteten Linux-Ordner sicher über öffentliche Download- und Upload-Links freigibt. Unterstützte Hostplattformen sind Linux x86_64 und aarch64; Windows-Hostsupport ist ab 0.4.1 entfernt. Windows-, macOS- und Linux-Clients bleiben über einen externen Standard-SMB-Server interoperabel.

Status: `0.5.0` ist als nächster Release für Debian 13 auf amd64 und arm64 geplant. Die Release-Linie ist erst veröffentlicht, sobald der signierte, annotierte Tag `v0.5.0` verfügbar ist. Details zum Umfang und zu den noch offenen Freigabeschritten stehen im [Changelog](CHANGELOG.md) und in der [Release-Checkliste](docs/RELEASE-CHECKLIST.md).

## 1. Sicherheitskonzept

Erfolgreiche sicherheitsrelevante SQLite-Mutationen und ihre Auditzeilen teilen eine `IMMEDIATE`-Transaktion. Ein Auditfehler rollt die Mutation zurueck; die JSON-API antwortet mit `503 audit_unavailable`. Abgelehnte Logins und andere reine Beobachtungen bleiben Best Effort, weil keine Fachmutation zurueckzurollen ist.

Ist eine Dateioperation bereits im Dateisystem sichtbar, wird ein nachfolgender Auditfehler nicht als fehlgeschlagene Operation ausgegeben. API- und Queue-Clients erhalten `202` plus `audit_durability_uncertain`; Browser zeigen eine Warnung. Clients duerfen diese Antwort nicht automatisch wiederholen. Rename/Delete bleiben im unveraenderten SecureFS-Journal und werden einmalig als Actor `system` ohne Client-IP abgeschlossen.

Anwendungseigene Passwort-, TOTP- und Share-Secret-Puffer verwenden einen zeroisierenden Wrapper ohne allgemeines `Clone`, `Display` oder `Serialize`. Unvermeidbare Kopien sind explizit benannt. Framework-, Serde-, SQLite-, Formatierungs- und Response-Puffer koennen dadurch nicht vollstaendig garantiert bereinigt werden; die Massnahme reduziert Lebensdauer und vermeidbare Kopien.

- Dateizugriffe sind Linux descriptor-relativ. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` bindet Adminzugriffe an den Storage-Root und öffentliche Zugriffe zusätzlich an eine pro Freigabe verengte Directory-/File-Capability. Im Co-Writer-Modus kommt `RESOLVE_NO_SYMLINKS` hinzu, damit externe Writer keinen gespeicherten Share-Pfad umbiegen können. Ein Kernel ohne die benötigten APIs wird mit verständlichem Startfehler abgewiesen.
- Relative Nutzpfade werden nach genau einer HTTP-Dekodierung geprüft und verbieten absolute Pfade, `..`, Backslashes und NUL. Uploadnamen folgen zusätzlich einer plattformübergreifenden Policy, damit Windows-Prefixe und reservierte Namen nie aus dem Zielordner aufgelöst werden.
- Uploads werden als zufällige `0600`-Temporärdateien im geschützten internen Upload-Staging geschrieben, geflusht und per `fsync` gesichert. Die Veröffentlichung in den sichtbaren Baum erfolgt atomar mit `renameat2(RENAME_NOREPLACE)`. Bei `external_writers = true` bleibt Überschreiben in UI, API und Uploadpfad standardmäßig deaktiviert. Der separate Opt-in `allow_external_writer_replace = true` aktiviert bewusst Last-Writer-Wins; parallele neuere SMB-Änderungen können dadurch verloren gehen.
- Abgebrochene Uploadfragmente und ausschließlich als committed markierte Lösch-Tombstones werden in fortsetzbaren Hintergrund-Batches entfernt. Uncommitted Pending-Löschungen und Rollback-Konflikte bleiben als Recovery-Einträge erhalten, statt beim Neustart Daten zu verlieren.
- Adminpasswörter verwenden Argon2id. Nach dem Passwort ist TOTP oder ein registrierter WebAuthn/FIDO2-Sicherheitsschlüssel (zum Beispiel YubiKey) erforderlich. Sessions sind zufällige serverseitige Bearer-Tokens, deren Hash in SQLite liegt.
- Cookies sind `HttpOnly`, `SameSite=Strict` und in Production `Secure`.
- Mutierende Adminaktionen verlangen CSRF. Login und Share-Unlock sind rate-limitiert.
- Im Reverse-Proxy-Modus ist `trusted_proxies` eine exakte TCP-Peer-Allowlist; nur für diese Peers werden zusätzlich Forwarded-Header ausgewertet.
- Security Header: CSP, `X-Content-Type-Options: nosniff`, Frame-Schutz, Referrer-Policy, Permissions-Policy und HSTS nur bei HTTPS.
- Audit liegt in SQLite und wird strukturiert an journald gespiegelt. Passwörter, TOTP-Secrets, Sessiontokens und Share-Tokens werden nicht geloggt.

Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner. Ohne externe Writer kann VaultLink vorhandene Dateien nur ersetzen, wenn ein Admin dies für den konkreten Upload-Link erlaubt und der Public-Uploader das Ersetzen aktiv bestätigt. Ordnerfreigaben unterstützen begrenzt und inkrementell im ZIP64-Format erzeugte ZIP-Downloads, Suche, Upload in navigierten Unterordnern und Preview bei Downloadrecht. Kleine Standardlimits schützen gepufferte Form-/JSON-Routen; nur Uploadrouten erhalten den großen, weiterhin gestreamten Body-Rahmen. Davor begrenzt ein konstanter Streaming-Guard Multipart-Präambel und jeden Headerblock, ohne Dateiinhalte zu sammeln. Upload-only-Freigaben listen keine Inhalte und erlauben keine Preview/Downloads.

## 2. Projektstruktur

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, Serverstart, TLS/ACME
│   ├── config.rs           TOML und Startvalidierung
│   ├── api.rs              stabile JSON-API-Fassade und Router unter /api/v1
│   ├── api/                Auth-, Files-, Shares-, Admin-, Settings- und Public-Handler
│   ├── auth.rs             Argon2id, TOTP, Rate Limit
│   ├── cifs_provision.rs   privilegierte, eng begrenzte CIFS/systemd-Provisionierung
│   ├── db.rs               DB-Fassade, gemeinsame Typen und Transaktionskern
│   ├── db/                 fachliche Auth-, Share-, Transfer-, Settings- und Audit-Operationen
│   ├── file_ops.rs         transaktionale Rename-/Delete-Operationen
│   ├── http_auth.rs        gemeinsame Session-, Cookie-, CSRF- und Audit-Helfer
│   ├── i18n.rs             serverseitige DE-/EN-Lokalisierung
│   ├── multipart_guard.rs  Streaming-Grenzen für Multipart-Header
│   ├── path_security.rs    Pfadvalidierung
│   ├── secure_fs.rs        Secure-FS-Fassade für openat2/renameat2
│   ├── secure_fs/          Capability-, Identity-, Journal-, Upload- und Recovery-Bausteine
│   ├── sensitive.rs        zeroisierende SecretString-Abstraktion
│   ├── services/           transportneutrale Auth-, Share-, Admin- und File-Services
│   ├── storage_mount.rs    Mount- und SMB-Vertrauensgrenze
│   ├── range.rs            einzelner HTTP-Byte-Range-Parser
│   ├── proxy.rs            vertrauenswürdige Proxy-Header
│   ├── runtime.rs          SQLite-Overrides für Policy-Settings
│   ├── setup.rs            lokales Bootstrap-Setup-UI
│   ├── ui.rs               gemeinsame Styles, Icons und UI-Bausteine
│   ├── webauthn.rs         WebAuthn-Ceremony-State und Credentials
│   ├── web.rs              stabile HTML-Fassade, Router und API-Re-Exports
│   └── web/                Middleware, Rendering, Browsing, Transfer, Upload und Fachbereiche
├── config/                 Beispielkonfigurationen
├── deploy/                 systemd, Caddy, Upgrade/Rollback
├── docs/                   Upgrade, Rollback, Release-Gates
├── fuzz/                   Pfad-, Range-, Multipart-, Preview-, Upload- und API-Policy-Fuzzing
├── Makefile
└── Cargo.toml
```

## 3. Daten- und Persistenzmodell

SQLite ist bewusst gewählt: eindeutige Aliase, parallele Sessions, atomare Transferlimits und crash-feste Transaktionen sind Kernanforderungen. WAL ist aktiv. Tabellen: `admins`, `sessions`, `shares`, `public_unlock_sessions`, `public_preview_sessions`, `public_transfer_grants`, `public_transfer_leases`, `public_upload_usage`, `public_upload_reservations`, `runtime_settings`, `audit`, `transfer_monthly_counts`, `transfer_statistics`, `admin_mfa_enrollments`, `admin_webauthn_credentials` und `admin_totp_replay`.

`shares.max_upload_size` ist das optionale Einzeldateilimit; `NULL` nutzt das globale Runtime-Limit. Upload-Shares besitzen zusätzlich die kumulativen Grenzen `max_upload_total_size` und `max_upload_files`, mit einer Basispolicy von 100.000.000.000 Byte und 1000 fail-closed verbuchten Uploads. Das Gesamtlimit wird bei der Erstellung mindestens auf das wirksame Einzeldateilimit angehoben. Byte- und Dateiverbrauch werden vor dem sichtbaren Publish atomar verbucht; scheitert das Publish danach, bleibt der Quotenverbrauch absichtlich bestehen, damit nie eine sichtbare Datei ungezählt bleibt. Migrationen laufen transaktional über `PRAGMA user_version`; unbekannte neuere Schemas verweigern den Start. Die Datenbank liegt standardmäßig in `/var/lib/vaultlink/data.sqlite` und muss `vaultlink:vaultlink 0600` gehören.

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

Jeder Production-Modus verlangt `require_mount = true`, ein pre-provisioniertes privates internes Verzeichnis sowie die exakte aktive Mount-Quelle und den Dateisystemtyp. Damit startet auch eine alte Production-Konfiguration nicht auf einem leeren lokalen Fallback, wenn ihr eigentliches Mount ausgefallen ist. Für lokalen Storage bleibt das interne Verzeichnis ein Geschwisterpfad; die Policy kann beispielsweise so aussehen:

```toml
[storage]
root_mount_path = "/srv/vaultlink/shared"
data_directory = "/var/lib/vaultlink"
internal_directory = "/srv/vaultlink/.vaultlink-internal"
require_mount = true
external_writers = false
allow_external_writer_replace = false
expected_filesystem_type = "ext4"
expected_mount_source = "/dev/mapper/vaultlink"
```

`expected_mount_source` muss exakt dem Source-Feld der aktiven Zeile in `/proc/self/mountinfo` entsprechen; ein `UUID=`-Eintrag aus `/etc/fstab` ist nicht automatisch derselbe Wert. Die Quelle bleibt auch bei lokalem Storage Pflicht, wenn `require_mount = true` gilt: Nur so erkennt VaultLink einen ausgefallenen Mount statt auf ein gleichnamiges lokales Fallback-Verzeichnis zu schreiben. Für auditierten lokalen Storage sind ext2/3/4, XFS, Btrfs, F2FS, Bcachefs und ZFS zugelassen. Root, internes Verzeichnis und Data Directory gehören dem `vaultlink`-Dienstbenutzer und dürfen weder über Gruppen-/Other-Modusbits noch über die POSIX-ACL-Maske schreibbar sein; lokale Co-Writer sind bei `external_writers = false` nicht unterstützt. SQLite darf dabei auf demselben lokalen Mount liegen, aber niemals innerhalb des sichtbaren Baums. Bei CIFS/SMB muss SQLite zusätzlich auf einem getrennten lokalen Dateisystem liegen.

`public_base_url` verwendet kanonische `http://`- beziehungsweise `https://`-Authority-Syntax ohne abschließenden Slash. Basispfade, Zugangsdaten, Query und Fragment sind nicht unterstützt.

### Externer SMB-Server mit Standardclients

VaultLink hostet keinen SMB-Server. Es mountet als Linux-SMB-Client ein bestehendes Share; Windows-, macOS- und Linux-Clients greifen weiterhin direkt und ohne VaultLink-Zusatzsoftware auf dessen Root zu:

```text
//fileserver.example/vaultlink  ->  /mnt/storage = root_mount_path
├── <Benutzerdaten direkt im Share-Root, normale SMB-Clients schreibbar>
└── .vaultlink-internal/        -> internal_directory, nur VaultLink-SMB-Konto
    ├── .vaultlink-instance.lock
    ├── uploads/
    └── tombstones/
```

Die drei internen Verzeichnisse müssen **vor dem ersten Start serverseitig** provisioniert werden. Ihre Server-ACL erlaubt ausschließlich dem separaten VaultLink-SMB-Dienstkonto Lesen, Schreiben, Löschen und Umbenennen. Co-Writer erhalten die benötigten Modify-Rechte für Benutzerdaten direkt im Share-Root, aber keine administrativen Rechte. Für `.vaultlink-internal` müssen Lesen, Schreiben, Löschen, Umbenennen, Parent-`DELETE_CHILD`, ACL-/Owner-Änderungen (`WRITE_DAC`/`WRITE_OWNER`) sowie `chmod`/`chown`/`setfacl`-Äquivalente verweigert sein. VaultLink reserviert den Namen einschließlich case-insensitiver SMB-Aliasse, filtert ihn aus allen Listings und Scans und verbietet in diesem Layout jede Symlink-Auflösung. Die lokal sichtbaren CIFS-Modi `0700`/`0600` sind nur eine zusätzliche Prüfung und kein Beweis für diese Server-ACL.

Pro Storage-Root darf genau **eine** VaultLink-Serverinstanz aktiv sein. Die Lock-Domain ist deshalb nicht frei wählbar: CIFS mit direktem Share-Root und Development verwenden ausschließlich `<root_mount_path>/.vaultlink-internal`; andere erforderliche Mounts verwenden den direkten privaten Geschwisterpfad `<root-parent>/.vaultlink-internal`. Vor Storage-Mutationsproben, Journal-Recovery und Fragment-Cleanup öffnet VaultLink dort `.vaultlink-instance.lock`, prüft die Lock-Semantik mit zwei unabhängigen Deskriptoren und erwirbt einen exklusiven, nicht blockierenden Linux-`flock` bis zum Ende der Serverlaufzeit. Dieselbe bereits gesperrte Internal-Directory-Capability wird an SecureFS übergeben; Device/Inode des konfigurierten Pfads werden vor jeder Startup-Mutation erneut dagegen geprüft, sodass ein Verzeichnistausch während des Handoffs fail-closed endet. Eine zweite Instanz beendet den Start mit einer klaren Fehlermeldung. Active/active-Replikate, Rolling Starts mit überlappenden Prozessen oder getrennte Kopien des internen Verzeichnisses sind nicht unterstützt. Alle Prozesse für dasselbe sichtbare Storage müssen denselben kanonischen Pfad im selben kohärenten Kernel-/SMB-Lock-Domain sehen; ein nur gleichnamiger Pfad auf einem anderen Mount oder Host schützt die Journals nicht. Die Server-ACL muss außerdem verhindern, dass Co-Writer die Lockdatei löschen oder ersetzen.

Für den auditierten Co-Writer-Modus gelten:

- `require_mount = true`, `external_writers = true`, `expected_filesystem_type = "cifs"` und die erwartete UNC-Quelle sind Pflicht. `allow_external_writer_replace = false` bleibt der sichere Standard.
- Der Kernel muss `statx`-Mount-IDs unterstützen (Linux 5.8 oder neuer). Root und interner Geschwisterpfad müssen dieselbe geprüfte Mount-ID nutzen; nur so bleiben Cross-Directory-Renames atomar.
- Client, Mount und SMB-Server müssen kohärente exklusive `flock`-/SMB-Byte-Range-Locks für `.vaultlink-instance.lock` durchsetzen. Schlägt die lokale Semantikprüfung fehl, startet VaultLink fail-closed; mehrere Hosts mit unabhängig gecachten oder getrennten Lockdateien sind keine unterstützte HA-Konfiguration.
- VaultLink prüft `vers=3.1.1`, `seal`, `cache=strict`, `serverino`, `nosuid`, `nodev`, `noexec`, Read-write-Status und verbietet unter anderem `cache=loose`, `nostrictsync`, `noperm`, `noserverino` und `multiuser`.
- Userpfade dürfen weder Symlinks noch verschachtelte Mounts/DFS-Submounts durchqueren.
- `data_directory` und SQLite/WAL bleiben auf einem separaten, explizit unterstützten lokalen Dateisystem; CIFS/NFS für SQLite wird abgewiesen.
- Externe Writer gelten als vertrauenswürdige Publisher des sichtbaren Inhalts. Sie können Dateien verändern oder ersetzen, die ein bestehender VaultLink-Link ausliefert. Diese direkten SMB-Aktionen umgehen VaultLink-Audit, Share-Limits und Web-Policy und müssen deshalb am SMB-Server selbst auditiert werden.
- `allow_external_writer_replace = true` ist ein ausdrücklicher Last-Writer-Wins-Opt-in. Die Veröffentlichung bleibt ein atomarer Rename, kann aber eine neuere parallele Änderung eines SMB-Clients überschreiben, weil Standardclients VaultLinks Storage-Lock nicht verwenden. VaultLink kann diesen Datenverlust nicht zuverlässig erkennen oder verhindern.
- VaultLinks Linux-Mount erzwingt Transportverschlüsselung per SMB `seal`. Zusätzlich muss der externe SMB-Server SMB 3.1.1 Signing und Encryption für **jede** direkte Windows-, macOS- und Linux-Co-Writer-Session verpflichtend machen; VaultLink kann diese separaten Sessions nicht erzwingen. Verschlüsselung ruhender Daten ist Aufgabe des SMB-Servers. Transparenter Zugriff mit Standard-SMB-Clients ist nicht mit einer ausschließlich von VaultLink kontrollierten clientseitigen Inhaltsverschlüsselung vereinbar.

Andere Netzwerkdateisysteme mit externen Schreibern sind in 0.5.0 nicht freigegeben. Ein erkanntes Remote-Dateisystem ohne explizite Mount-Policy wird beim Start abgewiesen. Production verlangt die Policy unabhängig vom gerade erkannten Dateisystem, sodass auch ein ausgefallener CIFS-Mount mit lokal sichtbarem Fallback-Verzeichnis fail-closed bleibt.

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

Zusätzlich gibt es eine session-basierte JSON-API unter `/api/v1`. Sie nutzt dieselben sicheren Cookies, MFA-Sessions, CSRF-Regeln, SecureFS-Zugriffe, SQLite-Operationen und Audit-Events wie die HTML-UI. In `0.5.0` gibt es bewusst keine API-Tokens; mutierende Admin-API-Routen verlangen den Header `X-CSRF-Token`.

Nach erfolgreichem `/api/v1/session/mfa` rotiert VaultLink Sessioncookie und CSRF-Wert. API-Clients müssen deshalb sowohl den neuen `Set-Cookie`-Wert als auch `csrf_token` aus der MFA-Antwort übernehmen; das Pre-MFA-Token ist anschließend ungültig.

Bei passwortgeschützten öffentlichen Shares liefert die Metadatenroute vor dem Unlock ausschließlich `{"locked":true}`. Clients müssen nach erfolgreichem Unlock mit dem gesetzten API-Cookie erneut abfragen; Pfad, Berechtigung und Transferzähler werden vorher nicht offengelegt. Die Unlock-Antwort liefert außerdem `csrf_token`: Browserformulare senden diesen Upload-CSRF-Wert als Multipart-Feld `csrf`, API-Clients im Header `X-VaultLink-Upload-CSRF`.

Wichtige API-Routen:

| Route | Methode | Zweck |
|---|---:|---|
| `/api/v1/health` | GET | Health/Version |
| `/api/v1/session/login` | POST | Passwortprüfung, setzt Session-Cookie |
| `/api/v1/session/mfa` | POST | TOTP-Verifikation und Rotation von Session/CSRF |
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

VaultLink lauscht lokal, z. B. auf `127.0.0.1:8080`; Caddy oder Nginx terminiert HTTPS. `trusted_proxies` ist zugleich die exakte Allowlist der direkten TCP-Peers und die Vertrauensgrenze für Forwarded-Header. Nicht gelistete Peers werden bereits vor der HTTP-Verarbeitung abgewiesen. IPv4-mapped-IPv6-Peers werden vor dem exakten Vergleich auf ihre IPv4-Adresse kanonisiert.

Bei einem externen Proxy muss der nicht lokale Bind zusätzlich mit `allow_non_loopback = true` freigeschaltet werden. Die tatsächliche Proxy-IP und der Peer der lokalen Readiness-Prüfung müssen beide explizit eingetragen sein. Für einen IPv4-Wildcard-Listener ist das `127.0.0.1`, für einen IPv6-Wildcard-Listener `::1`; bei einer konkreten Bind-Adresse ist es diese lokale Adresse. Beispiel:

```toml
[server]
mode = "reverse_proxy"
listen_address = "0.0.0.0:8080"

[reverse_proxy]
enabled = true
allow_non_loopback = true
trusted_proxies = ["192.0.2.10", "127.0.0.1"]
trust_x_forwarded_headers = true
```

`192.0.2.10` ist durch die reale Proxy-IP zu ersetzen. Das passende systemd-Netzwerk-Drop-in ist [deploy/vaultlink-external-proxy-network.conf](deploy/vaultlink-external-proxy-network.conf). Für Nginx/Nginx Proxy Manager bei großen Uploads:

```nginx
client_max_body_size 1g;
proxy_request_buffering off;
proxy_buffering off;
```

### Standalone TLS mit PEM-Dateien

`certificate_source = "files"` liest `cert_file` und `key_file`. Der private Key muss Modus `0400`, `0440`, `0600` oder `0640` haben. Damit bleibt insbesondere `root:vaultlink` mit reinem Gruppen-Leserecht unterstützt; weitere Mitglieder dieser dedizierten Gruppe gehören zur administrativen Vertrauensgrenze. Gruppen-Schreib-/Ausführrechte, alle Rechte für Other sowie Setuid/Setgid/Sticky werden abgewiesen. Mit `reload_on_cert_change = true` lädt `systemctl reload vaultlink` die PEM-Dateien per SIGHUP neu. Fehlerhafte neue PEMs lassen die alte TLS-Konfiguration aktiv.

Für Port 443 ohne Root:

```sh
sudo install -m 0644 deploy/vaultlink-standalone-capability.conf /etc/systemd/system/vaultlink.service.d/standalone-capability.conf
sudo systemctl daemon-reload
sudo systemctl restart vaultlink
```

### Standalone TLS mit Built-in Let's Encrypt

`certificate_source = "letsencrypt"` nutzt `rustls-acme` mit `tls-alpn-01` auf Port 443 und benötigt keinen externen ACME-Client oder Reverse Proxy. Der ACME-Cache liegt unter `data_directory`, z. B. `/var/lib/vaultlink/acme`, und enthält Account-/Zertifikatsdaten. In diesem Modus darf die Runtime-Einstellung `public_base_url` nicht von der Zertifikatsdomain in `config.toml` abweichen; ein Domainwechsel erfolgt in der Datei und wird erst mit einem Neustart aktiviert.

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

Erst mit `letsencrypt_staging = true` und `hsts_enabled = false` testen. Staging-Zertifikate sind absichtlich nicht browser-vertrauenswürdig; HSTS darf dabei nicht aktiv sein. Für Production auf `letsencrypt_staging = false` setzen und danach `hsts_enabled = true` aktivieren. Dieser Modus funktioniert nur, wenn VaultLink selbst aus dem Internet auf Port 443 erreichbar ist. Zertifikatsausstellung und -erneuerung erfolgen vollständig im VaultLink-Prozess.

## 8. Debian-Deployment

Für eine Installation das zur Hostarchitektur passende, signierte Debian-13-Release-Archiv verwenden und vor dem Entpacken Signaturen sowie Prüfsummen nach [docs/UPGRADE-ROLLBACK.md](docs/UPGRADE-ROLLBACK.md) verifizieren. Die folgenden Befehle werden im entpackten Archiv ausgeführt:

```sh
sudo apt update && sudo apt install -y cifs-utils coreutils curl sqlite3 util-linux

sudo useradd --system --home /var/lib/vaultlink --shell /usr/sbin/nologin vaultlink
sudo install -d -o root -g vaultlink -m 0750 /opt/vaultlink /etc/vaultlink /etc/vaultlink/tls
sudo install -d -o vaultlink -g vaultlink -m 0750 /var/lib/vaultlink /var/log/vaultlink
sudo install -o root -g root -m 0755 bin/vaultlink /opt/vaultlink/vaultlink
sudo install -o root -g root -m 0644 deploy/vaultlink.service /etc/systemd/system/vaultlink.service
sudo systemctl daemon-reload
```

`ReadWritePaths=/mnt/storage` in [deploy/vaultlink.service](deploy/vaultlink.service) an die geprüfte Mount-Basis anpassen. Die folgenden Schritte können weiterhin manuell mit [deploy/mnt-storage.mount.example](deploy/mnt-storage.mount.example) und [deploy/vaultlink-external-storage.conf](deploy/vaultlink-external-storage.conf) ausgeführt werden. Für die Standardstruktur `/mnt/storage` steht zusätzlich der eng begrenzte Root-Befehl im nächsten Abschnitt bereit.

### CIFS-Mount sicher provisionieren

Vorher auf dem SMB-Server `.vaultlink-internal/{uploads,tombstones}` mit den oben beschriebenen Server-ACLs anlegen. Benutzerdaten bleiben direkt im Share-Root. Der Linux-Client kann diese ACL-Grenze nicht zuverlässig beweisen und legt die internen Verzeichnisse deshalb nicht ersatzweise mit nur lokalen Modusbits an.

Danach als Root den Mount provisionieren; das Passwort wird ausschließlich interaktiv vom Terminal gelesen und ist kein CLI-Argument:

```sh
sudo /opt/vaultlink/vaultlink provision-cifs \
  --source //fileserver.example/vaultlink \
  --username vaultlink-service \
  --domain EXAMPLE
```

Der Befehl ist absichtlich auf `/mnt/storage` begrenzt. Er erstellt ausschließlich neue Dateien und verweigert das Überschreiben vorhandener Credentials oder systemd-Units. Die Credential-Datei erhält `root:root 0600`; die Mount-Unit erzwingt `vers=3.1.1`, Signing, Verschlüsselung, `cache=strict`, `serverino`, `nosuid`, `nodev` und `noexec`. Bei Aktivierungs-, Identitäts-, Options- oder Layoutfehlern stoppt er die Unit und entfernt die von diesem Versuch neu angelegten Dateien.

Nach erfolgreichem Mount erkennt das Browser-Setup aktive unterstützte lokale Mounts sowie sichere CIFS/SMB3-Mounts. Bei CIFS wird das Share-Root direkt als sichtbarer Root übernommen; lokale Mounts verwenden weiterhin `shared/` mit privatem Geschwisterpfad. `.vaultlink-internal`, Dateisystemtyp und die intern geprüfte Mount-Quelle werden automatisch gesetzt. Bei mehreren Mounts erscheint eine Auswahl; eine laufende Setup-Seite kann die Liste über „Mounts aktualisieren“ neu laden. Die Mount-Quelle wird absichtlich nicht als frei editierbares GUI-Feld angeboten.

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

## 9. Linux-Entwicklung

```sh
sudo apt update && sudo apt install -y build-essential coreutils curl libssl-dev pkg-config sqlite3 util-linux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
make dev-setup
cargo run -- init-admin --config config/development.toml --username admin
make run
```

`make sample-data` erzeugt `dev/mount` und `dev/data`. Wenn Docker verfügbar ist, baut `make docker-smoke` einmalig das digest-gepinnte Debian-13/Rust-Testimage und führt ohne externes Containernetzwerk Setup-, API-, Load-Fixture-, Soak-Evidence- sowie isolierte Upgrade-/Rollback-Fehlertests aus. Die einzelnen Smoke-Ziele bleiben separat verfügbar. `make policy-check` prüft die Supply-Chain-Vorgaben des Projekts.

## Troubleshooting

- Start verweigert: Config-Modus, HTTPS-URL, Loopback/Trusted Proxies, PEM/ACME-Einstellungen und Storage-Root prüfen.
- Built-in ACME scheitert: DNS muss auf den Server zeigen, VaultLink muss selbst Port 443 terminieren, Nginx/Caddy darf nicht davor laufen.
- 403 bei Datei: Pfadvalidierung oder Symlink-Grenze greift.
- Upload 409: Standard ist no-overwrite. Ohne externe Writer kann Ersetzen pro Upload-Link freigegeben und pro Upload bestätigt werden; im Co-Writer-Modus bleibt es gesperrt.
- SMB-Start verweigert: Mount-Quelle/-Typ und Optionen in `/proc/self/mountinfo`, vorhandenes reserviertes `.vaultlink-internal`-Layout, Modus `0700`, Server-ACL sowie das lokale SQLite-Dateisystem prüfen.
- TLS nach Renewal alt: `systemctl status vaultlink`, PEM-Rechte und Journal prüfen.

## Lizenz

MIT.
