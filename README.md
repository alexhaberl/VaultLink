# VaultLink

VaultLink ist eine serverseitig gerenderte Webanwendung, die einen bereits gemounteten Ordner sicher über zeitlich begrenzbare Download- und Upload-Links freigibt. Ziel ist Debian Linux; Entwicklung und Tests funktionieren ebenso unter Debian/Ubuntu in WSL. VaultLink verwendet keine Cloud- oder externen Laufzeitdienste.

> Status: `0.1.0-beta.1`-Kandidat für ein privates Debian-13-amd64-Prerelease. Ein Tag wird erst nach den Gates in [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md) gesetzt.

## 1. Architekturentscheidung: Rust

Rust wurde Go vorgezogen. Beide liefern einzelne Linux-Binaries und gute HTTP-Server. Für VaultLinks risikoreichste Bereiche – Pfad- und Dateiverarbeitung, nebenläufige Zähler, Multipart-Streaming und langlebige Sessions – bietet Rust zusätzliche Speicher- und Typensicherheit ohne Garbage-Collector. Axum/Tokio sind schlank, gut testbar und bauen auf dem etablierten Tower-Ökosystem auf. Der höhere Build-Aufwand ist für einen langlebigen Internetdienst vertretbar.

Stack: Rust stable, Axum/Tokio, Tower-Middleware, Rusqlite/SQLite, Argon2id, selbst getestete RFC-6238-TOTP-Validierung, Rustls und `tracing`. HTML wird bewusst mit kleinen serverseitigen Renderfunktionen erzeugt; es gibt kein JavaScript und keine Frontend-Buildchain.

## 2. Sicherheitskonzept

- Linux-Dateizugriffe sind descriptor-relativ. `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` bindet Listing, Metadaten, Download und Upload an den beim Start geöffneten Root-Descriptor; ein Kernel ohne `openat2` wird mit verständlichem Startfehler abgewiesen. Relative Nutzpfade verbieten absolute Pfade, `..`, Backslashes, NUL, doppelte Prozentkodierung und ungültiges UTF-8.
- Uploadnamen dürfen keine Separatoren oder Steuerzeichen enthalten. Uploads werden als zufällige `0600`-Temporärdatei im bereits geöffneten Zielordner geschrieben, geflusht und per `fsync` gesichert. `renameat2(RENAME_NOREPLACE)` veröffentlicht atomar ohne Überschreiben; Drop/Abbruch entfernt `.part`-Dateien.
- Adminpasswörter verwenden Argon2id mit zufälligem Salt. Nach dem Passwort ist TOTP zwingend. Undurchsichtige Sessiontokens werden nur SHA-256-gehasht indiziert, serverseitig gespeichert und als `HttpOnly`, `SameSite=Strict` sowie produktiv `Secure` gesetzt.
- Login-Limits gelten pro effektiver Client-IP und Benutzername. Forwarded-Header werden ausschließlich im Reverse-Proxy-Modus und nur von explizit vertrauenswürdigen Peer-Adressen ausgewertet.
- Alle mutierenden Adminaktionen verlangen ein sitzungsgebundenes CSRF-Token. CSP, `nosniff`, Frame-Schutz, Referrer-/Permissions-Policy und – nur bei echtem HTTPS – HSTS werden gesetzt.
- Share-Tokens besitzen 192 Bit Entropie. Optionale Share-Passwörter sind Argon2id-gehasht; Freischaltungen verwenden gehashte, share-spezifische Ein-Stunden-Tokens und fünf Versuche pro Share/IP in fünf Minuten. Ablauf, Status und Downloadlimit werden bei jedem Zugriff geprüft; das Heraufzählen eines Downloads erfolgt atomar in SQLite.
- Audit-Ereignisse liegen in SQLite und werden strukturiert an journald gespiegelt. Sie enthalten keine Passwörter, TOTP-Secrets, Sessiontokens oder Share-Tokens. Die SQLite-Datei ist als Secret zu behandeln.
- VaultLink führt Dateien nie aus. Der empfohlene systemd-Sandbox schützt das restliche System. Der Mount selbst darf keine vom Service-User ausführbaren Programme in Systempfade bringen.

Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner; VaultLink ersetzt keine vorhandenen Dateien. ZIP-Downloads, Suche und Audit-Dashboard sind nicht Teil dieses Releases. Ein Alias (`/s/name`) und Passwortschutz sind enthalten.

## 3. Projektstruktur

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, Serverstart, TLS
│   ├── config.rs           TOML und Startvalidierung
│   ├── auth.rs             Argon2id, TOTP, Rate Limit
│   ├── db.rs               Schema, Sessions, Shares, Audit
│   ├── path_security.rs    Pfad- und Symlink-Grenzen
│   ├── secure_fs.rs        openat2/renameat2 und atomare Uploads
│   ├── range.rs            einzelner HTTP-Byte-Range-Parser
│   ├── proxy.rs            vertrauenswürdige Proxy-Header
│   └── web.rs              Routen, HTML, Upload/Download
├── config/                 drei Beispielkonfigurationen
├── deploy/                 systemd, Caddy, ACME-Hook
├── docs/                   Upgrade, Rollback, Release-Gates
├── fuzz/                   Pfad-, Range- und Dateinamen-Fuzzing
├── Makefile
└── Cargo.toml
```

## 4. Daten- und Persistenzmodell

SQLite ist JSON/TOML-Dateien mit Locking vorzuziehen: eindeutige Aliase, parallele Sessions, atomare Downloadlimits und crash-feste Transaktionen sind Kernanforderungen. WAL ist aktiv. Tabellen: `admins`, `sessions`, `shares`, `public_unlock_sessions`, `audit`. Transaktionsmigrationen verwenden `PRAGMA user_version`; ein unbekanntes neueres Schema verweigert den Start. Die Datenbank liegt standardmäßig in `/var/lib/vaultlink/data.sqlite` und muss `vaultlink:vaultlink 0600` gehören.

Upgrade mit Backup bei gestopptem Dienst:

```sh
sudo deploy/vaultlink-upgrade.sh /pfad/zum/neuen/vaultlink
```

Das Skript nutzt SQLite `.backup`, prüft `PRAGMA integrity_check` und bewahrt Binary und Datenbank unter `/var/lib/vaultlink/backups/` auf. Restore und manuelles Rollback beschreibt [`docs/UPGRADE-ROLLBACK.md`](docs/UPGRADE-ROLLBACK.md). Der Mountpoint wird unabhängig gesichert.

## 5. Konfigurationsmodell

Beispiele: [`config/development.toml`](config/development.toml), [`config/production-reverse-proxy.toml`](config/production-reverse-proxy.toml), [`config/production-standalone-tls.toml`](config/production-standalone-tls.toml).

Beim Start gelten harte Regeln: Development bindet nur Loopback und HTTP; Reverse Proxy verlangt Produktionsmodus, HTTPS-Basis-URL, mindestens einen Trusted Proxy und kein App-TLS; Standalone verlangt Produktionsmodus, HTTPS-URL, aktiviertes TLS sowie vorhandenes Zertifikat/Key. Produktionscookies müssen `Secure` sein. HSTS ist in Development verboten.

Eine separate `session_secret` ist nicht nötig: Sessions sind zufällige serverseitige Bearer-Tokens, deren Hash in SQLite liegt. Eine Datenbankkopie allein offenbart keine aktiven Cookies. TLS-Key und SQLite bleiben dennoch schützenswerte Secrets.

## 6. Routen- und API-Design

| Route | Methode | Zweck |
|---|---:|---|
| `/login`, `/mfa`, `/logout` | GET/POST | zweistufige Adminauthentifizierung |
| `/admin` | GET | Root-begrenzter Dateibrowser |
| `/admin/shares` | GET/POST | Links auflisten/erstellen |
| `/admin/shares/:id/toggle` | POST | aktivieren/deaktivieren |
| `/admin/shares/:id/password` | POST | Passwort setzen/ersetzen/entfernen |
| `/admin/shares/:id/delete` | POST | löschen |
| `/v/:token` | GET | öffentliche Datei-/Ordnerseite |
| `/v/:token/unlock` | POST | passwortgeschützte Freigabe entsperren |
| `/v/:token/download` | GET/HEAD | Streaming, einzelner Byte-Range, `206`/`416` |
| `/v/:token/upload` | POST | exklusiver Ordnerupload |
| `/s/:alias` | GET | validierter Kurzlink |

Es gibt absichtlich keine öffentliche JSON-API. Interne absolute Pfade werden nie gerendert.

## 7. UI und UX

Login, MFA, Dateibrowser, Linkformular/-liste sowie öffentliche Download-/Uploadseiten sind responsiv. Berechtigungen, Passwortschutz und Status sind sichtbar; Hashes und Klartextpasswörter nie. Ein kleines, statisch ausgeliefertes und durch `script-src 'self'` begrenztes Script stellt den Copy-Button bereit; es gibt keine externe Frontend-Abhängigkeit. Verzeichnisse liefern descriptor-relativ höchstens 100 Einträge pro Seite.

## 8. HTTPS- und Betriebsmodi

### Development

Nur `127.0.0.1`, HTTP, kein Secure-Cookie und kein HSTS. Dies ist niemals ein Internetmodus.

### Reverse Proxy (empfohlen)

VaultLink lauscht auf `127.0.0.1:8080`; Caddy terminiert HTTPS. Die Beispiel-[`Caddyfile`](deploy/Caddyfile) genügt für Caddys Standard-ACME. Für ZeroSSL kann entweder Caddys ZeroSSL-Issuer oder die unten beschriebene externe Pipeline verwendet werden. Bei externen Zertifikaten referenziert Caddy die deployten PEM-Dateien.

```sh
sudo install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Läuft der Reverse Proxy auf einem anderen Host, muss der LAN-Bind ausdrücklich freigeschaltet und zusätzlich auf Betriebssystemebene begrenzt werden:

```toml
[server]
mode = "reverse_proxy"
listen_address = "0.0.0.0:8080"
public_base_url = "https://vaultlink.example.com"
production_mode = true

[reverse_proxy]
enabled = true
allow_non_loopback = true
trusted_proxies = ["192.0.2.10"]
trust_x_forwarded_headers = true
```

Die Vorlage [`deploy/vaultlink-external-proxy-network.conf`](deploy/vaultlink-external-proxy-network.conf) wird mit der echten Proxy-IP nach `/etc/systemd/system/vaultlink.service.d/external-proxy-network.conf` installiert. Sie blockiert Portzugriff für alle anderen Quelladressen über systemd-cgroup-BPF. Nach Änderungen sind `systemctl daemon-reload` und ein VaultLink-Neustart erforderlich. `allow_non_loopback=true` ohne diese Netzwerkbegrenzung ist nicht als sicherer Produktionsbetrieb vorgesehen.

Für Nginx Proxy Manager: Scheme `http`, Forward Hostname/IP auf die VaultLink-VM, Forward Port `8080`, SSL-Zertifikat aktivieren und „Force SSL“ einschalten. Für große Streaming-Uploads im Advanced-Block:

```nginx
client_max_body_size 1g;
proxy_request_buffering off;
proxy_buffering off;
```

Nginx muss `X-Forwarded-For`, `X-Forwarded-Proto` und `X-Forwarded-Host` setzen. VaultLink wertet Forwarded-Clientdaten ausschließlich aus, wenn der direkte TCP-Peer in `trusted_proxies` steht; öffentliche URLs werden immer aus `public_base_url` erzeugt.

### Standalone TLS

Rustls liest Fullchain und Key beim Prozessstart. Mit `reload_on_cert_change=true` lädt `systemctl reload vaultlink` die PEM-Dateien per SIGHUP; ein fehlerhaftes neues Zertifikat lässt die bisherige TLS-Konfiguration aktiv. Der Deploy-Hook nutzt `reload-or-restart`. Für Port 443 wird nur im Standalone-Modus das Drop-in `vaultlink-standalone-capability.conf` installiert. Alternativ bindet VaultLink auf 8443 und die Firewall leitet weiter. HTTP→HTTPS bleibt Aufgabe von Reverse Proxy oder Firewall.

## 9. Testkonzept

Unit- und HTTP-Integrationstests decken Argon2, RFC-TOTP, Login/MFA/Logout, Session/CSRF, Rate-Limits, Security Headers, Passwort-Unlock, Share-Rechte, Range/HEAD, Migrationserhalt, atomare Downloadlimits, Upload-Noclobber/-Cleanup/-Parallelität, Traversal/Encoding, Linux-Symlink-Races, Proxy-Vertrauen und Config-Modi ab. Sie nutzen In-Memory-SQLite bzw. `tempfile`, verändern keinen Produktionsmount und benötigen nach dem Dependency-Fetch kein Netzwerk.

```sh
make test
make security-test
make lint
```

Die Fuzz-Ziele liegen unter `fuzz/`; vor dem Tag läuft jedes Ziel zehn Minuten. Dependency-, Last- und 72-Stunden-Soak-Gates stehen in [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md).

Die ausgelieferten systemd-Schutzoptionen erreichen auf Debian 13 mit `systemd-analyze security` einen Exposure-Wert von 1.5 (`OK`). Die Basiseinheit besitzt keine Linux-Capabilities. Nur das optionale Standalone-Port-443-Drop-in setzt gezielt `CAP_NET_BIND_SERVICE` frei.

## 10. Debian-Deployment

```sh
sudo apt update && sudo apt install -y build-essential pkg-config
# Rust stable als Build-User via rustup installieren
cargo build --release --locked

sudo useradd --system --home /var/lib/vaultlink --shell /usr/sbin/nologin vaultlink
sudo install -d -o root -g vaultlink -m 0750 /opt/vaultlink /etc/vaultlink /etc/vaultlink/tls
sudo install -d -o vaultlink -g vaultlink -m 0750 /var/lib/vaultlink /var/log/vaultlink
sudo install -o root -g root -m 0755 target/release/vaultlink /opt/vaultlink/vaultlink
sudo install -o root -g vaultlink -m 0640 config/production-reverse-proxy.toml /etc/vaultlink/config.toml
sudo install -o root -g root -m 0644 deploy/vaultlink.service /etc/systemd/system/vaultlink.service
sudo systemctl daemon-reload
```

Passen Sie `ReadWritePaths=/mnt/storage` in der Unit an den echten Mount an. Für reine Downloads kann der Mount read-only sein; Uploadlinks benötigen Schreibrechte ausschließlich in vorgesehenen Zielordnern. Admin initialisieren:

```sh
sudo -u vaultlink /opt/vaultlink/vaultlink init-admin --config /etc/vaultlink/config.toml --username admin
sudo systemctl enable --now vaultlink
```

Firewall: bei Reverse Proxy nur 80/443 für Caddy/Nginx öffnen und 8080 auf Loopback lassen. Bei Standalone nur 443 öffnen. Updates erfolgen mit `deploy/vaultlink-upgrade.sh`, niemals durch Überschreiben des laufenden Binarys. `journalctl -u vaultlink` enthält strukturierte Betriebs- und Auditlogs, aber keine Credentials.

## ZeroSSL Auto-Renewal Setup

Voraussetzungen: DNS zeigt auf den Server, Ports/Challenge sind erreichbar, `curl`, `socat` und [acme.sh](https://github.com/acmesh-official/acme.sh) sind installiert. ZeroSSL stellt im Developer Portal EAB Key ID und HMAC Key bereit. Diese Werte dürfen nie in Shell-History oder Journald landen.

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/vaultlink/zerossl.env
sudoedit /etc/vaultlink/zerossl.env
```

Inhalt (echte Werte nur dort eintragen):

```sh
ZEROSSL_EAB_KID='...'
ZEROSSL_EAB_HMAC_KEY='...'
VAULTLINK_DOMAIN='files.example.com'
```

Account und Erstzertifikat in einer Root-Shell registrieren; Variablen nicht ausgeben:

```sh
set -a; . /etc/vaultlink/zerossl.env; set +a
/root/.acme.sh/acme.sh --register-account --server zerossl \
  --eab-kid "$ZEROSSL_EAB_KID" --eab-hmac-key "$ZEROSSL_EAB_HMAC_KEY" \
  --email admin@example.com
/root/.acme.sh/acme.sh --issue --server zerossl --standalone -d "$VAULTLINK_DOMAIN"
sudo install -o root -g root -m 0755 deploy/vaultlink-cert-deploy.sh /usr/local/libexec/vaultlink-cert-deploy.sh
/root/.acme.sh/acme.sh --install-cert -d "$VAULTLINK_DOMAIN" \
  --fullchain-file /etc/vaultlink/tls/fullchain.pem \
  --key-file /etc/vaultlink/tls/privkey.pem \
  --reloadcmd "/usr/local/libexec/vaultlink-cert-deploy.sh /root/.acme.sh/${VAULTLINK_DOMAIN}_ecc/fullchain.cer /root/.acme.sh/${VAULTLINK_DOMAIN}_ecc/${VAULTLINK_DOMAIN}.key"
sudo chown root:vaultlink /etc/vaultlink/tls/*.pem
sudo chmod 0640 /etc/vaultlink/tls/*.pem
```

Bei RSA statt ECC unterscheiden sich die acme.sh-Pfade; mit `acme.sh --info -d "$VAULTLINK_DOMAIN"` prüfen und den Hook entsprechend setzen. Für einen laufenden Caddy/Nginx ist DNS-01 oder Webroot statt `--standalone` erforderlich, damit Port 80 nicht kollidiert.

Timer installieren und testen:

```sh
sudo install -m 0644 deploy/vaultlink-cert-renew.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vaultlink-cert-renew.timer
sudo systemctl start vaultlink-cert-renew.service
sudo systemctl status vaultlink-cert-renew.service
sudo systemctl list-timers vaultlink-cert-renew.timer
```

`acme.sh --cron` entscheidet täglich selbst, ob erneuert wird. Der Hook prüft nichtleere Quelldateien, installiert beide PEMs mit `root:vaultlink 0640`, tauscht sie atomar innerhalb des Zielverzeichnisses und führt danach `systemctl reload-or-restart vaultlink` aus. Troubleshooting: `journalctl -u vaultlink-cert-renew`, DNS/Firewall und acme.sh-Domainpfade prüfen. EAB-Werte niemals in Logs kopieren. Die Timer-Unit bekommt keinen EAB-Wert als Kommandozeilenargument; EAB wird nur bei Accountregistrierung benötigt.

## 11. WSL-Entwicklung

WSL mit Debian/Ubuntu installieren, Repository innerhalb des Linux-Dateisystems bevorzugen und dann:

```sh
sudo apt update && sudo apt install -y build-essential curl pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
make dev-setup
cargo run -- init-admin --config config/development.toml --username admin
make run
```

`make sample-data` erzeugt `dev/mount` und `dev/data`. Auf `http://localhost:8080/login` anmelden. WSL benötigt weder systemd noch TLS. Tests: `make test`, Build: `make build`.

## Troubleshooting

- **Start verweigert:** Config-Modus, HTTPS-URL, Loopback/Trusted Proxies, PEM-Pfade und Storage-Root prüfen.
- **403 bei Datei:** Der validierte Pfad oder ein Symlink verlässt den per Descriptor geöffneten Root; das ist beabsichtigt.
- **Upload 409:** VaultLink überschreibt nie. Datei umbenennen oder administrativ entfernen.
- **Login gesperrt:** fünf Fehler innerhalb fünf Minuten; Fenster abwarten. Neustart leert nur den in-memory Rate-Limiter, nicht Sessions.
- **TLS nach Renewal alt:** `systemctl status vaultlink`, PEM-Rechte und Journal des Renewal-Service prüfen.

## Build und Lizenz

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release --locked
```

### Lokaler Validierungsstatus (7. Juli 2026)

Für den aktuellen Beta-Code sind Windows-Formatierung, Clippy mit `-D warnings`, 35 Tests einschließlich HTTP-Login/MFA/CSRF/Logout, Passwort-Unlock, Range/HEAD, Uploadlimit/-Konflikt/-Cleanup, Migration und parallelem Upload-Noclobber sowie `cargo-audit 0.22.2 --deny warnings` grün. Die Linux-spezifischen `openat2`-/`renameat2`-Tests, Fuzz-, Last-, öffentlicher Nginx- und 72-Stunden-Soak-Gates müssen vor dem Tag noch vollständig grün sein; maßgeblich ist die Release-Checkliste.

Projektbeschreibung für GitHub: **VaultLink – secure, self-hosted file and folder sharing for an existing Linux mountpoint, built in Rust.**

Lizenz: MIT.
