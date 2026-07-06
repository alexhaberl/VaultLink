# VaultLink

VaultLink ist eine serverseitig gerenderte Webanwendung, die einen bereits gemounteten Ordner sicher über zeitlich begrenzbare Download- und Upload-Links freigibt. Ziel ist Debian Linux; Entwicklung und Tests funktionieren ebenso unter Debian/Ubuntu in WSL. VaultLink verwendet keine Cloud- oder externen Laufzeitdienste.

> Status: sicherheitsorientiertes MVP. Vor öffentlichem Produktivbetrieb sollten ein unabhängiger Security-Review, Lasttests und ein Backup-/Restore-Test erfolgen.

## 1. Architekturentscheidung: Rust

Rust wurde Go vorgezogen. Beide liefern einzelne Linux-Binaries und gute HTTP-Server. Für VaultLinks risikoreichste Bereiche – Pfad- und Dateiverarbeitung, nebenläufige Zähler, Multipart-Streaming und langlebige Sessions – bietet Rust zusätzliche Speicher- und Typensicherheit ohne Garbage-Collector. Axum/Tokio sind schlank, gut testbar und bauen auf dem etablierten Tower-Ökosystem auf. Der höhere Build-Aufwand ist für einen langlebigen Internetdienst vertretbar.

Stack: Rust stable, Axum/Tokio, Tower-Middleware, Rusqlite/SQLite, Argon2id, selbst getestete RFC-6238-TOTP-Validierung, Rustls und `tracing`. HTML wird bewusst mit kleinen serverseitigen Renderfunktionen erzeugt; es gibt kein JavaScript und keine Frontend-Buildchain.

## 2. Sicherheitskonzept

- Der Storage-Root wird beim Start kanonisiert. Relative Nutzpfade verbieten absolute Pfade, `..`, Backslashes, NUL, doppelte Prozentkodierung und ungültiges UTF-8. Bestehende Ziele werden kanonisiert und müssen unterhalb des Roots liegen. Symlinks nach außen werden verworfen.
- Uploadnamen dürfen keine Separatoren oder Steuerzeichen enthalten. Uploads landen nur in kanonisierten Freigabeordnern, nutzen exklusives `create_new`, überschreiben nie und unvollständige/zu große Dateien werden entfernt.
- Adminpasswörter verwenden Argon2id mit zufälligem Salt. Nach dem Passwort ist TOTP zwingend. Undurchsichtige Sessiontokens werden nur SHA-256-gehasht indiziert, serverseitig gespeichert und als `HttpOnly`, `SameSite=Strict` sowie produktiv `Secure` gesetzt.
- Login-Limits gelten pro effektiver Client-IP und Benutzername. Forwarded-Header werden ausschließlich im Reverse-Proxy-Modus und nur von explizit vertrauenswürdigen Peer-Adressen ausgewertet.
- Alle mutierenden Adminaktionen verlangen ein sitzungsgebundenes CSRF-Token. CSP, `nosniff`, Frame-Schutz, Referrer-/Permissions-Policy und – nur bei echtem HTTPS – HSTS werden gesetzt.
- Share-Tokens besitzen 192 Bit Entropie. Ablauf, Status und Downloadlimit werden bei jedem Zugriff geprüft; das Heraufzählen eines Downloads erfolgt atomar in SQLite.
- Audit-Ereignisse liegen in SQLite und enthalten keine Passwörter, TOTP-Secrets, Sessiontokens oder Share-Tokens. Die SQLite-Datei ist als Secret zu behandeln.
- VaultLink führt Dateien nie aus. Der empfohlene systemd-Sandbox schützt das restliche System. Der Mount selbst darf keine vom Service-User ausführbaren Programme in Systempfade bringen.

Die Boundary-Prüfung schützt gegen normale und webbasierte Angreifer. Wenn ein anderer lokaler Prozess gleichzeitig Verzeichnisstrukturen im Mount böswillig austauschen kann, bleiben klassische Dateisystem-TOCTOU-Rennen möglich. Der Mount und seine lokalen Schreiber müssen daher administrativ vertrauenswürdig sein; für ein adversariales Multi-Writer-Dateisystem wäre eine Linux-`openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`-Schicht erforderlich.

MVP-Grenzen: Datei-Links sind nur `download_only`. Uploadrechte gelten für Ordner, weil sichere Dateiversionierung und Überschreibregeln nicht Teil des MVP sind. ZIP-Downloads, Passwortschutz und Suche sind noch nicht enthalten. Ein Alias (`/s/name`) ist bereits verfügbar. Das optionale Config-Feld `audit_log_path` ist für eine spätere JSONL-Spiegelung reserviert; die maßgebliche Auditquelle ist derzeit SQLite.

## 3. Projektstruktur

```text
VaultLink/
├── src/
│   ├── main.rs             CLI, Serverstart, TLS
│   ├── config.rs           TOML und Startvalidierung
│   ├── auth.rs             Argon2id, TOTP, Rate Limit
│   ├── db.rs               Schema, Sessions, Shares, Audit
│   ├── path_security.rs    Pfad- und Symlink-Grenzen
│   ├── proxy.rs            vertrauenswürdige Proxy-Header
│   └── web.rs              Routen, HTML, Upload/Download
├── config/                 drei Beispielkonfigurationen
├── deploy/                 systemd, Caddy, ACME-Hook
├── Makefile
└── Cargo.toml
```

## 4. Daten- und Persistenzmodell

SQLite ist JSON/TOML-Dateien mit Locking vorzuziehen: eindeutige Aliase, parallele Sessions, atomare Downloadlimits und crash-feste Transaktionen sind Kernanforderungen. WAL ist aktiv. Tabellen: `admins`, `sessions`, `shares`, `audit`; das Schema wird beim Start idempotent angelegt. Die Datenbank liegt standardmäßig in `/var/lib/vaultlink/data.sqlite` und muss `vaultlink:vaultlink 0600` gehören.

Backup bei gestopptem Dienst:

```sh
sudo systemctl stop vaultlink
sudo install -m 0600 -o root -g root /var/lib/vaultlink/data.sqlite /var/backups/vaultlink-$(date +%F).sqlite
sudo systemctl start vaultlink
```

Für Online-Backups ist `sqlite3 /var/lib/vaultlink/data.sqlite '.backup /sicheres/ziel.sqlite'` zu verwenden. Restore zuerst auf eine separate Datei testen. Der Mountpoint wird unabhängig gesichert.

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
| `/admin/shares/:id/delete` | POST | löschen |
| `/v/:token` | GET | öffentliche Datei-/Ordnerseite |
| `/v/:token/download` | GET | gestreamter Download |
| `/v/:token/upload` | POST | exklusiver Ordnerupload |
| `/s/:alias` | GET | validierter Kurzlink |

Es gibt absichtlich keine öffentliche JSON-API. Interne absolute Pfade werden nie gerendert.

## 7. UI und UX

Login, MFA, Dateibrowser, Linkformular/-liste sowie öffentliche Download-/Uploadseiten sind responsiv. Berechtigungen und Status sind sichtbar. Ein kleines, statisch ausgeliefertes und durch `script-src 'self'` begrenztes Script stellt den Copy-Button bereit; es gibt keine externe Frontend-Abhängigkeit. Verzeichnisse sind auf 1000 Einträge pro Ansicht begrenzt, um unkontrolliertes Rendering zu vermeiden.

## 8. HTTPS- und Betriebsmodi

### Development

Nur `127.0.0.1`, HTTP, kein Secure-Cookie und kein HSTS. Dies ist niemals ein Internetmodus.

### Reverse Proxy (empfohlen)

VaultLink lauscht auf `127.0.0.1:8080`; Caddy terminiert HTTPS. Die Beispiel-[`Caddyfile`](deploy/Caddyfile) genügt für Caddys Standard-ACME. Für ZeroSSL kann entweder Caddys ZeroSSL-Issuer oder die unten beschriebene externe Pipeline verwendet werden. Bei externen Zertifikaten referenziert Caddy die deployten PEM-Dateien.

```sh
sudo install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

### Standalone TLS

Rustls liest Fullchain und Key beim Prozessstart. Das MVP implementiert bewusst keinen SIGHUP-Hot-Reload; der atomare Deploy-Hook führt nach erfolgreichem Zertifikatswechsel einen kurzen systemd-Neustart aus. Für Port 443 wird nur im Standalone-Modus das Drop-in `vaultlink-standalone-capability.conf` installiert. Alternativ bindet VaultLink auf 8443 und die Firewall leitet weiter. Ein zusätzlicher HTTP-Redirect-Listener ist im MVP nicht implementiert; Port 80 sollte durch Firewall/Proxy auf HTTPS umgeleitet werden.

## 9. Testkonzept

Unit-Tests decken Argon2, den offiziellen RFC-TOTP-Vektor, Rate-Limit, Traversal/Encoding, Dateinamen, Unix-Symlink-Escape, Proxy-Vertrauen, Config-Modi, Berechtigungen, Alias-Eindeutigkeit und atomare Downloadlimits ab. Sie nutzen In-Memory-SQLite bzw. `tempfile`, verändern keinen Produktionsmount und benötigen nach dem Dependency-Fetch kein Netzwerk.

```sh
make test
make security-test
make lint
```

Vor einer Version 1.0 sind ergänzend End-to-End-Browsertests, parallele Multipart-Abbruchtests, Fuzzing von Pfad- und Multipartparsern und Lasttests einzuplanen.

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

Firewall: bei Reverse Proxy nur 80/443 für Caddy/Nginx öffnen und 8080 auf Loopback lassen. Bei Standalone nur 443 öffnen. Updates über neues Binary, `systemctl restart vaultlink`, Logs prüfen, dann altes Binary kontrolliert entfernen. `journalctl -u vaultlink` enthält strukturierte Betriebslogs, aber keine Credentials.

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

`acme.sh --cron` entscheidet täglich selbst, ob erneuert wird. Der Hook prüft nichtleere Quelldateien, installiert beide PEMs mit `root:vaultlink 0640`, tauscht sie atomar innerhalb des Zielverzeichnisses und startet VaultLink nur nach erfolgreichem Deploy neu. Troubleshooting: `journalctl -u vaultlink-cert-renew`, DNS/Firewall und acme.sh-Domainpfade prüfen. EAB-Werte niemals in Logs kopieren. Die Timer-Unit bekommt keinen EAB-Wert als Kommandozeilenargument; EAB wird nur bei Accountregistrierung benötigt.

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
- **403 bei Datei:** kanonisierter Zielpfad oder Symlink verlässt den Root; das ist beabsichtigt.
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

`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `cargo test --all-targets --locked`, `cargo build --release --locked` und `git diff --check` wurden unter Windows erfolgreich ausgeführt. 22 Tests liefen erfolgreich; der zusätzliche Unix-Symlink-Test ist unter Windows per `cfg(unix)` deaktiviert.

Auf einer sauberen Debian-13.5-VM wurden Rust stable 1.96.1, Clippy, alle 23 Tests einschließlich Symlink-Escape, Release-Build, ShellCheck und die systemd-Units erfolgreich geprüft. Zusätzlich liefen Admin-Bootstrap, Passwort/TOTP-Login, Session, Logout, CSRF-Ablehnung, Security Headers, Rate-Limit sowie öffentliche Download-only- und Upload-only-Flows Ende-zu-Ende gegen einen realen systemd-Dienst. Uploadinhalt, Dateimodus `0600` und Audit-Einträge wurden auf dem Server verifiziert.

Projektbeschreibung für GitHub: **VaultLink – secure, self-hosted file and folder sharing for an existing Linux mountpoint, built in Rust.**

Lizenz: MIT.
