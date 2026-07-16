# v0.5.0 release checklist

Stand: 2026-07-15 für die native Linux-amd64-/arm64-Freigabe von 0.5.0.

Ziel: privates GitHub-Release für Debian 13 amd64 und arm64. Die Umsetzung erfolgt über einen eigenen Pull Request; ein Tag wird erst nach dem Merge auf `main`, bei sauberem Worktree und vollständig grünen Gates gesetzt.

## Feature-Scope für 0.5.0

- [x] Admin Login, TOTP-MFA, Sessions, Logout, CSRF.
- [x] „Mein Konto“ für eigene Passwortänderungen mit aktuellem Passwort sowie zweistufigen MFA-Wechsel; das alte Secret bleibt bis zum bestätigten neuen TOTP-Code aktiv.
- [x] Lokaler `recover-admin`-Notfallpfad über SSH/Hostzugriff mit `--config` oder direktem `--database`, atomarem Credential-Wechsel, Session-/Pending-Widerruf und secret-freiem Audit.
- [x] Deutsch/Englisch in Setup-, Auth-, Admin- und Public-Flows; Cookie vor `Accept-Language`, Englisch als Fallback, locale-gerechte Datums-/Zahlen-/JavaScript-Ausgabe.
- [x] Session-basierte JSON-API unter `/api/v1`; keine API-Tokens in 0.5.0.
- [x] Admin-Dateiverwaltung zum Erstellen von Ordnern, No-Clobber-Umbenennen und permanenten rekursiven Löschen mit serverseitiger Bestätigung sowie clientseitigem Exact-Match-Gating.
- [x] Begrenzte, neustartfähige Tombstone-Bereinigung mit genau einem globalen, signalkoaleszierenden Cleanup-Worker und automatische Anpassung beziehungsweise Deaktivierung betroffener Freigaben.
- [x] API und UI teilen Auth-, Session-, CSRF-, SecureFS-, SQLite-, Runtime-Settings- und Audit-Logik.
- [x] API-Fehler werden als JSON normalisiert; Streaming-Routen liefern nur bei Erfolg Binärdaten.
- [x] Root-begrenzter Dateibrowser mit Breadcrumbs, Hoch-Link, Pagination, Suche und Linkerstellung aus der Oberfläche.
- [x] Linkverwaltung für Datei-/Ordnerlinks mit `download_only`, `upload_only`, `download_upload`.
- [x] Passwortgeschützte Shares mit Argon2id, Unlock-Cookies und Rate-Limit.
- [x] Optionaler Kurzlink-Alias.
- [x] Download-Streaming mit `HEAD`, `Accept-Ranges`, einzelnem Byte-Range, `206` und `416`; HEAD prüft die verfügbare Quote ohne Reservierung oder Zählung, feste Transfer-Grants zählen erst vollständige Antworten und fassen Range-Resumes ohne Sliding-Expiry zusammen.
- [x] Sichere Uploads mit temporärer Datei, `fsync`, atomarem No-Replace-Publish, globalem und optionalem per-Share-Uploadlimit.
- [x] Optionales Upload-Überschreiben pro Upload-Ordnerlink; bei `external_writers=true` erzwingen UI, API und Publish-Pfad standardmäßig No-Replace. Der separate Opt-in `allow_external_writer_replace=true` dokumentiert und testet bewusstes Last-Writer-Wins.
- [x] Upload in navigierten Unterordnern für `download_upload`-Ordnerlinks.
- [x] Upload-only-Freigaben listen keine Ordnerinhalte und erlauben keine Preview/Downloads.
- [x] Inkrementeller ZIP-Download für Ordnerfreigaben mit durchgehendem ZIP64, Datei-, Scan- und Größenlimits, gecappten Quelldateien, Temp-Budget und backpressured Direct-Stream-Fallback.
- [x] Begrenzte case-insensitive Dateinamensuche; Listing, Suche und ZIP zählen auch gefilterte rohe Verzeichniseinträge und setzen Scans ohne Offset-Rescan fort.
- [x] Sichere Browser-Textvorschau für allowlistete Endungen; escaped HTML in `<pre>`, kein Inline-User-MIME.
- [x] Sichere Browser-Vorschau für allowlistete Rasterbilder und PDFs über Raw-Preview-Routen mit `inline`, `nosniff`, `HEAD`, `206` und `416`.
- [x] Admin-UI für zusätzliche Admins; TOTP-Secret wird genau einmal angezeigt. Initial-Setup kann ein noch nicht bestätigtes Secret lokal und passwortgebunden wiederanzeigen.
- [x] Runtime-editierbare Policy-Settings in SQLite, nicht in `/etc/vaultlink/config.toml`.
- [x] Audit-Dashboard mit Pagination und Action-Filter.
- [x] Loopback-only Setup-UI (`vaultlink setup --config <path> --listen 127.0.0.1:8090`) mit dokumentiertem Headless-Zugriff über einen expliziten IPv4-SSH-Tunnel: `ssh -4 -N -L 127.0.0.1:8090:127.0.0.1:8090 user@server`.
- [x] Setup überschreibt keine bestehende Konfiguration; Config-ohne-Admin und committed Admin vor verlorener TOTP-Antwort sind wiederaufnehmbar.
- [x] Pro-Share SecureFS-Capabilities verhindern Symlink-Wechsel in Sibling-Shares für Listing, Preview, Download, ZIP und Upload.
- [x] Linux-only auf x86_64 und aarch64; Windows-Dateinamensinteroperabilität bleibt für Standard-SMB-Clients erhalten.
- [x] Externer CIFS-Co-Writer-Modus mit geprüftem direkten Share-Root, reserviertem pre-provisioniertem `.vaultlink-internal`, Mount-ID/-Quelle/-Optionen, lokalem SQLite und crash-sicherem Pending-/Committed-Delete-Protokoll.
- [x] Separater Root-Befehl für die nicht überschreibende `/mnt/storage`-CIFS-Provisionierung mit interaktiver Credential-Eingabe und Rollback; das unprivilegierte Browser-Setup erkennt sichere aktive SMB-Mounts und übernimmt Pfade, Typ und Quelle.
- [x] Exklusiver, nicht blockierender Lifetime-Lock im gemeinsamen `internal_directory` wird vor Storage-Recovery/Cleanup erworben, auf wirksame Lock-Semantik geprüft und verhindert überlappende VaultLink-Server für dieselbe Journal-Domain.
- [x] Jede Production-Konfiguration verlangt eine exakte fail-closed Mount-Identität; ein ausgefallener CIFS-Mount darf auch dann nicht auf das lokale Fallback-Verzeichnis starten, wenn dort gerade ext4 sichtbar ist. Auditiertes lokales Production-Storage darf SQLite außerhalb des sichtbaren Baums auf demselben lokalen Mount halten.
- [x] Browser-Setup und `init-admin` prüfen Root/Internal/Data-Mount und kanonische Pfade vor Konfiguration, Datenbank oder Credential-Secrets; Symlink-Aliase in den sichtbaren Baum werden abgewiesen.
- [x] Upgrade-/Rollback-Backups und Recovery bestehen immer aus einem validierten Binary/Config/SQLite-Tripel; Candidate-Konfigurationen verändern die Live-Konfiguration nicht vor der Downtime.
- [x] Gepufferte Form-/JSON-Bodies sind klein begrenzt; ausschließlich Uploadrouten erhalten den großen Streaming-Rahmen. Ein konstanter Streaming-Guard begrenzt Präambel und jeden Multipart-Headerblock, zusätzlich sind Feldanzahl und Metadaten klein begrenzt.
- [x] Reverse-Proxy-Modus, Standalone-TLS-Modus, SIGHUP-Zertifikatsreload für PEM-Dateien.
- [x] Optionaler Built-in-Let's-Encrypt-Standalone-TLS-Modus über `tls-alpn-01` und `rustls-acme`.
- [x] UI-/UX-Polish mit getrennten Auth/Public/Admin-Shells, Logo/Favicon, locale-gerechtem Date-Time-Picker, dezimalen MB/GB-Einheiten und konsistenten Buttons/Switches.
- [x] Public Upload-Fehlerseiten für validierbare Fehler inklusive blockierter Dateitypen, Konflikte, Größenlimits, fehlende Dateinamen und Speicherfehler.
- [x] Fuzzing für Produktionsparser und isolierte Policy-/Zustandskomponenten: Pfade, Byte-Ranges, Dateinamen, ZIP/Search/Preview-Pfade, Upload-Overwrite, `UploadFormState`, Share-Policy, Dateimutationen und Multipart-Envelope-Streaming. Middleware-, Router-, DB-, Async- und Dateisystem-Races gehören ausschließlich zu den separaten Integrations-/Smoke-Gates; siehe [FUZZING.md](FUZZING.md).

## Bewusste Nicht-Ziele für 0.5.0

- DEB-Paket.
- Öffentliches Repository.
- API-Tokens oder externe API-Clients als stabile Public Contract Garantie.
- Inline-Preview für alle anderen Dateitypen.
- Built-in ACME hinter Nginx/Caddy; Auto-TLS ist ausschließlich für echten Standalone-Port-443-Betrieb.
- Unbegrenzte ZIPs und Kompression; das durchgehend verwendete ZIP64-Format ändert nichts an den konfigurierten Datei-, Scan- und Größenlimits.
- Admin-Löschen; Admins können deaktiviert/reaktiviert werden.

## Verbindliche native Linux-Gates

- [ ] `cargo check --locked` auf amd64 und arm64
- [ ] `cargo fmt --all -- --check` auf amd64 und arm64
- [ ] `cargo clippy --locked --all-targets --all-features -- -D warnings` auf amd64 und arm64
- [ ] `cargo test --locked --all-targets` auf amd64 und arm64
  - Das verbindliche 0.5.0-Gate sind native Linux-Läufe für amd64 und arm64; frühere Windows-Läufe gelten nicht als Freigabenachweis.
  - Enthalten: Account-Passwort/MFA, Recovery-Races, DE/EN-Hauptrouten und Setup, API Login/MFA/Session/CSRF, Secret-Redaction, Setup-Recovery, UTF-8, SecureFS, Preview, Transfers, ZIP, Multipart, Body-Limits, Upload-Atomizität und Migrationen.
- [ ] `cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets`
  - Fuzz-Crate inklusive `zip_search_preview_paths`, `upload_overwrite_policy`, `upload_request_state`, `share_request_policy`, `file_mutation_policy` und `multipart_guard` kompiliert.
- [ ] `cargo build --release --locked` auf amd64 und arm64
- [ ] `cargo audit --deny warnings` für das gemeinsame Workspace-Lockfile auf dem finalen Stand wiederholen.
- [ ] `shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh` und `make policy-check` auf amd64 und arm64 wiederholen.
- [ ] `make docker-smoke` auf dem finalen 0.5.0-Stand nativ auf amd64 und arm64 wiederholen.
- [ ] Wöchentlicher/manueller Reproducibility-Workflow baut pro Architektur zweimal mit leeren Target-Verzeichnissen und identischem `SOURCE_DATE_EPOCH`; Binär- und Archiv-SHA-256 sind bitgenau gleich.
- [ ] Debian-Basisimage, Snapshot-Zeitpunkt sowie direkte und transitive Release-Pakete entsprechen `debian-snapshot.sources` und `debian-packages.lock`; das source-unabhängige `Dockerfile.release-builder` wurde explizit als linux/amd64+linux/arm64-Manifest gebaut und gepusht.
- [ ] Externen Blocker auflösen: `release-builder-image.lock` enthält nicht mehr `UNPROVISIONED`, sondern die vollständige echte `ghcr.io/alexhaberl/vaultlink-release-builder@sha256:<64-hex>`-Referenz; `VAULTLINK_RELEASE_BUILDER_IMAGE` ist exakt gleich und das private GHCR-Paket gewährt dem Repository-Actions-Token Lesezugriff. Release-/Reproducibility-Jobs ziehen sie mit `packages: read` und installieren weder APT- noch Cargo-Werkzeuge zur Laufzeit.

## Historische Beobachtung vor dem 0.3.2-Upgrade

- [x] Bestehendes `0.3.0`-Binary auf beiden Testsystemen vor jeder Änderung geprüft; identischer SHA-256 `d6def1640bf8c93ddb5f30689731c4f3f2efb62d13c949b75a0012bd0cfb2946`.
- [x] Reverse-Proxy-Testsystem nach 10 h 11 min und Standalone-TLS-Testsystem nach 10 h 08 min weiterhin `active/running`, jeweils `NRestarts=0` und ohne fehlgeschlagene systemd-Units.
- [x] `PRAGMA integrity_check = ok`, leere WAL-Dateien sowie erfolgreiche lokale beziehungsweise öffentliche `/api/v1/health`-Antworten mit Version `0.3.0`.
- [x] Aktueller RSS 10.5 MiB auf dem Reverse-Proxy-System und 13.0 MiB auf dem Standalone-TLS-System; im ausgewerteten Dienstjournal keine VaultLink-Warnungen, Panics oder Fehler.
- [ ] Diese Beobachtung ist kein formaler Soak-Gate: Es lief weder `soak-monitor.sh` noch das Lastprofil. Der finale 72h-Soak wurde bewusst noch nicht gestartet.

## Historische 0.3.x-Debian-/Docker-Verifikation

- [x] Digest-gepinntes Debian-13-amd64-Testimage, Build im Container und read-only Workspace-Mount nur für Fuzz-/Shell-Checks:
  - `cargo fmt --all -- --check`
  - `cargo test --locked --all-targets`
  - `cargo clippy --locked --all-targets --all-features -- -D warnings`
  - `cargo build --release --locked`
  - `cargo check --manifest-path fuzz/Cargo.toml --locked --all-targets`
  - `shellcheck deploy/*.sh deploy/docker/*.sh tools/*.sh`
  - `sh tools/check-supply-chain-policy.sh`
- [x] Nach diesem Feature-Update erneut auf dem Reverse-Proxy-Testsystem bauen/deployen und Public-Smoke ausführen.
  - Transaktionales Upgrade auf `0.3.2` mit verifiziertem Backup `/var/lib/vaultlink/backups/20260710T173328Z` erfolgreich.
  - Binary-SHA-256 `d382903ff9d238cbc44f616c6af39c9d27d6afb61e1bea5d1ac3706e55fa6e2c`, `NRestarts=0`, SQLite `ok`, lokale und öffentliche Health-Antwort exakt `{"ok":true,"version":"0.3.2"}`, öffentlicher Login HTTP 200.
- [x] Standalone-Testsystem erneut bauen/deployen und Public-HTTPS-Smoke ausführen.
  - Transaktionales Upgrade auf `0.3.2` mit verifiziertem Backup `/var/lib/vaultlink/backups/20260710T173409Z` erfolgreich.
  - Identischer Binary-SHA-256, `NRestarts=0`, SQLite `ok`, öffentliche HTTPS-Health-Antwort exakt `{"ok":true,"version":"0.3.2"}`, Login HTTP 200 und gecachtes Let's-Encrypt-Zertifikat erfolgreich geladen.
- [x] Erweiterten isolierten Runtime-Smoke auf beiden Debian-13-Systemen ausgeführt: Setup, Login/MFA/CSRF, Exact-Match-Lösch-UI, Ordnererstellung, Share-Erstellung, Share-Pfadänderung nach Umbenennung, Bestätigungspflicht, permanente Teilbaumlöschung, Share-Deaktivierung und Tombstone-Wiederaufnahme nach Prozessneustart.

## Noch auszuführende Release-Gates

- [ ] Fuzz-Gate auf amd64 und arm64 jeweils zehn Minuten:
  - Pfadnormalisierung,
  - Byte-Range-Parser,
  - Dateinamen,
  - ZIP/Search/Preview-Pfadfälle inklusive Media-Preview,
  - Upload-Overwrite-Policy,
  - echte Upload-Request-Zustandslogik,
  - echte Share-Request-Policy,
  - Admin-Dateimutations- und Share-Teilbaumpolicy,
  - Multipart-Streaming-Guard inklusive Chunk-Grenzen, EOF, Header- und Preamble-Limits.
  - Der Workflow läuft zusätzlich wöchentlich als native amd64/arm64-Matrix; jede Architektur führt alle neun Targets mit vier Workern in drei Gruppen und einem 60-Minuten-Timeout aus und publiziert einen eigenen Commit-Status. Der manuelle Lauf auf dem finalen Commit bleibt das Release-Gate.
- [ ] Dependency-Gate mit `cargo-audit 0.22.2 --deny warnings` final wiederholen.
- [ ] Dabei das gemeinsame Workspace-`Cargo.lock` prüfen.
- [ ] GitHub Actions CI auf finalem `main` grün.
- [ ] Release-Dry-Run mit `--locked` für amd64 auf `[self-hosted, Linux, X64, vaultlink]` und arm64 auf `[self-hosted, Linux, ARM64, vaultlink]` grün; beide verwenden exakt `VAULTLINK_RELEASE_BUILDER_IMAGE` als digest-gepinnten Multi-Arch-Builder ohne Laufzeitinstallation von APT-/Cargo-Werkzeugen. Architekturunabhängige Release-Jobs laufen auf arm64.
- [ ] Vor dem Candidate-Preflight ist `release/minisign.pub` offline erzeugt, committed, nicht leer und als Minisign-Ed25519-Public-Key validiert; die beiden Signing-Secrets sind provisioniert. Keine Key- oder Builder-Pin-Änderung nach Soak-Start.
- [ ] Reproducibility-Evidenz für amd64 und arm64 gehört zum exakten finalen Commit und enthält gleiche Hashes beider unabhängiger Builds.
- [ ] Offline erzeugten Minisign-Public-Key als `release/minisign.pub` committen und `MINISIGN_SECRET_KEY` sowie `MINISIGN_PASSWORD` als GitHub-Actions-Secrets provisionieren; ohne alle drei Werte muss der Tag-Publish absichtlich fehlschlagen.
- [ ] Ein autorisierter Maintainer pusht den annotierten `v0.5.0`-Tag erst nach Merge und allen Gates. Das private GitHub-Free-Repository besitzt kein wirksames Environment-Approval-Gate; Tag-Autorisierung, exakte Gleichheit von Tag-Commit und `origin/main` sowie der tag-only `contents: write`-Job bilden deshalb die explizite Freigabekette.
- [ ] Artefakte prüfen:
  - versionierte amd64- und arm64-Archive,
  - eigenständige, architekturspezifische Binaries,
  - README,
  - LICENSE,
  - Beispielkonfigurationen,
  - systemd/deploy-Dateien,
  - `SHA256SUMS-amd64` und `SHA256SUMS-arm64`,
  - architekturspezifische CycloneDX-SBOMs,
  - deterministisches `tar.gz`,
  - Minisign-Signatur nur beim Tag-Release.

## Staging- und Public-Gates vor finalem Soak

- [ ] Finalen Release-Candidate auf je einem Debian-13-amd64- und Debian-13-arm64-Staging-System deployen.
- [ ] SQLite-Backup vor Upgrade bei gestopptem Dienst erstellen.
- [ ] Upgrade-Test durchführen.
  - getrennte alte/neue Binary+Config-Paare vor Downtime validieren,
  - jedes pre-0.4.1→0.4.1+-Upgrade verweigert ein noch aktives `vaultlink.service` vor jeder Mutation; semantische Downgrades werden vom Upgrade- und Roll-forwards vom Rollback-Einstiegspunkt abgelehnt,
  - Backup enthält `vaultlink`, `config.toml` und `data.sqlite` mit restriktiven Ownern/Modi,
  - Candidate-Failure restauriert das vollständige alte Tripel und prüft dessen eigenen Health-Endpunkt,
  - paralleles Upgrade/Rollback scheitert vor dem Dienst-Stopp am Maintenance-Lock.
- [ ] Passwortgeschützte Public-Uploads akzeptieren den Unlock-gebundenen CSRF-Wert als Multipart-Feld beziehungsweise `X-VaultLink-Upload-CSRF` und lehnen fehlende/fremde Werte ab.
- [ ] Upload-Shares erzwingen Einzeldatei-, kumulatives Byte- und Dateianzahllimit auch bei parallelen Queue-Uploads und Overwrite-Versuchen.
- [ ] Rollback-Test durchführen:
  - Dienst stoppen,
  - vorheriges Binary, passende Konfiguration und SQLite-Backup wiederherstellen,
  - Dienst starten,
  - exakten lokalen Health-/Versions-Smoke ausführen,
  - fehlgeschlagener Recovery-Stop oder unvollständiger Emergency-Restore bleibt gestoppt.
- [ ] Reales SMB-3.1.1-Co-Writer-Gate auf einem externen Server:
  - pre-0.4.1-Share-Root unter vollständiger Writer-Quiesce inventarisieren; `.vaultlink-internal`-Alias- und alte Fragment/Tombstone-Kollisionen auflösen,
  - alle sichtbaren Einträge einschließlich Dotfiles direkt im Share-Root gegen Snapshot/Hashes verifizieren,
  - separates VaultLink-SMB-Konto sowie normale Windows-, macOS- und Linux-Co-Writer-Konten verwenden,
  - SMB-Server/Share erzwingt SMB 3.1.1 Signing und Encryption; dies wird für die VaultLink-Mount-Session und jede direkte Windows-/macOS-/Linux-Session separat verifiziert,
  - das Share-Root ist für alle beabsichtigten Co-Writer im benötigten Umfang les-/schreibbar,
  - Co-Writer besitzen Modify für Benutzerdaten im Share-Root, niemals administrative Rechte oder Zugriff auf `.vaultlink-internal`,
  - `.vaultlink-internal/{uploads,tombstones}` ist vorab vorhanden und für Co-Writer weder lesbar noch schreib-, lösch- oder umbenennbar; Parent-`DELETE_CHILD`, `WRITE_DAC`, `WRITE_OWNER` sowie chmod/chown/setfacl-Äquivalente sind verweigert,
  - `/proc/self/mountinfo` zeigt `vers=3.1.1`, `seal`, `cache=strict`, `nosuid`, `nodev`, `noexec` und keine verbotenen Optionen,
  - SQLite liegt auf einem separaten lokalen Dateisystem,
  - paralleles SMB-Put und VaultLink-No-Replace erzeugen exakt einen Gewinner, niemals Mischinhalt oder Clobbering,
  - bestehende Overwrite-Shares liefern im Co-Writer-Modus 409/400 und ersetzen keine externe Datei,
  - Disconnect/Reconnect, Dienstneustart, Pending-Delete-Recovery und Mount-Race schlagen sicher beziehungsweise recoverable fehl,
  - kompletter CIFS-Unmount bei vorhandenem lokalen Mountpoint wird in Production vor jedem Secret-/DB-Zugriff fail-closed abgewiesen,
  - eine lokale ext4-/XFS-Production-Policy mit Root/Internal/Data auf demselben Mount wird außerhalb des sichtbaren Baums akzeptiert; group-/other-/ACL-schreibbare lokale Roots werden abgewiesen,
  - direkte SMB-Änderungen erscheinen im SMB-Server-Audit; ihr Bypass von VaultLink-Audit und Linklimits ist abgenommen.
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
  - Registrierung, Anmeldung und geschütztes Entfernen mit zwei realen FIDO2-Sicherheitsschlüsseln,
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

- [ ] Vor dem Soak ist im obersten Changelog-Eintrag statt `Unreleased release candidate` das geplante echte UTC-Kalenderdatum im Format `YYYY-MM-DD` committed. Der manuelle Release-Workflow im Modus `candidate` ist für exakt diesen Commit erfolgreich und setzt `vaultlink/release-candidate-preflight`.
- [ ] Erst nach dem letzten Runtime-Deploy starten.
- [ ] Dedizierten Debian-13-amd64-Runner `[self-hosted, Linux, X64, vaultlink-soak]` ausschließlich über den manuellen Start-Workflow auf dem exakten `origin/main`-Commit starten; der Workflow verlangt den Candidate-Preflight und prüft Debian 13 sowie `x86_64` fail-closed.
- [ ] Gate über mindestens 259200 Sekunden:
  - keine ungeplanten Restarts,
  - `PRAGMA integrity_check = ok`,
  - Health-Version durchgehend `0.5.0`, keine 5xx-/Panic-/DB-Fehler im Journal,
  - Metadaten-p95 < 750 ms bei 100 Clients, 40 parallele Streams und zehn parallele Uploads je Lastlauf,
  - RSS immer ≤ 256 MiB und höchstens 15 % Wachstum zwischen Warm- und Schlussmedian.
- [ ] Der stündliche Collector hat das atomare Ergebnis, CSV-Metriken, Lastberichte, Journal, Commit und vollständigen Binärhash als `soak-evidence-COMMIT` hochgeladen und den Commit-Status `vaultlink/72h-soak` auf `success` gesetzt.
- [ ] Jede Änderung am Commit nach Soak-Beginn – einschließlich Doku, CI, Deploy-Skripten, Konfiguration oder Version – invalidiert die Evidenz und startet das vollständige 72h-Gate neu.

## Tag-Freigabe

- [ ] Sauberer Worktree.
- [ ] Grüner CI-Run auf finalem `main`.
- [ ] Release-Dry-Run und `cargo-audit` weiterhin grün.
- [ ] `make policy-check` grün; alle Dependabot-Pin-Updates gegen die jeweiligen Upstream-Repositories geprüft.
- [ ] Staging- und Public-Gates grün.
- [ ] `vaultlink/72h-soak` ist für exakt diesen Commit erfolgreich; der Release-Workflow verifiziert Dauer, Metriken, Lastläufe und den vollständigen amd64-Binärhash aus dem verknüpften Evidenzartefakt.
- [ ] Der manuelle Release-Workflow im Modus `evidence` hat für denselben unveränderten Commit Soak- und Reproducibility-Evidenz heruntergeladen, Binär-/Archivhashes mit beiden Neubauten verglichen und `vaultlink/release-evidence-preflight` auf `success` gesetzt.
- [ ] Das committed Changelog-Datum entspricht beim Tag-Lauf exakt dem aktuellen UTC-Datum. Wird der geplante Termin verpasst, ist eine Datumsänderung ein neuer Commit und erzwingt Candidate-Preflight sowie vollständigen 72h-Soak erneut.
- [ ] Annotierten Tag `v0.5.0` erstellen.
- [ ] Tag-Commit entspricht exakt dem freigegebenen `origin/main`-Commit; Release-Environment/Secrets sind für den Tag freigegeben.
- [ ] Offline erzeugtes `release/minisign.pub` ist vor dem Tag committed und die beiden Minisign-Secrets sind provisioniert.
- [ ] Tag-Release-Workflow prüfen:
  - GitHub Release ist privat,
  - Artefakte stammen ausschließlich aus CI,
  - beide Archive, Binaries sowie `SHA256SUMS-amd64` und `SHA256SUMS-arm64` mit den jeweils architekturspezifischen Minisign-Dateien gegen `release/minisign.pub` verifizieren.
