# v0.1.0-beta.1 release checklist

Stand: 2026-07-07 15:19 Europe/Vienna.

Aktueller Repository-Stand: `main` bei `941f547`. Die VM läuft mit dem aus `a349794` gebauten Binary; `941f547` ändert nur CI, Makefile und Dokumentation und hat keine Runtime-Codeänderung.

## Bereits grün

- [x] `main` war vor dieser Checklisten-Konsolidierung sauber; CI für `941f547` war grün.
- [x] Formatting, Clippy, Unit-Tests, HTTP-Integrationstests, Migrationstests und Release-Build laufen in CI mit `--locked`.
  - GitHub Actions: `CI` Run `28866453280`, erfolgreich.
- [x] Shellcheck ist in CI und Release-Dry-Run für `deploy/*.sh` und `tools/*.sh` erzwungen.
  - GitHub Actions: `CI` Run `28866453280`, erfolgreich.
- [x] Fuzz-Gate: Path-Normalisierung, Byte-Range-Parser und Dateinamen je zehn Minuten ohne Findings.
  - GitHub Actions: `Fuzz release gate` Run `28866884860`, erfolgreich.
- [x] Dependency-Gate mit `cargo-audit 0.22.2 --deny warnings`.
  - GitHub Actions: `Release prerelease` Dry-Run `28866884894`, erfolgreich.
- [x] Debian-13-amd64 Lastprofil auf der VM gegen `127.0.0.1:8080`.
  - 100 parallele Metadata-Nutzer: p95 `0.0303s`.
  - 40 parallele Range-Downloadstreams: erfolgreich.
  - 10 parallele Uploadstreams: erfolgreich.
  - Zusätzlicher RSS: `22,863,872` Bytes, deutlich unter 256 MiB.
  - Keine 5xx im Metadata-Profil.
- [x] Öffentlicher Nginx-Pfad `vaultlink.haberl.tech` geprüft.
  - HTTP→HTTPS Redirect: `301` auf `https://vaultlink.haberl.tech/login`.
  - HTTPS/Login-Header: CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
  - Passwortgeschützte Freigabe: gesperrte Landingpage, falsches Passwort `401`, erfolgreiches Unlock `303`.
  - Unlock-Cookie: `Secure`, `HttpOnly`, `SameSite=Strict`.
  - `HEAD`, `Accept-Ranges`, `206` Range-Download: erfolgreich.
  - Upload-only-Link: Upload erfolgreich, Download `403`.
  - Revoke und Expiry: jeweils `410`.
- [x] Release-Dry-Run baut Artefakte im gepinnten Debian-13-Container.
  - GitHub Actions: `Release prerelease` Run `28866884894`, erfolgreich.
  - Enthalten: Binary, README, LICENSE, Konfigurationen, systemd/deploy-Dateien, SHA-256-Datei, CycloneDX-SBOM, deterministisches `tar.gz`.
  - Signatur- und Release-Schritte sind im Dry-Run bewusst übersprungen, weil sie nur auf einem Tag laufen.
- [x] Laufender VM-Dienst nach Gates stabil.
  - `vaultlink.service`: `active`, `NRestarts=0`.
  - SQLite: `PRAGMA integrity_check = ok`.
  - Soak-Monitor schreibt weiter Evidenz nach `/var/log/vaultlink/soak.csv`.

## Offen vor dem Tag

- [ ] Feature-Freeze für `v0.1.0-beta.1` bestätigen.
  - Ab diesem Punkt keine Code-, Config- oder systemd-Änderungen mehr außer Release-Blockern.
- [ ] Finalen Release-Candidate deployen, falls nach dieser Datei noch Runtime-Code geändert wird.
  - Falls nur Dokumentation/CI geändert wird, ist kein VM-Redeploy nötig.
- [ ] Upgrade und Rollback einmal bewusst testen.
  - Upgrade ist mehrfach erfolgreich gelaufen.
  - Rollback muss noch mit einem Backup unter `/var/lib/vaultlink/backups/` geprüft werden.
  - Dieser Test startet den Dienst neu und gehört deshalb vor den finalen 72h-Soak.
- [ ] Finalen 72h-Soak nach dem letzten Runtime-Deploy starten und vollständig abwarten.
  - Gate: keine ungeplanten Restarts, `PRAGMA integrity_check = ok`, kein kontinuierliches RSS-Wachstum über 15 %.
  - Lange Soaks werden nicht nach reinen UI-/Doku-/CI-Änderungen neu gestartet; ein neues Binary-Deploy setzt den Soak zurück.
- [ ] Nach bestandenem Soak final prüfen:
  - sauberer Worktree,
  - grüner CI-Run auf finalem `main`,
  - `cargo-audit`/Release-Dry-Run weiterhin grün,
  - `vaultlink.haberl.tech` Smoke-Test weiterhin grün.
- [ ] Annotierten Tag `v0.1.0-beta.1` nur bei sauberem Worktree und vollständig grünen Gates erstellen.
- [ ] Tag-Release-Workflow prüfen.
  - Binary und `SHA256SUMS` müssen mit Minisign gegen `release/minisign.pub` verifizieren.
  - GitHub Release muss `private/prerelease` sein und ausschließlich CI-produzierte Artefakte enthalten.

## Bewusste Nicht-Ziele für `v0.1.0-beta.1`

- ZIP-Download für Ordner.
- Suche.
- Audit-Dashboard.
- DEB-Paket.
- ARM64-Build.
- Öffentliches Repository.
