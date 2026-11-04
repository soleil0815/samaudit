# SAMAUDIT – Handbuch

SAMAUDIT prüft die Sicherheit Ihres Active Directory (Windows AD oder Samba AD). Es liest die Domäne mit den Rechten eines **normalen** Benutzerkontos aus, wendet 115 Prüfungen an und zeigt das Ergebnis als Risikowert, ausführlichen Bericht mit Maßnahmen und PDF.

Das Handbuch hat zwei Teile: **Teil A** für Prüferinnen und Prüfer, die SAMAUDIT im Browser benutzen, **Teil B** für den Betrieb auf dem Server.

## Teil A – Benutzung

### Anmelden

1. SAMAUDIT im Browser öffnen, z. B. `https://samaudit.firma.local:9400`.
2. Im Anmeldefeld steht, an welcher **Domäne** Sie sich anmelden.
3. Mit Ihrem **normalen** Domänenkonto anmelden – als `benutzer`, `DOMÄNE\benutzer` oder `benutzer@domäne`.

Anmelden darf nur, wer Mitglied der Prüfer-Gruppe ist (Standard `SAMAUDIT-Benutzer`).

> **Admin-Konten werden immer abgewiesen** – auch wenn sie in der Prüfer-Gruppe sind. Das ist Absicht: So wird nie ein Passwort eines hochprivilegierten Kontos in eine Weboberfläche eingegeben. Verwenden Sie Ihr normales Arbeitskonto.

Ihr Passwort wird nicht gespeichert. Es liegt nur verschlüsselt im Arbeitsspeicher, solange Sie angemeldet sind, damit ein Scan mit Ihren Rechten laufen kann. Nach 30 Minuten ohne Aktivität (einstellbar) oder spätestens nach 12 Stunden werden Sie abgemeldet. Abmelden: Knopf mit dem Pfeil neben Ihrem Namen links unten.

### Übersicht

Die Startseite zeigt den **letzten Scan**: Gesamtwert, die vier Bereiche, die wichtigsten Befunde und – ab dem zweiten Scan – den Verlauf. Mit **Scan starten** beginnt eine neue Prüfung.

### Einen Scan durchführen

1. **Übersicht** → **Scan starten**.
2. Der Fortschritt wird angezeigt (je nach Domänengröße einige Sekunden bis wenige Minuten).
3. Danach öffnet sich der Bericht automatisch.

Vor jedem Scan prüft SAMAUDIT erneut, ob Sie noch zur Prüfer-Gruppe gehören. Es läuft immer nur ein Scan gleichzeitig; startet jemand anderes einen, sehen Sie dessen Fortschritt.

### Den Bericht lesen

**Risikowert (0–100):** 0 bedeutet keine Befunde, 100 sehr hohes Risiko. Jeder der vier Bereiche hat einen eigenen Wert (höchstens 100); der Gesamtwert ist der **höchste** Bereichswert – eine einzige gravierende Schwäche bestimmt also das Gesamtbild.

| Wert | Bewertung |
|---|---|
| 0–14 | Sehr gut |
| 15–34 | Gut |
| 35–59 | Handlungsbedarf |
| 60–100 | Kritisch |

**Die vier Bereiche:**

| Bereich | Worum es geht |
|---|---|
| Veraltete Objekte | inaktive Konten und Computer, alte Betriebssysteme, Passwörter, die nie ablaufen, alte Funktionsebenen |
| Privilegierte Konten | Admin-Gruppen, Delegierung, gefährliche Berechtigungen, DCSync, AD-Zertifikatsdienste (ESC1–ESC15) |
| Vertrauensstellungen | Trusts zu anderen Domänen, SID-Filterung, veraltete Trusts |
| Anomalien | Richtlinien, GPOs, Kennwortrichtlinie, Überwachung, Skripte mit Passwörtern, DNS, Sicherung |

**Ein Befund** zeigt beim Aufklappen: was das Problem ist, wie man es behebt (oft mit PowerShell-Beispiel und Knopf **Kopieren**), die betroffenen Objekte (bei vielen Einträgen mit Filterfeld) und Quellen zum Nachlesen. Die Farbe am Rand steht für den **Schweregrad** (Kritisch, Hoch, Mittel, Niedrig, Info), `+Punkte` für den Beitrag zum Bereichswert.

**neu** markiert Befunde, die im vorherigen Scan noch nicht auftraten. Unter **Seit dem vorherigen Scan behoben** stehen erledigte Punkte.

**Nicht prüfbar** heißt nicht „bestanden“: Die Information war nicht verfügbar – meist, weil ein normales Konto sie nicht lesen darf, SYSVOL per SMB nicht erreichbar war oder die Prüfung für diesen Domänentyp (Windows/Samba) nicht gilt. Der Grund steht jeweils dabei.

### PDF-Export

Im Bericht oben rechts **PDF herunterladen**. Das PDF enthält Deckblatt, Zusammenfassung, Domänenüberblick, alle Befunde mit Maßnahmen und den Anhang. Es wird in der aktuell eingestellten Sprache erzeugt.

> Berichte und PDFs beschreiben die Schwachstellen Ihrer Domäne. Behandeln Sie sie vertraulich und legen Sie sie nur an geschützten Orten ab.

### Berichte

Unter **Berichte** stehen alle Scans mit Datum, Werten und Anzahl der Befunde. Einzelne Berichte lassen sich **löschen** (nicht während ein Scan läuft). Berichte werden außerdem nach der eingestellten Frist automatisch gelöscht (Standard 365 Tage).

### Prüfkatalog

Alle 115 Prüfungen mit Kennung, Bereich, Schweregrad und Beschreibung. Die Kennungen beginnen mit `STL-` (veraltete Objekte), `PRV-` (privilegierte Konten), `TRS-` (Vertrauensstellungen) und `ANM-` (Anomalien).

### Verbindung

- **Domäne und DCs:** Domänenname, erkannter Typ (Windows AD / Samba AD), verwendete Domänencontroller, LDAPS-Modus.
- **HTTPS-Zertifikat der Weboberfläche:** zeigt das aktive Zertifikat (Quelle, Aussteller, Ablaufdatum, Fingerabdruck) und Warnungen (abgelaufen, läuft bald ab, Servername fehlt im Zertifikat).
  - **Eigenes Zertifikat hochladen:** PFX-Datei (z. B. Export aus der Windows-Zertifizierungsstelle) mit Passwort **oder** Zertifikat + privaten Schlüssel auswählen → **Hochladen und aktivieren**. Es wird sofort aktiv, ohne Neustart; danach die Seite neu laden. Vorher wird geprüft, ob Zertifikat und Schlüssel zusammenpassen, ob es gültig ist und ob der Schlüssel stark genug ist (RSA mindestens 2048 Bit).
  - **Hochgeladenes Zertifikat entfernen** stellt das vorherige wieder her.
- **Vertrauenswürdige DC-Zertifikate:** SAMAUDIT merkt sich beim ersten Kontakt das Zertifikat jedes DCs samt seinem DNS-Namen und lehnt später ein fremdes Zertifikat ab (Schutz vor Man-in-the-Middle) – auch eines, das dieselbe Unternehmens-CA für einen anderen Rechner oder Benutzer ausgestellt hat. Normale Erneuerungen bleiben gültig. Nach einem **gewollten** Zertifikats- oder CA-Wechsel (oder einem neuen DC) zurücksetzen – aus Sicherheitsgründen auf dem Server: `docker exec samaudit python -m app.pins reset <DC>`. Mit `PIN_RESET_WEB=true` in der `.env` geht das auch hier über **Zurücksetzen**.

### Protokoll

Alle Anmeldungen (auch abgewiesene), Scans, PDF-Exporte, Löschungen, Zertifikatsänderungen und blockierte Netzwerkverbindungen mit Zeit, Benutzer und IP-Adresse. Einträge werden nach der eingestellten Frist automatisch gelöscht (Standard 90 Tage).

### Neuigkeiten

Links unten unter **Neuigkeiten** steht, was sich mit jeder Version geändert hat: neue **Funktionen**, **Sicherheit**sverbesserungen, **Fehlerbehebungen** und **Hinweise** auf neue Risiken im Active Directory (z. B. Abschaltungen durch Microsoft). Gibt es Neues, das Sie noch nicht gesehen haben, zeigt ein kleiner Punkt daneben das an (orange bei Sicherheitsthemen), und auf der Übersicht erscheint einmalig eine schmale Zeile. Mit **×** oder einem Besuch der Seite verschwindet beides. Die Neuigkeiten kommen mit dem Update mit – SAMAUDIT lädt dafür nichts aus dem Internet. Gemerkt wird nur in einem Cookie Ihres Browsers, welche Version Sie zuletzt gesehen haben.

### Sprache, Darstellung, Datenschutz

Links unten: **DE / EN** wechselt die Sprache, **Dunkel / Hell** die Darstellung. **Datenschutz** zeigt, welche Daten SAMAUDIT verarbeitet, wie lange sie gespeichert werden und wer zuständig ist – diese Seite ist auch ohne Anmeldung erreichbar.

### Meldungen bei der Anmeldung

| Meldung | Bedeutung / Abhilfe |
|---|---|
| Benutzername oder Passwort ist falsch | Eingabe prüfen. Nach mehreren Fehlversuchen wird kurz gesperrt (Standard 5 Versuche / 15 Minuten). |
| Zugriff verweigert: nicht Mitglied der Prüfer-Gruppe | Konto in die Gruppe `SAMAUDIT-Benutzer` aufnehmen lassen, danach neu anmelden. |
| Admin-Konten dürfen sich nicht anmelden | Normales Konto verwenden (siehe oben). |
| Die Prüfer-Gruppe existiert nicht | Gruppe in der Domäne anlegen (Betrieb, Teil B). |
| Das Konto ist in der Domäne gesperrt / deaktiviert / Passwort muss geändert werden | In der Domäne klären (z. B. Passwort am PC ändern). |
| Kein Domänencontroller erreichbar | Netzwerk und `DC_HOSTS` prüfen (Teil B). |
| Das Zertifikat des Domänencontrollers hat sich geändert | Möglicher Angriff **oder** gewollter Zertifikatswechsel bzw. neuer DC. Wenn gewollt: auf dem Server `docker exec samaudit python -m app.pins reset <DC>`. |
| Sitzung abgelaufen | Erneut anmelden. |

## Teil B – Betrieb

### Voraussetzungen

- Server oder NAS mit Docker und Docker Compose (oder einer Container-Verwaltung wie Dockhand oder Portainer).
- Vom Server zu den DCs: TCP 636 (LDAPS), TCP 445 (SMB/SYSVOL), DNS.
- In der Domäne eine Gruppe **`SAMAUDIT-Benutzer`** mit den normalen Konten der Prüfer:
  - Windows: `New-ADGroup SAMAUDIT-Benutzer -GroupScope Global` und `Add-ADGroupMember SAMAUDIT-Benutzer -Members max.muster`
  - Samba: `samba-tool group add SAMAUDIT-Benutzer` und `samba-tool group addmembers SAMAUDIT-Benutzer max.muster`

### Installation

Auf dem Server liegen nur `docker-compose.yml`, `.env` und der Datenordner – das Programm steckt im Image.

```bash
mkdir -p /opt/samaudit && cd /opt/samaudit
curl -fsSLO https://github.com/soleil0815/samaudit/releases/latest/download/docker-compose.yml
curl -fsSL -o .env https://github.com/soleil0815/samaudit/releases/latest/download/env.example
nano .env            # mindestens DOMAIN_FQDN eintragen
docker compose up -d
```

Ohne `curl` die Dateien aus dem Image kopieren: `docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.yml > docker-compose.yml` (und `/app/dist/.env.example > .env`). Danach im Browser `https://<PUBLIC_HOSTNAME>:9400` öffnen. Beim ersten Aufruf warnt der Browser vor dem selbstsignierten Zertifikat – ein eigenes Zertifikat lädt man unter **Verbindung** hoch.

**Mit Dockhand, Portainer & Co.:** Inhalt der `docker-compose.yml` als Stack anlegen, die Einstellungen der `.env` beim Stack hinterlegen und die Pfade `./data` und `./certs` durch einen festen Ordner ersetzen (z. B. `/opt/samaudit/data`).

**DCs nicht per DNS auflösbar?** Eine Datei `docker-compose.override.yml` neben die `docker-compose.yml` legen – Compose liest sie automatisch mit:

```yaml
services:
  samaudit:
    dns: [10.0.10.10]
    extra_hosts: ["dc01.firma.local:10.0.10.10"]
```

**Ausprobieren ohne Domäne:** In der `.env` `DEMO_MODE=true` setzen, Anmeldung mit `demo` / `demo`.

### Einstellungen (`.env`)

Alle Einstellungen stehen in der Datei `.env` (Vorlage mit Erklärungen: `.env.example`). Nach einer Änderung: `docker compose up -d`. Die wichtigsten:

| Einstellung | Standard | Bedeutung |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS-Name der Domäne (Pflicht) |
| `DC_HOSTS` | `DOMAIN_FQDN` | feste DCs, mit `;` getrennt |
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | Prüfer-Gruppe(n) |
| `DENIED_GROUPS` | – | zusätzlich gesperrte Gruppen |
| `PUBLIC_HOSTNAME` | – | Name, unter dem SAMAUDIT aufgerufen wird |
| `PORT` | `9400` | Port der Weboberfläche auf dem Server |
| `SAMAUDIT_VERSION` | `latest` | Version des Images, z. B. `2.0.0` |
| `LDAP_CERT_MODE` | `auto` | DC-Zertifikat merken (`auto`), immer vertrauen (`trust`), gegen CA prüfen (`verify`) |
| `INACTIVE_DAYS` | `180` | ab wann ein Konto als inaktiv gilt |
| `SMB_CHECKS` | `true` | SYSVOL-Prüfungen über SMB |
| `REPORT_RETENTION_DAYS` | `365` | Berichte automatisch löschen nach … Tagen (0 = nie) |
| `AUDIT_RETENTION_DAYS` | `90` | Protokoll automatisch löschen nach … Tagen (0 = nie) |
| `PRIVACY_CONTACT` | – | Ansprechpartner auf der Datenschutzseite |
| `DEFAULT_LANG` | `de` | Standardsprache |

Die vollständige Liste steht in der README.

### Update

**Mit einer Container-Verwaltung (empfohlen):** Dockhand, Watchtower, Tugtainer o. Ä. halten den Container `samaudit` aktuell. Empfehlung: die Update-Zeit **nachts** legen – ein Neustart bricht einen gerade laufenden Scan ab.

**Von Hand:**

```bash
docker compose pull && docker compose up -d
```

oder `sh update.sh`: merkt sich die laufende Version, prüft die neue und startet bei Problemen wieder die vorige; bringt bei Bedarf eine neuere `docker-compose.yml` mit (die bisherige bleibt als `docker-compose.yml.alt`). Läuft auch auf einem NAS. Ist das Repository privat, auf dem Server einmalig `docker login ghcr.io` (Passwort: GitHub-Token mit `read:packages`).

**Bei jedem Versionswechsel** sichert SAMAUDIT beim ersten Start selbst die Datenbank nach `data/backups/samaudit-vor-<Version>-<Zeit>.db` (die letzten 5 bleiben) – egal, wie das Update kam.

**Version festlegen:** In der `.env` `SAMAUDIT_VERSION=2.0.0` eintragen (oder ein Sicherheitsupdate wie `2.0.0-s1`), dann `docker compose up -d`. Zurück zur neuesten: `SAMAUDIT_VERSION=latest`.

**Zurück auf eine ältere Version:** Eine ältere Version startet nicht auf der Datenbank einer neueren, sondern nennt im Log (`docker compose logs`) die zurückzuspielende Sicherung. Reihenfolge:

```bash
docker compose stop
docker compose run --rm samaudit restore    # Sicherung wählen, z. B. „samaudit-vor-2.1.0-…“ für den Weg zurück von 2.1.0
nano .env                                   # SAMAUDIT_VERSION=2.0.0
docker compose up -d
```

Oder in einem Schritt: `sh update.sh --restore --version=2.0.0`.

**Ohne Internet:** Aus dem GitHub-Release die Image-Datei (`samaudit-<Version>-amd64.tar.gz`, bei ARM `-arm64`) und `SHA256SUMS` holen, in den SAMAUDIT-Ordner kopieren und `sh update.sh --load samaudit-<Version>-amd64.tar.gz` ausführen.

**Umstieg von Version 1.x** (bisher `update.sh` mit ZIP oder `--pull`):

1. Neue `update.sh` holen: `docker pull ghcr.io/soleil0815/samaudit:latest` und `docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/update.sh > update.sh`
2. `sh update.sh` – stellt einmalig auf Docker Compose um (Daten bleiben, `DOCKER_DNS`/`DOCKER_EXTRA_HOSTS` werden in die `docker-compose.override.yml` übernommen).
3. `sh update.sh --cleanup` – zeigt die nicht mehr gebrauchten Dateien früherer Versionen und löscht sie nach Rückfrage. Daten, Sicherungen, `.env`, Compose-Dateien und eingebundene Ordner werden nie angefasst.

### Sicherheitsupdates und Versionen

Alle Bestandteile des Images haben feste Versionen: Basisimage (Debian 13 „trixie“, Python 3.13) mit Prüfsumme, Debian-Pakete und Python-Pakete. Jeden Montag früh prüft GitHub, ob es innerhalb dieses Unterbaus neuere Pakete gibt. Wenn ja, wird ohne Cache neu gebaut, im Image getestet und mit Trivy auf Schwachstellen geprüft. Nur wenn alles bestanden ist, erscheint ein Sicherheitsupdate mit der Versionsnummer `<Version>-s<n>`, z. B. `2.0.0-s1`, und als `latest`. Die geänderten Pakete stehen in `CHANGELOG-SECURITY.md`. Gibt es nichts Neues, passiert nichts. Die laufende Version steht unten links und unter `/healthz` (Feld `image`).

Wer `latest` verwendet (Container-Verwaltung oder `docker compose pull && docker compose up -d`), bekommt das Update. Wer bei einer Version bleiben will, gibt sie fest an.

Zusätzlich wird das veröffentlichte Image täglich gescannt, und jede Woche wird geprüft, wie lange Python 3.13 und Debian 13 noch Sicherheitsupdates bekommen: weniger als 12 Monate ergibt einen Hinweis, weniger als 6 Monate einen roten Lauf. Python und Debian werden nie automatisch auf eine neue Hauptversion gehoben.

**Wenn ein Lauf rot ist:** GitHub schickt eine E-Mail. Es wurde nichts veröffentlicht; die laufenden Installationen bleiben auf dem letzten geprüften Stand. Oben am Lauf steht kurz der Grund:

| Grund | Was tun |
|---|---|
| Trivy meldet CRITICAL/HIGH | Meist kommt die Korrektur in den nächsten Tagen – nächsten Montag abwarten oder den Lauf später unter *Actions → Security update → Run workflow* neu starten. Bleibt er rot: Paket gezielt anheben lassen oder den Fund bewerten und mit Begründung und Ablaufdatum in `.trivyignore` eintragen. |
| *Security update: versions not determinable* / *Build failed* | Meist kurzzeitig eine Quelle nicht erreichbar – Lauf neu starten. Bleibt er rot, prüfen lassen. |
| *Tests in the image failed* | Eine neue Paketversion passt nicht – prüfen lassen. |
| Unterbau bald / jetzt anheben | Wechsel auf die nächste Python- bzw. Debian-Version planen und bewusst durchführen (`tools/lock-policy.env`, `tools/update-locks.sh --major`, neue Programmversion). |
| Täglicher Scan rot | Neue Schwachstelle im veröffentlichten Image – Sicherheitsupdate von Hand starten, sonst wie bei Trivy. |

### Ausgehende Verbindungen

SAMAUDIT selbst verbindet sich nur zu den Domänencontrollern (LDAP, LDAPS, Global Catalog, SMB). Jeder andere Verbindungsversuch wird abgewiesen und im **Protokoll** vermerkt (`EGRESS_GUARD`, Standard an). Eine zusätzliche Abschottung auf Netzwerkebene regeln Sie bei Bedarf mit Ihrer eigenen Firewall (Docker-Netz `samaudit-net`, Bridge `br-samaudit`).

### Daten, Sicherung und Wiederherstellung

Alles, was SAMAUDIT speichert, liegt im Ordner `data/`: die Datenbank `samaudit.db` (Berichte, Protokoll, gemerkte DC-Zertifikate), unter `backups/` die automatischen Sicherungen vor jedem Versionswechsel und unter `tls/` die Zertifikate der Weboberfläche.

**Sicherung zurückspielen:**

```bash
docker compose stop
docker compose run --rm samaudit restore    # Liste der Sicherungen, Auswahl per Nummer
docker compose up -d
```

Die Datenbank vor dem Zurückspielen bleibt als `samaudit-ersetzt-<Zeit>.db` erhalten. **Komplette Sicherung** (z. B. vor einem Umzug): `docker compose stop`, `sudo tar czf samaudit-backup.tgz data .env`, `docker compose start`.

### Datenschutz

SAMAUDIT überträgt keine Daten an Dritte, lädt nichts aus dem Internet und löscht Berichte und Protokoll automatisch. Für Ihre Dokumentation (Verzeichnis von Verarbeitungstätigkeiten, Abstimmung mit Datenschutzbeauftragten und Betriebsrat) siehe `DATENSCHUTZ.md`.

### Fehlersuche

| Problem | Lösung |
|---|---|
| Container startet nicht, Log: „START REFUSED: The database comes from SAMAUDIT …“ | Eine ältere Version läuft auf der Datenbank einer neueren – die genannte Sicherung zurückspielen (siehe oben) oder wieder die neuere Version verwenden. |
| Hinweis „docker-compose.yml ist veraltet“ (Log: „Note: your docker-compose.yml is outdated …“) | Aktuelle Datei holen (`sh update.sh` oder `/app/dist/docker-compose.yml` aus dem Image), eigene Ergänzungen in die `docker-compose.override.yml`, `docker compose up -d`. |
| Kein DC erreichbar | DNS im Container: `dns`/`extra_hosts` in der `docker-compose.override.yml` eintragen (siehe Installation), dann `docker compose up -d`. |
| Viele Prüfungen „nicht prüfbar (SMB)“ | TCP 445 zu den DCs freigeben oder `SMB_CHECKS=false`. |
| Logs ansehen | `docker compose logs -f` |
| Version prüfen | `curl -k https://localhost:9400/healthz` |

---

SAMAUDIT ist freie Software unter der GNU AGPL-3.0-or-later und wird ohne Gewährleistung bereitgestellt. Die Bewertungen sind Hinweise und ersetzen keine fachliche Prüfung. Webseite: [helfi.space](https://helfi.space)
