# SAMAUDIT – Handbuch

SAMAUDIT prüft die Sicherheit Ihres Active Directory (Windows AD oder Samba AD). Es liest die Domäne mit den Rechten eines **normalen** Benutzerkontos aus, wendet 110 Prüfungen an und zeigt das Ergebnis als Risikowert, ausführlichen Bericht mit Maßnahmen und PDF.

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

Alle 110 Prüfungen mit Kennung, Bereich, Schweregrad und Beschreibung. Die Kennungen beginnen mit `STL-` (veraltete Objekte), `PRV-` (privilegierte Konten), `TRS-` (Vertrauensstellungen) und `ANM-` (Anomalien).

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

- Linux-Server mit Docker (Docker Compose wird nicht benötigt).
- Vom Server zu den DCs: TCP 636 (LDAPS), TCP 445 (SMB/SYSVOL), DNS.
- In der Domäne eine Gruppe **`SAMAUDIT-Benutzer`** mit den normalen Konten der Prüfer:
  - Windows: `New-ADGroup SAMAUDIT-Benutzer -GroupScope Global` und `Add-ADGroupMember SAMAUDIT-Benutzer -Members max.muster`
  - Samba: `samba-tool group add SAMAUDIT-Benutzer` und `samba-tool group addmembers SAMAUDIT-Benutzer max.muster`

### Installation

```bash
unzip samaudit-v*.zip -d /opt && cd /opt/samaudit
cp .env.example .env
nano .env            # mindestens DOMAIN_FQDN und PUBLIC_HOSTNAME eintragen
./update.sh
```

`update.sh` baut das Image, startet den Container und prüft, dass alles läuft. Danach im Browser `https://<PUBLIC_HOSTNAME>:9400` öffnen. Beim ersten Aufruf warnt der Browser vor dem selbstsignierten Zertifikat – ein eigenes Zertifikat lädt man unter **Verbindung** hoch.

**Ausprobieren ohne Domäne:** In der `.env` `DEMO_MODE=true` setzen, Anmeldung mit `demo` / `demo`.

### Einstellungen (`.env`)

Alle Einstellungen stehen in der Datei `.env` (Vorlage mit Erklärungen: `.env.example`). Nach einer Änderung genügt `sh update.sh --restart`. Die wichtigsten:

| Einstellung | Standard | Bedeutung |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS-Name der Domäne (Pflicht) |
| `DC_HOSTS` | `DOMAIN_FQDN` | feste DCs, mit `;` getrennt |
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | Prüfer-Gruppe(n) |
| `DENIED_GROUPS` | – | zusätzlich gesperrte Gruppen |
| `PUBLIC_HOSTNAME` | – | Name, unter dem SAMAUDIT aufgerufen wird |
| `PORT` | `9400` | Port der Weboberfläche |
| `LDAP_CERT_MODE` | `auto` | DC-Zertifikat merken (`auto`), immer vertrauen (`trust`), gegen CA prüfen (`verify`) |
| `INACTIVE_DAYS` | `180` | ab wann ein Konto als inaktiv gilt |
| `SMB_CHECKS` | `true` | SYSVOL-Prüfungen über SMB |
| `REPORT_RETENTION_DAYS` | `365` | Berichte automatisch löschen nach … Tagen (0 = nie) |
| `AUDIT_RETENTION_DAYS` | `90` | Protokoll automatisch löschen nach … Tagen (0 = nie) |
| `PRIVACY_CONTACT` | – | Ansprechpartner auf der Datenschutzseite |
| `DEFAULT_LANG` | `de` | Standardsprache |

Die vollständige Liste steht in der README.

### Update

**Fertiges Image von GitHub (empfohlen):**

```bash
sh update.sh --pull
```

Holt die neueste Version von `ghcr.io/soleil0815/samaudit`, sichert vorher Datenbank und Zertifikate, startet die neue Version, prüft sie und startet bei Problemen automatisch wieder die bisherige. `update.sh` selbst wird dabei mit aktualisiert. Eine bestimmte Version: `sh update.sh --pull=1.9.6`. Ist das Repository privat, auf dem Server einmalig `docker login ghcr.io` (Passwort: GitHub-Token mit `read:packages`).

**Per ZIP-Datei (lokaler Build):**

Die neue ZIP-Datei in den SAMAUDIT-Ordner kopieren (z. B. per WinSCP) und dort ausführen:

```bash
sh update.sh samaudit-*.zip
```

Das Skript zeigt die installierte und die neue Version und fragt nach. Dann sichert es die bisherigen Programmdateien (`backups/program-*.tgz`), spielt die neuen ein und entfernt Dateien, die es in der neuen Version nicht mehr gibt. Ihre `.env`, `data/`, `certs/` und `backups/` werden nie verändert. Zum Schluss fragt es, ob die ZIP-Datei gelöscht werden soll. Ohne ZIP (`./update.sh`) wird nur neu gebaut und gestartet, mit `--restart` nur neu gestartet.

Bei jedem Lauf sichert das Skript außerdem Datenbank und Zertifikate nach `backups/` (die letzten 5 bleiben), baut neu, startet, prüft die Funktion und räumt alte Images auf. Läuft die neue Version nicht, startet automatisch wieder die bisherige. Ihre `.env`, `data/`, `certs/` und `backups/` bleiben erhalten. Optionen: `--no-backup`, `--no-cache`, `--help`. Jeder Bau holt das aktuelle Basisimage, alle Sicherheitsupdates und die neuesten Paketversionen.

### Ausgehende Verbindungen

SAMAUDIT selbst verbindet sich nur zu den Domänencontrollern (LDAP, LDAPS, Global Catalog, SMB). Jeder andere Verbindungsversuch wird abgewiesen und im **Protokoll** vermerkt (`EGRESS_GUARD`, Standard an). Eine zusätzliche Abschottung auf Netzwerkebene regeln Sie bei Bedarf mit Ihrer eigenen Firewall (Docker-Netz `samaudit-net`, Bridge `br-samaudit`).

### Daten, Sicherung und Wiederherstellung

Alles, was SAMAUDIT speichert, liegt im Ordner `data/` im SAMAUDIT-Ordner: die Datenbank `samaudit.db` (Berichte, Protokoll, gemerkte DC-Zertifikate) und unter `tls/` die Zertifikate der Weboberfläche.

**Sicherung:** automatisch bei jedem `./update.sh` nach `backups/`. **Wiederherstellen:**

```bash
docker stop samaudit
sudo rm -f data/samaudit.db-wal data/samaudit.db-shm
sudo tar xzf backups/samaudit-<version>-<datum>.tgz -C data
docker start samaudit
```

### Datenschutz

SAMAUDIT überträgt keine Daten an Dritte, lädt nichts aus dem Internet und löscht Berichte und Protokoll automatisch. Für Ihre Dokumentation (Verzeichnis von Verarbeitungstätigkeiten, Abstimmung mit Datenschutzbeauftragten und Betriebsrat) siehe `DATENSCHUTZ.md`.

### Fehlersuche

| Problem | Lösung |
|---|---|
| `update.sh` meldet „.env fehlte“ | `.env` wurde aus der Vorlage angelegt – `DOMAIN_FQDN` eintragen, erneut starten. |
| Kein DC erreichbar | DNS im Container: DCs in der `.env` per `DOCKER_EXTRA_HOSTS=dc01.firma.local:10.0.0.10` eintragen oder `DOCKER_DNS` setzen, dann `sh update.sh --restart`. |
| Viele Prüfungen „nicht prüfbar (SMB)“ | TCP 445 zu den DCs freigeben oder `SMB_CHECKS=false`. |
| Logs ansehen | `docker logs -f samaudit` |
| Version prüfen | `curl -k https://localhost:9400/healthz` |

---

SAMAUDIT ist freie Software unter der GNU AGPL-3.0-or-later und wird ohne Gewährleistung bereitgestellt. Die Bewertungen sind Hinweise und ersetzen keine fachliche Prüfung. Webseite: [helfi.space](https://helfi.space)
