# Änderungen – SAMAUDIT

*English version: [CHANGELOG.md](CHANGELOG.md)*

Programmversionen. Die wöchentlichen Sicherheitsupdates (gleiches Programm, nur neue Paketstände) stehen in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md).

## 2.1.7 – neuer Kaffee-Link

- Der „Buy me a coffee“-Link führt jetzt zu [buymeacoffee.com/soleil0815](https://buymeacoffee.com/soleil0815) (im Programm, in der README, in den Release-Texten und beim Sponsor-Knopf auf GitHub).

## 2.1.6 – kompakter Kaffee-Knopf

- Kompakter „Buy me a coffee“-Knopf (gelbe Pille mit dem offiziellen Becher-Symbol, lokal gespeichert) unten in der Seitenleiste auf allen Seiten, auch auf der Übersicht, und auf der Hilfe-Seite.

## 2.1.5 – Kaffee-Knopf

- Der offizielle „Buy me a coffee“-Knopf steht unten in der Seitenleiste (alle Seiten außer der Übersicht) und auf der Hilfe-Seite, lokal gespeichert (keine Anfrage an deren Server; die Sicherheitsrichtlinie bleibt `img-src 'self'`).
- GitHub: Sponsor-Knopf (`.github/FUNDING.yml`), derselbe Knopf oben in der README und ein Link am Ende jedes Release-Textes.

## 2.1.4 – englischer Name der Prüfer-Gruppe

- **Neue Standard-Prüfer-Gruppe `SAMAUDIT-Users`** (bisher `SAMAUDIT-Benutzer`), damit englischsprachige Admins wissen, was sie anlegen müssen.
- **Bestehende Installationen müssen nichts tun:** Ist `ALLOWED_GROUPS` in der `.env` gesetzt, gilt wie bisher genau diese Gruppe. Ohne Einstellung werden `SAMAUDIT-Users` und der bisherige Name `SAMAUDIT-Benutzer` angenommen. Privilegierte Konten werden weiterhin immer abgewiesen.
- `.env.example` setzt die Gruppe nicht mehr ausdrücklich; Anmelde- und Datenschutzseite nennen alle angenommenen Gruppen.

## 2.1.3 – erste öffentliche Version

- **SAMAUDIT ist jetzt Open Source** unter [github.com/soleil0815/samaudit](https://github.com/soleil0815/samaudit).
- **Englisch für Betrieb und Entwicklung:** Server-Protokoll, Meldungen von `update.sh` und `restore`, die automatischen Texte auf GitHub (Einträge der Sicherheitsupdates, Release-Texte, Meldungen der Abläufe) und alle Kommentare im Code sind jetzt englisch. Beispiel: `START REFUSED` statt `START ABGEBROCHEN`. `update.sh` und `restore` nehmen weiter deutsche Antworten (`j`/`ja`) an. Oberfläche, PDF und Handbuch bleiben zweisprachig.
- **Fehlerbehebung:** Fehlermeldungen beim Hochladen eines eigenen Zertifikats und einige Scan-Fehler erscheinen jetzt in der gewählten Sprache der Oberfläche (bisher nur deutsch).

## 2.1.2 – bereit für Open Source

- **GitHub-Seite auf Englisch** mit Kurzanleitung in drei Schritten (zwei Dateien, eine Einstellung, `docker compose up -d`); deutsche Fassung in [README.de.md](README.de.md). Die Versionsgeschichte steht jetzt in dieser Datei.
- **Hilfe-Seite:** Lizenz, Link zum Quellcode und ein freiwilliger „Kaffee spendieren“-Link (nicht auf der Übersicht). Die Anmeldeseite verlinkt den Quellcode (AGPL).
- **Mitmachen:** [CONTRIBUTING.md](CONTRIBUTING.md) mit DCO-Abzeichnung, Issue-Formulare mit Warnung vor echten Domänendaten, vertrauliche Meldung von Sicherheitslücken.
- **Lizenzen:** Liste der Fremdkomponenten mit dem aktuellen Paketstand abgeglichen; Lizenzkopf in jeder Quelldatei; Markenhinweis erweitert. Die Demo-Daten nutzen nur noch reservierte Beispiel-Domänen.

## 2.1.1 – automatische Code-Prüfung

- **Statische Prüfungen bei jedem Pull Request:** ruff (Programmierfehler und die Sicherheitsregeln von Bandit) und mypy (Typprüfung) laufen in GitHub vor den Selbsttests. Ein Fund färbt den Lauf rot – dann wird nichts veröffentlicht. Bewusst zugelassene Stellen sind im Code mit Begründung markiert, die Regeln stehen in `pyproject.toml`.
- **Dabei gefundene und behobene Fehler:** Bei einer Anmeldung mit einer nicht lesbaren Gruppen-SID im Token konnte die Anmeldung mit einem internen Fehler abbrechen statt sauber geprüft zu werden. Die Übersicht stürzte ab, wenn der neueste Bericht gerade gelöscht wurde. Ein Übersetzungseintrag ohne deutschen Text führte zu einem Fehler statt zur Anzeige des Schlüssels. Der Zertifikats-Upload verstand Feldnamen in RFC-2231-Schreibweise nicht.
- **Aktualisierte Pakete:** anyio 4.16.0 und Debian-Paketstand vom 01.11.2026 (innerhalb der Basis Debian 13 / Python 3.13).
- Sonst keine Änderungen am Verhalten; die Prüfungen und Berichte sind unverändert.

## 2.1.0 – fünf neue Prüfungen (jetzt 115)

- **ESC13 (PRV-38):** Zertifikatvorlagen, deren Ausstellungsrichtlinie mit einer AD-Gruppe verknüpft ist – wer das Zertifikat beantragen darf, bekommt die Gruppenrechte ohne Mitgliedschaft (kritisch, wenn die Gruppe privilegiert ist).
- **Golden gMSA/dMSA (PRV-39):** Wer außer Domänen-/Organisations-Admins und DCs den KDS-Stammschlüssel lesen (oder sich die Rechte dafür verschaffen) darf, kann alle gMSA- und dMSA-Kennwörter dauerhaft ausrechnen. Der Schlüssel selbst wird dabei nie abgerufen. Mit einem normalen Konto sind die Schlüsselobjekte meist unsichtbar; dann prüft SAMAUDIT die vererbten Rechte und meldet den Rest als „nicht prüfbar“.
- **gMSA-Kennwort für zu viele abrufbar (PRV-40):** breite Gruppen wie „Domänen-Benutzer“ oder „Domänencomputer“ in msDS-GroupMSAMembership, bei privilegierten gMSA auch einzelne Nicht-Administratoren.
- **Certighost, CVE-2026-54121 (PRV-41):** Benutzer dürfen Computerkonten anlegen und eine Unternehmens-CA bietet eine Anmeldevorlage (z. B. „Computer“) für Domänencomputer oder alle Benutzer an – dann ist die Domänenübernahme möglich, solange die CA das Update vom Juli 2026 nicht hat. Da SAMAUDIT den Patchstand nicht sieht und das in vielen Domänen der Standard ist, ist die Prüfung als Erinnerung niedrig gewichtet.
- **Gruppenrichtlinie lockert Anmeldeschutz (ANM-45):** leere Kennwörter bei Netzwerkanmeldung, anonyme SAM-Aufzählung, „Jeder“-Rechte für Anonyme, anonymer Zugriff auf Named Pipes/Freigaben (wie PingCastle A-LimitBlankPasswordUse / A-AnonymousAuthorizedGPO).
- **Windows Server 2016 (STL-11):** ab 90 Tagen vor dem Supportende (12.01.2027) mit Punkten, bei Domänencontrollern dringlicher; danach zählen die Systeme automatisch als „ohne Herstellersupport“ (bisher wären sie dauerhaft nur als „läuft bald aus“ geführt worden).
- **NTLMv1 (ANM-17):** Hinweis auf das Oktober-Update 2026, das NTLMv1-Anmeldungen für Single Sign-on standardmäßig blockiert.
- **Aktualisierte Pakete:** Python 3.13.18, pyasn1 0.6.5 (behebt vier als hoch eingestufte Lücken, die Trivy beim ersten Veröffentlichungsversuch gefunden hat), neue Zeitzonendaten.

## 2.0.0 – Installation und Updates wie bei Docker üblich

- **Nur noch drei Dinge auf dem Server:** `docker-compose.yml`, `.env` und der Datenordner. Das Programm steckt komplett im Image – kein ZIP, kein Programmordner, kein lokaler Bau. Installation: zwei Dateien holen, `.env` ausfüllen, `docker compose up -d`.
- **Updates wie gewohnt:** mit einer Container-Verwaltung (Dockhand, Watchtower, Tugtainer …) oder `docker compose pull && docker compose up -d`. Die Version steht in der `.env` (`SAMAUDIT_VERSION`, Standard `latest`).
- **Das Programm sichert sich selbst:** Beim ersten Start einer neuen Version legt SAMAUDIT eine Sicherung der Datenbank an (`data/backups/samaudit-vor-<Version>-…db`) und passt erst danach die Datenbank an – egal, wie das Update kam. Startet eine ältere Version auf einer Datenbank einer neueren, bricht sie mit einer klaren Meldung ab, welche Sicherung zurückzuspielen ist (`docker compose run --rm samaudit restore`).
- **Stabile `docker-compose.yml`:** Die Datei hat eine Versionsnummer; ist sie veraltet, zeigt SAMAUDIT einen Hinweis. Eigene Ergänzungen (DNS, feste Host-Einträge) gehören in `docker-compose.override.yml`. Im Container läuft SAMAUDIT immer auf Port 9400, `PORT` in der `.env` bestimmt nur noch den Port nach außen.
- **Neues `update.sh`** (für den Weg von Hand, läuft mit `/bin/sh`, auch auf einem NAS): merkt sich die vorige Version, prüft die neue und startet bei Problemen wieder die vorige; ohne Internet mit `--load` aus der Image-Datei des Releases; `--restore` spielt eine Sicherung zurück; `--cleanup` räumt Dateien früherer Versionen auf.
- **Ohne Internet:** Jedes Release enthält die Image-Dateien für amd64 und arm64 mit Prüfsummen.
- **Entfallen:** ZIP-Pakete, lokaler Bau durch `update.sh`, Start per `docker run`, `DOCKER_DNS`/`DOCKER_EXTRA_HOSTS` in der `.env` (werden beim Umstieg automatisch in die `docker-compose.override.yml` übernommen).
- **Umstieg** bestehender Installationen: einmal `sh update.sh`, danach `sh update.sh --cleanup` – siehe [Umstieg von Version 1.x](#umstieg-von-version-1x).
- Veröffentlicht wird nur noch nach ausdrücklicher Freigabe; Pull Requests werden nicht mehr automatisch übernommen.

## 1.9.8

- **Docker-Compose-Vorlage:** `docker-compose.example.yml` startet SAMAUDIT mit denselben Sicherheitseinstellungen wie `update.sh` – z. B. als Stack in Dockhand oder Portainer oder mit `docker compose up -d`. Siehe [Mit Docker Compose oder Dockhand](#mit-docker-compose-oder-dockhand). Die Vorlage liegt auch im Image (`/app/dist/`) und wird von `update.sh --pull` aktuell gehalten.

## 1.9.7 – feste Versionen und wöchentliche Sicherheitsupdates

- **Reproduzierbarer Bau:** Statt „immer die neueste Version“ ist jetzt alles fest: das Basisimage mit Version **und** Digest (`python:3.13.17-slim-trixie@sha256:…`), die Debian-Pakete über einen festen Stand von snapshot.debian.org und alle Python-Pakete samt Unterabhängigkeiten mit exakter Version und Prüfsummen (`requirements.txt`, erzeugt aus `requirements.in`). Gleicher Quellstand ergibt gleiches Image. Die Debian-Paketliste steht in `locks/os-packages.txt` und wird bei jedem Bau verglichen. `tools/update-locks.sh` ermittelt die Versionen neu.
- **Wöchentliches Sicherheitsupdate auf GitHub** (montags früh, auch von Hand startbar): aktualisiert nur innerhalb des Unterbaus, baut ohne Cache, testet im Image, prüft mit Trivy und veröffentlicht nur bei Erfolg – als `latest` und `<Version>-s<n>` (z. B. `1.9.7-s1`). Die geänderten Pakete stehen in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md). Siehe [Sicherheitsupdates und Versionen](#sicherheitsupdates-und-versionen).
- **Weniger im Image:** pip und apt werden nach dem Bau entfernt – sie werden zur Laufzeit nicht gebraucht.
- **Täglicher Scan** des veröffentlichten Images und **Unterbau-Warnung** (Supportende von Python und Debian laut endoflife.date).
- **Abgesicherte GitHub-Abläufe:** Actions auf Commit-Hashes fixiert, je Job nur die nötigen Rechte, keine gespeicherten Git-Zugangsdaten, Veröffentlichung nur von `main`, nie zwei gleichzeitig, veröffentlichte Versionen werden nie überschrieben, `latest` nur für die höchste Version. Selbsttests dafür in `tests/test_pipeline.py`.
- Weboberfläche, PDF und `/healthz` (Feld `image`) zeigen die Image-Version, z. B. `1.9.7-s2`. Die Issues des alten Montagslaufs entfallen; einen roten Lauf meldet GitHub per E-Mail.

## 1.9.6

- **Alles im Image bleibt aktuell:** Neben Debian und Python werden jetzt auch alle Python-Pakete (inkl. Unterabhängigkeiten) bei jedem Bau in der neuesten Version installiert – auch beim wöchentlichen Neubau. `requirements.txt` enthält nur noch Mindestversionen. Der Rauchtest läuft jetzt im fertigen Image, also mit genau den Paketversionen, die veröffentlicht würden; zusammen mit dem Trivy-Scan entscheidet er, ob `latest` erneuert wird. Die Versionen jedes Images stehen in `/app/package-versions.txt` und in der Zusammenfassung des GitHub-Laufs.
- **Unterbau anheben:** Nur der Wechsel auf die nächste Python-Hauptversion bleibt ein bewusster Schritt. Ab Mai 2029 erinnert der wöchentliche Lauf per Issue daran, dass Python 3.13 am 31.10.2029 ausläuft.
- `update.sh` holt bei jedem lokalen Bau das aktuelle Basisimage; `--lock` und `--refresh-base` werden nicht mehr gebraucht.

## 1.9.5

- **Python wird mit aktualisiert:** Das Image baut auf `python:3.13-slim` statt fest auf 3.13.16 auf. Der wöchentliche Neubau nimmt damit automatisch die neueste Python-3.13-Version mit (derzeit 3.13.17) – Fehler- und Sicherheitskorrekturen von Python selbst, kein Sprung auf 3.14. Wie bisher wird jeder Neubau getestet und mit Trivy geprüft, bevor er als `latest` erscheint.

## 1.9.4

- **Sicherheitsupdates im Image, jede Woche:** Beim Bau werden jetzt alle verfügbaren Debian-Sicherheitsupdates des Basisimages eingespielt. GitHub baut `main` jeden Montag neu, testet, prüft mit Trivy und veröffentlicht nur bei Erfolg als `latest` – so bekommt das Image laufend Sicherheitsupdates, auch ohne Änderungen am Programm. Schlägt Test oder Scan fehl, bleibt `latest` unverändert und ein GitHub-Issue nennt den Grund (z. B. ein Python-Paket, das eine neue Version braucht; das wird dann gezielt aktualisiert).

## 1.9.3

- **Schwachstellen-Scan mit Trivy:** Jedes Image wird vor der Veröffentlichung gescannt. Kritische oder hohe Schwachstellen, für die es bereits eine Korrektur gibt, stoppen die Veröffentlichung – `latest` bleibt dann auf dem letzten sauberen Stand. Alles andere (z. B. Schwachstellen ohne verfügbare Korrektur) steht im Bericht des Laufs (Zusammenfassung und Artefakt `trivy-report`). Bewusst akzeptierte Ausnahmen gehören mit Begründung in `.trivyignore`.
- **Wöchentlicher Nachscan:** Montags wird das veröffentlichte `latest` erneut geprüft, denn Schwachstellen werden oft erst nach dem Bau bekannt. Dazu wird `main` jeden Montag automatisch neu gebaut – mit dem aktuellen Basisimage (Debian-Sicherheitsupdates) –, getestet und mit Trivy geprüft; nur wenn alles grün ist, wird das Ergebnis als `latest` veröffentlicht (die Versionsnummer bleibt). Andernfalls bleibt `latest` unverändert, und ein GitHub-Issue „Wöchentlicher Neubau …“ nennt den Grund (z. B. ein Python-Paket, das eine neue Version braucht) und erwähnt den Repository-Besitzer. Der nächste erfolgreiche Neubau schließt das Issue.
- Trivy wird als feste Version mit geprüfter Prüfsumme geladen, nicht über die Trivy-GitHub-Action, deren Versions-Tags im März 2026 kompromittiert waren (CVE-2026-33634).

## 1.9.2 – Code-Audit

Vier unabhängige Prüfungen (Weboberfläche, LDAP/SYSVOL, Prüfregeln, Build/Update/CI); alle bestätigten Befunde mit hoher Auswirkung sind behoben.

- **Anmeldung:**
  - Organisations-, Schema- und Domänen-Admins **jeder** Domäne der Gesamtstruktur werden abgewiesen, auch in untergeordneten Domänen. Geprüft wird zusätzlich der SID-Verlauf.
  - Die „Who am I“-Gegenprobe vergleicht jetzt auch die Domäne.
  - LDAP folgt keinen Verweisen mehr. Bisher hätte ein Verweis das Passwort erneut, unter Umständen unverschlüsselt, senden können.
  - Sperrlisten, die sich nicht auflösen lassen, führen zur Abweisung statt zum Durchlassen.
- **LDAPS-Vertrauen:**
  - Das DC-Zertifikat muss ein Serverzertifikat sein und den beim ersten Kontakt gesehenen DNS-Namen tragen. Ein von der Unternehmens-CA für beliebige Rechner oder Benutzer ausgestelltes Zertifikat wird abgewiesen.
  - Eine neue Adresse eines bereits gemerkten Namens (z. B. der zweite DC, wenn der erste ausfällt) wird nur übernommen, wenn ihr Zertifikat zu einem DC der Domäne gehört (bekannt aus dem letzten Scan).
  - `python -m app.pins reset firma.local` entfernt jetzt auch alle Einträge „firma.local [IP]“.
  - Das Zurücksetzen gemerkter Zertifikate geht standardmäßig nur noch auf dem Server (`PIN_RESET_WEB`).
- **Login-Sperre:** gilt jetzt auch bei vielen gleichzeitigen Versuchen. Wiederholte gesperrte Versuche füllen das Protokoll nicht mehr.
- **Robustheit:**
  - Eine fehlerhafte PEM-Datei legt die Anwendung nicht mehr lahm.
  - Anfragen werden nur bis zur Größengrenze gelesen.
  - Lange Werte sprengen das PDF nicht mehr.
- **Folgenreiche Aktionen:** Zertifikat hochladen/entfernen und Berichte löschen prüfen vorher erneut im AD, ob der Prüfer noch berechtigt ist.
- **SYSVOL:**
  - `GptTmpl.inf` wird wie von Windows gelesen. Eine einzige Zeile ohne „=“ verwarf vorher die ganze Datei; dadurch waren u. a. Druckwarteschlange, LDAP-Signierung und Benutzerrechte oft falsch.
  - Groß-/Kleinschreibung spielt keine Rolle mehr.
  - Eine kaputte Datei stoppt nicht mehr den ganzen Scan.
  - Für den Prüfer nicht lesbare GPOs ergeben „nicht prüfbar“ statt eines falschen Ergebnisses.
- **Ehrlichere Ergebnisse:** Konnte ein Datenabschnitt nicht gelesen werden (Suchfehler), gelten die betroffenen Prüfungen als „nicht prüfbar“, nicht als „bestanden“.
- **Prüfregeln – Fehlalarme beseitigt:**
  - Vertrauensstellungs-Konten
  - sMSA
  - eingebauter Administrator (inaktiv bzw. in Schema-Admins)
  - AZUREADSSOACC$
  - Windows 10 LTSC (Supportende je nach Build)
  - alte, abgelaufene CA-Zertifikate nach einer Erneuerung
  - Exchange-Standardrecht auf DCs
  - MIT-Kerberos-Bereiche
  - FullSecureChannelProtection (wirkt seit 2021 nicht mehr)
  - doppelte Wertung von DCSync/Domänen-ACL und ESC1/9/15/17
- **Prüfregeln – Lücken geschlossen:**
  - Delegierung an DC-Dienste mit dreiteiligem SPN
  - Primärgruppe „Domänen-Admins“ in deutschen Domänen
  - fehlende Tombstone-Lebensdauer (= 60 Tage)
  - NTLMv1 auf Stufe 3/4
  - untergeordnete Domänen bei AD CS
- **Weitere Korrekturen:**
  - ESC8 meldet „nicht prüfbar“, weil `/certsrv` nicht im AD steht.
  - Der STL-21-Text entspricht jetzt KB5073381.
- **update.sh:**
  - Ein neues `update.sh` aus dem Image wird nie mehr ungefragt ausgeführt (auch nicht mit `-y`); es liegt als `update.sh.new` bereit.
  - Abgebrochene Updates werden beim nächsten Lauf erkannt und die letzte funktionierende Version wiederhergestellt; Strg+C während des Wechsels rollt zurück.
  - ZIP-Pakete mit symbolischen Links oder unsicheren Pfaden werden abgelehnt.
  - Vor einer Schemaänderung sichert die Anwendung die Datenbank selbst (`data/samaudit.db.vor-*.bak`).
- **GitHub:**
  - Vor dem Bauen läuft ein Rauchtest (`tests/smoke.py`).
  - Automatisch übernommen wird nur genau der getestete Stand.
  - Ein Veröffentlichungslauf wird nicht mehr abgebrochen.
  - Veröffentlichte Versionsnummern werden nicht überschrieben.
  - Dependabot hält die GitHub Actions aktuell.

## 1.9.1

- **Neuigkeiten in der App:** Unten links unter **Neuigkeiten** steht, was sich je Version geändert hat – gekennzeichnet als Funktion, Sicherheit, Fehlerbehebung oder Hinweis (z. B. zur RC4-Abschaltung). Neue Einträge zeigt ein kleiner Punkt an (orange bei Sicherheit) sowie einmalig eine schmale Zeile auf der Übersicht, die sich ausblenden lässt. Die Einträge kommen mit dem Update (`app/docs/news.json`), es wird nichts aus dem Internet geladen; nur ein Cookie merkt sich die zuletzt gesehene Version.

## 1.9.0

- **5 neue Prüfungen (jetzt 110)** zu Neuerungen aus 2025/2026:
  - **STL-21 Kerberos-RC4:** Dienstkonten ohne AES-Schlüssel und auf RC4 festgelegte Konten – sie fallen mit der RC4-Abschaltung von Microsoft (CVE-2026-20833, seit April/Juli 2026) aus.
  - **STL-22 Schwache Zertifikatszuordnung:** `altSecurityIdentities` mit Antragsteller, Aussteller+Antragsteller oder E-Mail (seit September 2025 voll erzwungen, KB5014754).
  - **PRV-36 ESC17:** Zertifikatvorlagen, mit denen normale Konten ein Serverzertifikat für beliebige Namen erhalten (z. B. WSUS über HTTPS übernehmen; TROOPERS 2026).
  - **PRV-37 dMSA / „BadSuccessor“:** Wer auf DCs mit Windows Server 2025 delegierte Dienstkonten anlegen darf und welche dMSAs auf privilegierte Konten verweisen.
  - **ANM-44 UPN/SPN-Missbrauch („KerberLoss“, „ResetNightmare“, 2026):** unsichtbare Unicode-Zeichen in UPN/SPN, UPNs gleich dem Anmeldenamen eines anderen Kontos, doppelte Namen, abgeschaltete Eindeutigkeitsprüfung.
- Zusätzlich gelesen werden `altSecurityIdentities`, das Erstellungsdatum der Gruppen sowie OUs und dMSAs (nur wenn das Schema Windows Server 2025 kennt).

## 1.8.1

- **Windows-Zeilenenden werden repariert:** Wurde `update.sh` über Windows kopiert oder bearbeitet (CRLF), brach `sh update.sh` mit „Syntax error: "(" unexpected“ ab. Das Skript wandelt sich jetzt selbst (und `entrypoint.sh`, `Dockerfile`, Paketlisten) automatisch um; `.gitattributes` sorgt dafür, dass Git die Dateien auch unter Windows mit LF auscheckt.
- **Lizenz:** `LICENSE` enthält den vollständigen Text der GNU AGPL v3, der Copyright-Hinweis steht in `NOTICE`; beide liegen auch im Container-Image.

## 1.8.0

- **Bereit für GitHub:** Das Container-Image wird per GitHub Actions gebaut und unter `ghcr.io/soleil0815/samaudit` veröffentlicht (amd64 + arm64, mit SBOM). Siehe [GitHub: Repository und Container-Image](#github-repository-und-container-image).
- **`sh update.sh --pull`:** holt das fertige Image von GitHub statt lokal zu bauen – mit Sicherung, Funktionsprüfung und automatischem Rückfall wie bisher. `update.sh` und `.env.example` liegen im Image und werden dabei mit aktualisiert. Klassisch per ZIP oder lokalem Build geht weiterhin.
- Dockhand-Label entfernt.

## 1.7.5

- **Installationsdateien auf Englisch:** `update.sh` (alle Meldungen und Rückfragen, Antwort mit `y`/`n` – `j` geht weiterhin), `.env.example`, `Dockerfile`, `entrypoint.sh`, `requirements.*`, `certs/README.txt`. Weboberfläche, Berichte und Handbuch bleiben zweisprachig.
- Sicherungen der Programmdateien heißen jetzt `backups/program-*.tgz`.

## 1.7.4

- **Host-Firewall entfernt:** `samaudit-firewall.sh` und der systemd-Dienst `samaudit-firewall` entfallen; `update.sh` setzt keine iptables-Regeln mehr und braucht dafür kein root/sudo. Beim ersten Update entfernt es die Regeln und den Dienst früherer Versionen automatisch. Die programminterne Sperre (`EGRESS_GUARD`) bleibt: SAMAUDIT selbst verbindet sich weiterhin nur zu den Domänencontrollern.

## 1.7.3

- **Paketname in Kleinbuchstaben:** `samaudit-v1.7.3.zip` mit dem Ordner `samaudit/` – Update mit `sh update.sh samaudit-*.zip`.
- **Sicherer Wechsel beim Update:** Der bisherige Container wird erst entfernt, wenn der neue läuft und geprüft ist. Startet der neue nicht oder wird er nicht „healthy“, läuft automatisch wieder die bisherige Version.
- `.env` darf Windows-Zeilenenden (CRLF) und BOM enthalten (z. B. nach Bearbeitung mit WinSCP/Notepad); Kommentare hinter Werten werden überall korrekt ignoriert.

## 1.7.2

- **Docker Compose wird nicht mehr benötigt** – nur noch Docker. `update.sh` baut und startet den Container selbst (mit denselben Sicherheitseinstellungen wie bisher). `docker-compose.yml` und `docker-compose.override.example.yml` entfallen; ein bestehender, mit Compose gestarteter Container wird beim Update einfach ersetzt.
- Nach Änderungen an der `.env`: `sh update.sh --restart` (ohne Neubau).
- DNS-Server und feste DC-Namen bei Bedarf über `DOCKER_DNS` und `DOCKER_EXTRA_HOSTS` in der `.env` (ab 2.0: `docker-compose.override.yml`).

## 1.7.1

- **Update in einem Befehl:** ZIP-Datei in den SAMAUDIT-Ordner legen und `sh update.sh samaudit-*.zip` ausführen. Das Skript zeigt installierte und neue Version, fragt nach, sichert die bisherigen Programmdateien, spielt die neuen ein (Ihre `.env`, `data/`, `certs/` usw. bleiben unberührt), entfernt veraltete Dateien, baut, startet, prüft – und fragt zum Schluss, ob die ZIP-Datei gelöscht werden soll.

## 1.7.0

- **Handbuch** auf Deutsch und Englisch – für Prüfer (Benutzung, Bericht lesen, Meldungen) und Betrieb (Installation, Update, Netzwerksperre, Sicherung, Fehlersuche). In der Weboberfläche unter **Hilfe** (auch ohne Anmeldung erreichbar), als Datei unter `app/docs/`.
- Zertifikats-Upload lehnt Zertifikate ab, die nicht für Webserver ausgestellt sind (fehlender Verwendungszweck „Serverauthentifizierung“).

## 1.6.0

- **Reproduzierbarer Build:** Alle Python-Pakete sind exakt fixiert – inklusive aller Unterabhängigkeiten (`requirements.txt`, installiert ohne Nachauflösung, mit `pip check`). Python ist auf **3.13.16** fixiert; beim ersten Build legt `update.sh` das Basisimage zusätzlich auf seinen unveränderlichen Digest fest (`base-image.lock`). Zeitzonendaten kommen aus dem fixierten Paket statt aus apt.
- **`update.sh`:** Sicherung → Neubau → **Netzwerksperre setzen** → Start → Funktionsprüfung → **Gegenprobe ohne Internet** → alte Images aufräumen, in einem Schritt. Die Sperre wird zusätzlich als systemd-Dienst eingerichtet, der bei jedem Systemstart vor Docker läuft. Siehe [Update](#update).
- Weniger Fremdcode im Image: Uvicorn ohne Zusatzpakete (`uvloop`, `httptools`, `websockets`, `watchfiles`, `pyyaml`, `python-dotenv` entfallen).
- Seite **Verbindung**: Hinweis und Warnung zu Zwischenzertifikaten entfernt.
- Korrektur: Für einen Neubau muss die Netzwerksperre **nicht** abgeschaltet werden – Builds laufen nicht im Netz `samaudit-net`.

## 1.5.2 – Sicherheits- und Fehlerprüfung

- **Anmeldung:** Das geprüfte Konto muss eindeutig zum angemeldeten passen (eindeutige Suche plus Gegenprobe per LDAP „Who am I“). Bei mehrdeutigen Anmeldenamen wird abgewiesen.
- **Mehrere DCs:** Zeigt der Domänenname auf mehrere DCs, wird jedem DC einzeln vertraut (Eintrag „firma.local [IP]“ unter **Verbindung**). Vorher konnte ein Wechsel des antwortenden DCs fälschlich als „Zertifikat geändert“ gemeldet werden. Bestehende Einträge werden übernommen.
- **Netzwerksperre:** sperrt jetzt auch Verbindungen vom Container zu Diensten auf dem Docker-Host selbst (außer der Host ist DC).
- **HTTPS:** nur noch sichere Verschlüsselungsverfahren (TLS 1.2 mit Vorwärtsgeheimnis/AEAD, TLS 1.3); hochgeladene Zertifikate mit schwachen Schlüsseln (RSA < 2048 Bit) werden abgelehnt.
- **Datenschutz:** Gelöschte Berichte werden sofort auch physisch aus der Datenbankdatei entfernt; keine Seite landet mehr im Browser-Cache; Scan-Daten bleiben nach dem Scan nicht mehr im Arbeitsspeicher.
- **Fehler behoben:** Löschen eines laufenden Scans entfernte dessen Teilergebnisse; Löschfrist scheiterte bei sehr vielen alten Berichten; Weiterleitung nach Sprachwechsel ließ sich auf fremde Seiten umbiegen; Neuladen nach dem Zertifikats-Upload schickte das Formular erneut.

## 1.5.1

- **Zertifikat über die Weboberfläche hochladen:** unter **Verbindung** PFX-Datei oder Zertifikat + Schlüssel auswählen, Passwort eingeben, fertig – wird sofort aktiv, ohne Neustart. Mit Prüfung vor dem Übernehmen, Anzeige im Protokoll und „Entfernen“-Knopf.
- Weboberfläche nur noch mit TLS 1.2 oder neuer.

## 1.5.0

- **Eigenes HTTPS-Zertifikat ohne Reverse Proxy:** Datei(en) in den Ordner `certs` legen, `docker compose restart` – fertig. Erkannt werden PFX-Dateien (z. B. aus der Windows-CA) sowie Zertifikat + Schlüssel (PEM/DER, auch verschlüsselt); Zwischenzertifikate werden automatisch als Kette mitgesendet. Der Ordner `certs` ist jetzt standardmäßig eingebunden.
- Unter **Verbindung** zeigt SAMAUDIT das aktive Web-Zertifikat mit Aussteller, Ablaufdatum und Warnungen (abgelaufen, läuft bald ab, falscher Hostname).
- `LDAP_CA_FILE` kann jetzt einfach ein Dateiname im Ordner `certs` sein (z. B. `ca.pem`).

## 1.4.2

- **Anmeldeseite zeigt die Ziel-Domäne** direkt im Anmeldefeld – mit erkanntem Typ (Windows AD / Samba AD) und Domänencontroller.
- **Alte Bezeichnungen entfernt:** Nur noch die Gruppe `SAMAUDIT-Benutzer` darf sich anmelden (der frühere Gruppenname wird nicht mehr akzeptiert). Eine Datenbankdatei früherer Versionen wird beim Start automatisch in `samaudit.db` umbenannt, alle Berichte bleiben erhalten. Nach dem Update ist eine neue Anmeldung nötig; Sprache und Hell/Dunkel ggf. neu wählen.

## 1.4.1

- **Einstellungen in `.env`:** Alle Einstellungen stehen jetzt in der Datei `.env` statt in der docker-compose.yml. Die `.env` ist nicht im Paket enthalten und wird bei einem Update nie überschrieben – die docker-compose.yml kann einfach ersetzt werden. Eigene Compose-Ergänzungen (`dns`, `extra_hosts`, Zertifikate) gehören in `docker-compose.override.yml`.
- **Umstieg von 1.4.0:** einmalig `cp .env.example .env` und die bisher in der docker-compose.yml geänderten Werte (mindestens `DOMAIN_FQDN`) in die `.env` übertragen. Eigene `dns:`/`extra_hosts:`-Einträge in eine `docker-compose.override.yml` übernehmen (Vorlage: `docker-compose.override.example.yml`).
- Abmelde-Button neben dem Benutzernamen.

## 1.4.0

- **Container ohne Internet:** Firewall-Skript `samaudit-firewall.sh` sperrt dem Container auf dem Docker-Host jeden ausgehenden Verkehr außer zu den Domänencontrollern; zusätzlich weist SAMAUDIT selbst jede andere Verbindung ab (`EGRESS_GUARD`).
- **Datenschutz:** automatische Löschfristen für Berichte und Protokoll, öffentliche Datenschutzseite `/privacy`, begrenzte Container-Logs, Unterlagen für Verzeichnis von Verarbeitungstätigkeiten und Betriebsrat in [`DATENSCHUTZ.md`](DATENSCHUTZ.md).
- Eigenes Docker-Netz `samaudit-net` (Bridge `br-samaudit`, ohne IPv6).

## 1.3.2

- Neuer Name **SAMAUDIT** (passend zu SAMONBOARDING); Prüfer-Gruppe heißt jetzt `SAMAUDIT-Benutzer`
- Eigenes Regel-ID-Schema: `STL-xx` (veraltete Objekte), `PRV-xx` (privilegierte Konten), `TRS-xx` (Vertrauensstellungen), `ANM-xx` (Anomalien). Ältere Berichte werden automatisch zugeordnet.
- Open Source unter **GNU AGPL-3.0-or-later**, mit Sicherheitsrichtlinie (`SECURITY.md`) und Übersicht der Fremdlizenzen (`THIRD-PARTY-NOTICES.md`)

## 1.2.0

- **Keine Admin-Konten mehr:** Anmelden darf nur, wer in der Prüfer-Gruppe `SAMAUDIT-Benutzer` ist. Konten in Domänen-, Organisations- oder Schema-Admins, Administratoren, Operator-Gruppen, DnsAdmins usw. werden **immer abgewiesen** – auch wenn sie zusätzlich in der Prüfer-Gruppe sind. So wird nie ein Tier-0-Passwort in die Weboberfläche eingegeben.
- **Scan mit normalen Benutzerrechten:** Daten, die ein normales Konto nicht lesen darf (z. B. PSOs, auf RODCs zwischengespeicherte Passwörter), führen zu „nicht prüfbar“ statt zu einem falschen „bestanden“.
- **Windows AD / Samba AD werden automatisch erkannt** (`DOMAIN_TYPE=auto`); `DC_HOSTS` ist optional.

## 1.1.0

- Name **SAMAUDIT** mit Versionsnummer in Oberfläche, PDF und `/healthz`
- **LDAPS ohne CA-Import:** Das DC-Zertifikat wird automatisch vertraut und gemerkt (siehe unten)
- Zeitzone **Europe/Berlin** für alle Anzeigen, Berichte und Logs
- Webport **9400**
- Prüfkatalog von 61 auf **105 Prüfungen** erweitert: DNS, AD CS (ESC1–ESC9/15), GPO-Berechtigungen, Benutzerrechte und Überwachung auf DCs, Registry-Richtlinien (LLMNR, WDigest, WSUS, AlwaysInstallElevated …), Anmeldeskripte, AD-Sicherung, RODC, Shadow Credentials u. v. m.
- Neue Optik im Stil von SAMONBOARDING (dunkel als Standard, hell umschaltbar)
- Neue Seite „Verbindung“ mit den gemerkten DC-Zertifikaten
