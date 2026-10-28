# SAMAUDIT v1.9.8 – Sicherheitsprüfung für Active Directory

*English version: [README.en.md](README.en.md)* · **Handbuch:** [app/docs/handbuch.de.md](app/docs/handbuch.de.md) (auch in der Weboberfläche unter **Hilfe**)

Selbst gehostete Webanwendung, die eine Windows- oder Samba-AD-Domäne ausliest, **110 Sicherheitsprüfungen** durchführt und das Ergebnis als Risikowert (0–100), detaillierten Bericht mit Maßnahmen und PDF ausgibt – auf Deutsch oder Englisch.

> **Status: Beta – Hobbyprojekt, ohne Gewähr.** SAMAUDIT wurde für den eigenen Einsatz entwickelt und vor allem mit Testdaten geprüft; Ergebnisse können unvollständig oder falsch sein und ersetzen keine fachliche Prüfung. Rückmeldungen sind willkommen, Support oder Reaktionszeiten werden nicht zugesagt. Sicherheitslücken bitte vertraulich melden (siehe [SECURITY.md](SECURITY.md)).

## Neu in 1.9.8

- **Docker-Compose-Vorlage:** `docker-compose.example.yml` startet SAMAUDIT mit denselben Sicherheitseinstellungen wie `update.sh` – z. B. als Stack in Dockhand oder Portainer oder mit `docker compose up -d`. Siehe [Mit Docker Compose oder Dockhand](#mit-docker-compose-oder-dockhand). Die Vorlage liegt auch im Image (`/app/dist/`) und wird von `update.sh --pull` aktuell gehalten.

## Neu in 1.9.7 – feste Versionen und wöchentliche Sicherheitsupdates

- **Reproduzierbarer Bau:** Statt „immer die neueste Version“ ist jetzt alles fest: das Basisimage mit Version **und** Digest (`python:3.13.17-slim-trixie@sha256:…`), die Debian-Pakete über einen festen Stand von snapshot.debian.org und alle Python-Pakete samt Unterabhängigkeiten mit exakter Version und Prüfsummen (`requirements.txt`, erzeugt aus `requirements.in`). Gleicher Quellstand ergibt gleiches Image. Die Debian-Paketliste steht in `locks/os-packages.txt` und wird bei jedem Bau verglichen. `tools/update-locks.sh` ermittelt die Versionen neu.
- **Wöchentliches Sicherheitsupdate auf GitHub** (montags früh, auch von Hand startbar): aktualisiert nur innerhalb des Unterbaus, baut ohne Cache, testet im Image, prüft mit Trivy und veröffentlicht nur bei Erfolg – als `latest` und `<Version>-s<n>` (z. B. `1.9.7-s1`). Die geänderten Pakete stehen in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md). Siehe [Sicherheitsupdates und Versionen](#sicherheitsupdates-und-versionen).
- **Weniger im Image:** pip und apt werden nach dem Bau entfernt – sie werden zur Laufzeit nicht gebraucht.
- **Täglicher Scan** des veröffentlichten Images und **Unterbau-Warnung** (Supportende von Python und Debian laut endoflife.date).
- **Abgesicherte GitHub-Abläufe:** Actions auf Commit-Hashes fixiert, je Job nur die nötigen Rechte, keine gespeicherten Git-Zugangsdaten, Veröffentlichung nur von `main`, nie zwei gleichzeitig, veröffentlichte Versionen werden nie überschrieben, `latest` nur für die höchste Version. Selbsttests dafür in `tests/test_pipeline.py`.
- Weboberfläche, PDF und `/healthz` (Feld `image`) zeigen die Image-Version, z. B. `1.9.7-s2`. Die Issues des alten Montagslaufs entfallen; einen roten Lauf meldet GitHub per E-Mail.

## Neu in 1.9.6

- **Alles im Image bleibt aktuell:** Neben Debian und Python werden jetzt auch alle Python-Pakete (inkl. Unterabhängigkeiten) bei jedem Bau in der neuesten Version installiert – auch beim wöchentlichen Neubau. `requirements.txt` enthält nur noch Mindestversionen. Der Rauchtest läuft jetzt im fertigen Image, also mit genau den Paketversionen, die veröffentlicht würden; zusammen mit dem Trivy-Scan entscheidet er, ob `latest` erneuert wird. Die Versionen jedes Images stehen in `/app/package-versions.txt` und in der Zusammenfassung des GitHub-Laufs.
- **Unterbau anheben:** Nur der Wechsel auf die nächste Python-Hauptversion bleibt ein bewusster Schritt. Ab Mai 2029 erinnert der wöchentliche Lauf per Issue daran, dass Python 3.13 am 31.10.2029 ausläuft.
- `update.sh` holt bei jedem lokalen Bau das aktuelle Basisimage; `--lock` und `--refresh-base` werden nicht mehr gebraucht.

## Neu in 1.9.5

- **Python wird mit aktualisiert:** Das Image baut auf `python:3.13-slim` statt fest auf 3.13.16 auf. Der wöchentliche Neubau nimmt damit automatisch die neueste Python-3.13-Version mit (derzeit 3.13.17) – Fehler- und Sicherheitskorrekturen von Python selbst, kein Sprung auf 3.14. Wie bisher wird jeder Neubau getestet und mit Trivy geprüft, bevor er als `latest` erscheint.

## Neu in 1.9.4

- **Sicherheitsupdates im Image, jede Woche:** Beim Bau werden jetzt alle verfügbaren Debian-Sicherheitsupdates des Basisimages eingespielt. GitHub baut `main` jeden Montag neu, testet, prüft mit Trivy und veröffentlicht nur bei Erfolg als `latest` – so bekommt das Image laufend Sicherheitsupdates, auch ohne Änderungen am Programm. Schlägt Test oder Scan fehl, bleibt `latest` unverändert und ein GitHub-Issue nennt den Grund (z. B. ein Python-Paket, das eine neue Version braucht; das wird dann gezielt aktualisiert).

## Neu in 1.9.3

- **Schwachstellen-Scan mit Trivy:** Jedes Image wird vor der Veröffentlichung gescannt. Kritische oder hohe Schwachstellen, für die es bereits eine Korrektur gibt, stoppen die Veröffentlichung – `latest` bleibt dann auf dem letzten sauberen Stand. Alles andere (z. B. Schwachstellen ohne verfügbare Korrektur) steht im Bericht des Laufs (Zusammenfassung und Artefakt `trivy-report`). Bewusst akzeptierte Ausnahmen gehören mit Begründung in `.trivyignore`.
- **Wöchentlicher Nachscan:** Montags wird das veröffentlichte `latest` erneut geprüft, denn Schwachstellen werden oft erst nach dem Bau bekannt. Dazu wird `main` jeden Montag automatisch neu gebaut – mit dem aktuellen Basisimage (Debian-Sicherheitsupdates) –, getestet und mit Trivy geprüft; nur wenn alles grün ist, wird das Ergebnis als `latest` veröffentlicht (die Versionsnummer bleibt). Andernfalls bleibt `latest` unverändert, und ein GitHub-Issue „Wöchentlicher Neubau …“ nennt den Grund (z. B. ein Python-Paket, das eine neue Version braucht) und erwähnt den Repository-Besitzer. Der nächste erfolgreiche Neubau schließt das Issue.
- Trivy wird als feste Version mit geprüfter Prüfsumme geladen, nicht über die Trivy-GitHub-Action, deren Versions-Tags im März 2026 kompromittiert waren (CVE-2026-33634).

## Neu in 1.9.2 – Code-Audit

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

## Neu in 1.9.1

- **Neuigkeiten in der App:** Unten links unter **Neuigkeiten** steht, was sich je Version geändert hat – gekennzeichnet als Funktion, Sicherheit, Fehlerbehebung oder Hinweis (z. B. zur RC4-Abschaltung). Neue Einträge zeigt ein kleiner Punkt an (orange bei Sicherheit) sowie einmalig eine schmale Zeile auf der Übersicht, die sich ausblenden lässt. Die Einträge kommen mit dem Update (`app/docs/news.json`), es wird nichts aus dem Internet geladen; nur ein Cookie merkt sich die zuletzt gesehene Version.

## Neu in 1.9.0

- **5 neue Prüfungen (jetzt 110)** zu Neuerungen aus 2025/2026:
  - **STL-21 Kerberos-RC4:** Dienstkonten ohne AES-Schlüssel und auf RC4 festgelegte Konten – sie fallen mit der RC4-Abschaltung von Microsoft (CVE-2026-20833, seit April/Juli 2026) aus.
  - **STL-22 Schwache Zertifikatszuordnung:** `altSecurityIdentities` mit Antragsteller, Aussteller+Antragsteller oder E-Mail (seit September 2025 voll erzwungen, KB5014754).
  - **PRV-36 ESC17:** Zertifikatvorlagen, mit denen normale Konten ein Serverzertifikat für beliebige Namen erhalten (z. B. WSUS über HTTPS übernehmen; TROOPERS 2026).
  - **PRV-37 dMSA / „BadSuccessor“:** Wer auf DCs mit Windows Server 2025 delegierte Dienstkonten anlegen darf und welche dMSAs auf privilegierte Konten verweisen.
  - **ANM-44 UPN/SPN-Missbrauch („KerberLoss“, „ResetNightmare“, 2026):** unsichtbare Unicode-Zeichen in UPN/SPN, UPNs gleich dem Anmeldenamen eines anderen Kontos, doppelte Namen, abgeschaltete Eindeutigkeitsprüfung.
- Zusätzlich gelesen werden `altSecurityIdentities`, das Erstellungsdatum der Gruppen sowie OUs und dMSAs (nur wenn das Schema Windows Server 2025 kennt).

## Neu in 1.8.1

- **Windows-Zeilenenden werden repariert:** Wurde `update.sh` über Windows kopiert oder bearbeitet (CRLF), brach `sh update.sh` mit „Syntax error: "(" unexpected“ ab. Das Skript wandelt sich jetzt selbst (und `entrypoint.sh`, `Dockerfile`, Paketlisten) automatisch um; `.gitattributes` sorgt dafür, dass Git die Dateien auch unter Windows mit LF auscheckt.
- **Lizenz:** `LICENSE` enthält den vollständigen Text der GNU AGPL v3, der Copyright-Hinweis steht in `NOTICE`; beide liegen auch im Container-Image.

## Neu in 1.8.0

- **Bereit für GitHub:** Das Container-Image wird per GitHub Actions gebaut und unter `ghcr.io/soleil0815/samaudit` veröffentlicht (amd64 + arm64, mit SBOM). Siehe [GitHub: Repository und Container-Image](#github-repository-und-container-image).
- **`sh update.sh --pull`:** holt das fertige Image von GitHub statt lokal zu bauen – mit Sicherung, Funktionsprüfung und automatischem Rückfall wie bisher. `update.sh` und `.env.example` liegen im Image und werden dabei mit aktualisiert. Klassisch per ZIP oder lokalem Build geht weiterhin.
- Dockhand-Label entfernt.

## Neu in 1.7.5

- **Installationsdateien auf Englisch:** `update.sh` (alle Meldungen und Rückfragen, Antwort mit `y`/`n` – `j` geht weiterhin), `.env.example`, `Dockerfile`, `entrypoint.sh`, `requirements.*`, `certs/README.txt`. Weboberfläche, Berichte und Handbuch bleiben zweisprachig.
- Sicherungen der Programmdateien heißen jetzt `backups/program-*.tgz`.

## Neu in 1.7.4

- **Host-Firewall entfernt:** `samaudit-firewall.sh` und der systemd-Dienst `samaudit-firewall` entfallen; `update.sh` setzt keine iptables-Regeln mehr und braucht dafür kein root/sudo. Beim ersten Update entfernt es die Regeln und den Dienst früherer Versionen automatisch. Die programminterne Sperre (`EGRESS_GUARD`) bleibt: SAMAUDIT selbst verbindet sich weiterhin nur zu den Domänencontrollern.

## Neu in 1.7.3

- **Paketname in Kleinbuchstaben:** `samaudit-v1.7.3.zip` mit dem Ordner `samaudit/` – Update mit `sh update.sh samaudit-*.zip`.
- **Sicherer Wechsel beim Update:** Der bisherige Container wird erst entfernt, wenn der neue läuft und geprüft ist. Startet der neue nicht oder wird er nicht „healthy“, läuft automatisch wieder die bisherige Version.
- `.env` darf Windows-Zeilenenden (CRLF) und BOM enthalten (z. B. nach Bearbeitung mit WinSCP/Notepad); Kommentare hinter Werten werden überall korrekt ignoriert.

## Neu in 1.7.2

- **Docker Compose wird nicht mehr benötigt** – nur noch Docker. `update.sh` baut und startet den Container selbst (mit denselben Sicherheitseinstellungen wie bisher). `docker-compose.yml` und `docker-compose.override.example.yml` entfallen; ein bestehender, mit Compose gestarteter Container wird beim Update einfach ersetzt.
- Nach Änderungen an der `.env`: `sh update.sh --restart` (ohne Neubau).
- DNS-Server und feste DC-Namen bei Bedarf über `DOCKER_DNS` und `DOCKER_EXTRA_HOSTS` in der `.env`.

## Neu in 1.7.1

- **Update in einem Befehl:** ZIP-Datei in den SAMAUDIT-Ordner legen und `sh update.sh samaudit-*.zip` ausführen. Das Skript zeigt installierte und neue Version, fragt nach, sichert die bisherigen Programmdateien, spielt die neuen ein (Ihre `.env`, `data/`, `certs/` usw. bleiben unberührt), entfernt veraltete Dateien, baut, startet, prüft – und fragt zum Schluss, ob die ZIP-Datei gelöscht werden soll.

## Neu in 1.7.0

- **Handbuch** auf Deutsch und Englisch – für Prüfer (Benutzung, Bericht lesen, Meldungen) und Betrieb (Installation, Update, Netzwerksperre, Sicherung, Fehlersuche). In der Weboberfläche unter **Hilfe** (auch ohne Anmeldung erreichbar), als Datei unter `app/docs/`.
- Zertifikats-Upload lehnt Zertifikate ab, die nicht für Webserver ausgestellt sind (fehlender Verwendungszweck „Serverauthentifizierung“).

## Neu in 1.6.0

- **Reproduzierbarer Build:** Alle Python-Pakete sind exakt fixiert – inklusive aller Unterabhängigkeiten (`requirements.txt`, installiert ohne Nachauflösung, mit `pip check`). Python ist auf **3.13.16** fixiert; beim ersten Build legt `update.sh` das Basisimage zusätzlich auf seinen unveränderlichen Digest fest (`base-image.lock`). Zeitzonendaten kommen aus dem fixierten Paket statt aus apt.
- **`update.sh`:** Sicherung → Neubau → **Netzwerksperre setzen** → Start → Funktionsprüfung → **Gegenprobe ohne Internet** → alte Images aufräumen, in einem Schritt. Die Sperre wird zusätzlich als systemd-Dienst eingerichtet, der bei jedem Systemstart vor Docker läuft. Siehe [Update](#update).
- Weniger Fremdcode im Image: Uvicorn ohne Zusatzpakete (`uvloop`, `httptools`, `websockets`, `watchfiles`, `pyyaml`, `python-dotenv` entfallen).
- Seite **Verbindung**: Hinweis und Warnung zu Zwischenzertifikaten entfernt.
- Korrektur: Für einen Neubau muss die Netzwerksperre **nicht** abgeschaltet werden – Builds laufen nicht im Netz `samaudit-net`.

## Neu in 1.5.2 – Sicherheits- und Fehlerprüfung

- **Anmeldung:** Das geprüfte Konto muss eindeutig zum angemeldeten passen (eindeutige Suche plus Gegenprobe per LDAP „Who am I“). Bei mehrdeutigen Anmeldenamen wird abgewiesen.
- **Mehrere DCs:** Zeigt der Domänenname auf mehrere DCs, wird jedem DC einzeln vertraut (Eintrag „firma.local [IP]“ unter **Verbindung**). Vorher konnte ein Wechsel des antwortenden DCs fälschlich als „Zertifikat geändert“ gemeldet werden. Bestehende Einträge werden übernommen.
- **Netzwerksperre:** sperrt jetzt auch Verbindungen vom Container zu Diensten auf dem Docker-Host selbst (außer der Host ist DC).
- **HTTPS:** nur noch sichere Verschlüsselungsverfahren (TLS 1.2 mit Vorwärtsgeheimnis/AEAD, TLS 1.3); hochgeladene Zertifikate mit schwachen Schlüsseln (RSA < 2048 Bit) werden abgelehnt.
- **Datenschutz:** Gelöschte Berichte werden sofort auch physisch aus der Datenbankdatei entfernt; keine Seite landet mehr im Browser-Cache; Scan-Daten bleiben nach dem Scan nicht mehr im Arbeitsspeicher.
- **Fehler behoben:** Löschen eines laufenden Scans entfernte dessen Teilergebnisse; Löschfrist scheiterte bei sehr vielen alten Berichten; Weiterleitung nach Sprachwechsel ließ sich auf fremde Seiten umbiegen; Neuladen nach dem Zertifikats-Upload schickte das Formular erneut.

## Neu in 1.5.1

- **Zertifikat über die Weboberfläche hochladen:** unter **Verbindung** PFX-Datei oder Zertifikat + Schlüssel auswählen, Passwort eingeben, fertig – wird sofort aktiv, ohne Neustart. Mit Prüfung vor dem Übernehmen, Anzeige im Protokoll und „Entfernen“-Knopf.
- Weboberfläche nur noch mit TLS 1.2 oder neuer.

## Neu in 1.5.0

- **Eigenes HTTPS-Zertifikat ohne Reverse Proxy:** Datei(en) in den Ordner `certs` legen, `docker compose restart` – fertig. Erkannt werden PFX-Dateien (z. B. aus der Windows-CA) sowie Zertifikat + Schlüssel (PEM/DER, auch verschlüsselt); Zwischenzertifikate werden automatisch als Kette mitgesendet. Der Ordner `certs` ist jetzt standardmäßig eingebunden.
- Unter **Verbindung** zeigt SAMAUDIT das aktive Web-Zertifikat mit Aussteller, Ablaufdatum und Warnungen (abgelaufen, läuft bald ab, falscher Hostname).
- `LDAP_CA_FILE` kann jetzt einfach ein Dateiname im Ordner `certs` sein (z. B. `ca.pem`).

## Neu in 1.4.2

- **Anmeldeseite zeigt die Ziel-Domäne** direkt im Anmeldefeld – mit erkanntem Typ (Windows AD / Samba AD) und Domänencontroller.
- **Alte Bezeichnungen entfernt:** Nur noch die Gruppe `SAMAUDIT-Benutzer` darf sich anmelden (der frühere Gruppenname wird nicht mehr akzeptiert). Eine Datenbankdatei früherer Versionen wird beim Start automatisch in `samaudit.db` umbenannt, alle Berichte bleiben erhalten. Nach dem Update ist eine neue Anmeldung nötig; Sprache und Hell/Dunkel ggf. neu wählen.

## Neu in 1.4.1

- **Einstellungen in `.env`:** Alle Einstellungen stehen jetzt in der Datei `.env` statt in der docker-compose.yml. Die `.env` ist nicht im Paket enthalten und wird bei einem Update nie überschrieben – die docker-compose.yml kann einfach ersetzt werden. Eigene Compose-Ergänzungen (`dns`, `extra_hosts`, Zertifikate) gehören in `docker-compose.override.yml`.
- **Umstieg von 1.4.0:** einmalig `cp .env.example .env` und die bisher in der docker-compose.yml geänderten Werte (mindestens `DOMAIN_FQDN`) in die `.env` übertragen. Eigene `dns:`/`extra_hosts:`-Einträge in eine `docker-compose.override.yml` übernehmen (Vorlage: `docker-compose.override.example.yml`).
- Abmelde-Button neben dem Benutzernamen.

## Neu in 1.4.0

- **Container ohne Internet:** Firewall-Skript `samaudit-firewall.sh` sperrt dem Container auf dem Docker-Host jeden ausgehenden Verkehr außer zu den Domänencontrollern; zusätzlich weist SAMAUDIT selbst jede andere Verbindung ab (`EGRESS_GUARD`).
- **Datenschutz:** automatische Löschfristen für Berichte und Protokoll, öffentliche Datenschutzseite `/privacy`, begrenzte Container-Logs, Unterlagen für Verzeichnis von Verarbeitungstätigkeiten und Betriebsrat in [`DATENSCHUTZ.md`](DATENSCHUTZ.md).
- Eigenes Docker-Netz `samaudit-net` (Bridge `br-samaudit`, ohne IPv6).

## Neu in 1.3.2

- Neuer Name **SAMAUDIT** (passend zu SAMONBOARDING); Prüfer-Gruppe heißt jetzt `SAMAUDIT-Benutzer`
- Eigenes Regel-ID-Schema: `STL-xx` (veraltete Objekte), `PRV-xx` (privilegierte Konten), `TRS-xx` (Vertrauensstellungen), `ANM-xx` (Anomalien). Ältere Berichte werden automatisch zugeordnet.
- Open Source unter **GNU AGPL-3.0-or-later**, mit Sicherheitsrichtlinie (`SECURITY.md`) und Übersicht der Fremdlizenzen (`THIRD-PARTY-NOTICES.md`)

## Neu in 1.2.0

- **Keine Admin-Konten mehr:** Anmelden darf nur, wer in der Prüfer-Gruppe `SAMAUDIT-Benutzer` ist. Konten in Domänen-, Organisations- oder Schema-Admins, Administratoren, Operator-Gruppen, DnsAdmins usw. werden **immer abgewiesen** – auch wenn sie zusätzlich in der Prüfer-Gruppe sind. So wird nie ein Tier-0-Passwort in die Weboberfläche eingegeben.
- **Scan mit normalen Benutzerrechten:** Daten, die ein normales Konto nicht lesen darf (z. B. PSOs, auf RODCs zwischengespeicherte Passwörter), führen zu „nicht prüfbar“ statt zu einem falschen „bestanden“.
- **Windows AD / Samba AD werden automatisch erkannt** (`DOMAIN_TYPE=auto`); `DC_HOSTS` ist optional.

## Neu in 1.1.0

- Name **SAMAUDIT** mit Versionsnummer in Oberfläche, PDF und `/healthz`
- **LDAPS ohne CA-Import:** Das DC-Zertifikat wird automatisch vertraut und gemerkt (siehe unten)
- Zeitzone **Europe/Berlin** für alle Anzeigen, Berichte und Logs
- Webport **9400**
- Prüfkatalog von 61 auf **105 Prüfungen** erweitert: DNS, AD CS (ESC1–ESC9/15), GPO-Berechtigungen, Benutzerrechte und Überwachung auf DCs, Registry-Richtlinien (LLMNR, WDigest, WSUS, AlwaysInstallElevated …), Anmeldeskripte, AD-Sicherung, RODC, Shadow Credentials u. v. m.
- Neue Optik im Stil von SAMONBOARDING (dunkel als Standard, hell umschaltbar)
- Neue Seite „Verbindung“ mit den gemerkten DC-Zertifikaten

## Kurzüberblick

| | |
|---|---|
| **Anmeldung** | Mit dem eigenen **normalen** Domänenkonto direkt gegen den Domänencontroller (LDAPS). **Kein Dienstkonto, kein Admin-Konto.** |
| **Zugriff** | Nur Mitglieder der Prüfer-Gruppe (`ALLOWED_GROUPS`, Standard `SAMAUDIT-Benutzer`). Privilegierte Konten werden immer abgewiesen. Geprüft über die effektiven Gruppen (`tokenGroups`, inkl. Verschachtelung). |
| **Scan** | Manuell per Knopfdruck mit den Rechten des angemeldeten Prüfers. Vor jedem Scan wird die Berechtigung erneut geprüft. |
| **Domänentyp** | Windows AD oder Samba AD wird automatisch erkannt. |
| **Bewertung** | Vier Bereiche (Veraltete Objekte, Privilegierte Konten, Vertrauensstellungen, Anomalien), je 0–100 Punkte. Gesamtwert = höchster Bereichswert. |
| **Bericht** | Befunde mit Erklärung, Maßnahme, PowerShell-Beispiel, betroffenen Objekten und Quellen. Vergleich mit dem vorherigen Scan (neu / behoben). |
| **Export** | PDF mit Deckblatt, Zusammenfassung, Domänenüberblick, allen Befunden und Anhang. |
| **Speicher** | SQLite (WAL-Modus) im Ordner `data` im SAMAUDIT-Ordner. |

## Schnellstart

**Variante A – fertiges Image von GitHub (empfohlen, kein Bauen auf dem Server):**

```bash
mkdir -p /opt/samaudit && cd /opt/samaudit
docker login ghcr.io          # nur nötig, solange Repository/Paket privat sind (siehe unten)
IMG=ghcr.io/soleil0815/samaudit:latest
docker run --rm --entrypoint cat $IMG /app/dist/update.sh   > update.sh
docker run --rm --entrypoint cat $IMG /app/dist/.env.example > .env.example
cp .env.example .env && nano .env      # DOMAIN_FQDN usw. eintragen
sh update.sh --pull
```

Spätere Updates: `sh update.sh --pull` (holt das neueste Image, aktualisiert dabei auch `update.sh` selbst).

**Variante B – selbst bauen aus dem Quellcode** (Repository klonen oder ZIP entpacken):

```bash
# 1. Prüfer-Gruppe anlegen und normale (Nicht-Admin-)Konten aufnehmen – siehe unten
# 2. Einstellungen anlegen und DOMAIN_FQDN eintragen (alles andere ist optional)
cp .env.example .env
nano .env
# 3. Bauen und starten
./update.sh
# 4. Im Browser öffnen
https://<docker-host>:9400
```

**Variante C – mit Docker Compose oder Dockhand:** siehe [Mit Docker Compose oder Dockhand](#mit-docker-compose-oder-dockhand).

Beim ersten Start wird ein selbstsigniertes HTTPS-Zertifikat für die Weboberfläche erzeugt (einmalige Browserwarnung). Eigenes Zertifikat: siehe [Eigenes HTTPS-Zertifikat](#eigenes-https-zertifikat).

**Ausprobieren ohne Domäne:** In der `.env` `DEMO_MODE=true` setzen, Anmeldung mit `demo` / `demo`. Für den Echtbetrieb wieder `false`.

### Mit Docker Compose oder Dockhand

`docker-compose.example.yml` enthält dieselben Einstellungen, mit denen `update.sh` den Container startet (nur lesbares Dateisystem, keine zusätzlichen Rechte, eigenes Netz `samaudit-net`, Log-Begrenzung).

```bash
cd /opt/samaudit                      # Ordner mit .env, data/ und certs/
docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.example.yml > docker-compose.yml
docker compose up -d                  # Update: docker compose pull && docker compose up -d
```

**Dockhand/Portainer:** Inhalt der Datei als neuen Stack einfügen und die Pfade `./data`, `./certs` und `.env` durch den SAMAUDIT-Ordner ersetzen (z. B. `/opt/samaudit/data`). Mit `latest` kommen neue Versionen und die wöchentlichen Sicherheitsupdates automatisch, sobald das Werkzeug das Image neu zieht.

Hinweise:
- **Nur ein Weg je Container:** entweder `update.sh` oder Compose. Beim Umstieg von `update.sh` einmalig `docker rm -f samaudit && docker network rm samaudit-net`. Die Daten in `data/` bleiben erhalten.
- `DOCKER_DNS` und `DOCKER_EXTRA_HOSTS` aus der `.env` wirken nur mit `update.sh`. Mit Compose die Einträge `dns:` bzw. `extra_hosts:` in der Datei verwenden (Beispiel ist enthalten).
- Ändert man `PORT` in der `.env`, nutzt Compose ihn auch für die Portfreigabe, sofern die `.env` neben der Compose-Datei liegt; sonst die Zeile `ports:` anpassen.
- Sicherungen legt `update.sh` an; bei Compose den Ordner `data/` selbst sichern (siehe [Datenordner und Sicherung](#betrieb)).

**Wo steht was?**

| Datei | Gehört | Bei Updates |
|---|---|---|
| `.env` | Ihnen – alle Einstellungen | bleibt erhalten (nicht im Paket) |
| `certs/` | Ihnen – eigene Zertifikate | bleibt erhalten (nur `README.txt` im Paket) |
| `data/` | Ihnen – Datenbank, Zertifikate | bleibt erhalten |
| `.env.example`, `update.sh`, Programmdateien | SAMAUDIT | werden ersetzt – nicht bearbeiten |

Nach Änderungen an der `.env` reicht `sh update.sh --restart` (kein Neubau nötig).

## LDAPS: automatisches Vertrauen

Standard ist `LDAP_CERT_MODE=auto` – es muss **kein CA-Zertifikat importiert** werden:

1. Beim ersten Kontakt zu einem DC liest SAMAUDIT dessen Zertifikatskette und merkt sich den obersten nachweisbaren Aussteller (meist Ihre Unternehmens-CA, bei Samba das selbst erzeugte Zertifikat).
2. Bei jeder weiteren Verbindung muss die Kette wieder zu diesem gemerkten Zertifikat führen – **bevor** das Passwort gesendet wird.
3. Erneuert die CA das DC-Zertifikat, bleibt das Vertrauen bestehen. Präsentiert jemand ein Zertifikat einer fremden CA (Man-in-the-Middle), wird die Anmeldung abgebrochen und im Protokoll vermerkt.

Zeigt ein Name auf mehrere DCs (z. B. der Domänenname ohne `DC_HOSTS`), wird jedem DC einzeln vertraut; die Einträge heißen dann „firma.local [10.0.0.10]“. Ein neu hinzugekommener DC wird beim ersten Kontakt gemerkt und im Protokoll vermerkt. Wer das nicht möchte, trägt die DCs fest in `DC_HOSTS` ein oder nutzt `LDAP_CERT_MODE=verify`.

Die gemerkten Zertifikate stehen unter **Verbindung**. Nach einem gewollten CA-Wechsel dort zurücksetzen oder per Kommandozeile:

```bash
docker exec samaudit python -m app.pins list
docker exec samaudit python -m app.pins reset                  # alle
docker exec samaudit python -m app.pins reset dc01.firma.local # einzelner DC
```

Weitere Modi: `trust` (immer vertrauen, keine Prüfung – nur Testlabor) und `verify` (klassische Prüfung gegen `LDAP_CA_FILE`, z. B. `ca.pem` im Ordner `certs`). Unverschlüsselte LDAP-Binds sind gesperrt.

## Eigenes HTTPS-Zertifikat

Kein Reverse Proxy nötig – SAMAUDIT liefert HTTPS selbst aus. Am einfachsten über die Weboberfläche:

1. **Verbindung** öffnen → Abschnitt **HTTPS-Zertifikat der Weboberfläche**.
2. Unter **Eigenes Zertifikat hochladen** die Datei(en) auswählen:
   - eine **PFX-Datei** (z. B. Export aus der Windows-Zertifizierungsstelle) + Passwort, **oder**
   - **Zertifikat + privaten Schlüssel** (PEM oder DER; ein verschlüsselter Schlüssel braucht das Passwort).
3. **Hochladen und aktivieren** – das Zertifikat ist sofort aktiv, ohne Neustart. Ggf. die Seite neu laden.

SAMAUDIT prüft vor dem Übernehmen, ob Zertifikat und Schlüssel zusammenpassen, ob das Zertifikat abgelaufen ist und ob es sich als Server-Zertifikat laden lässt; bei Problemen bleibt das bisherige aktiv und die Seite nennt den Grund. Angezeigt werden Aussteller, Ablaufdatum, Fingerabdruck und Warnungen (läuft bald ab, `PUBLIC_HOSTNAME` fehlt im Zertifikat). Mit **Hochgeladenes Zertifikat entfernen** geht es zurück zum vorherigen. Hochladen und Entfernen stehen im Protokoll.

- Das Zertifikat muss den Namen enthalten, unter dem SAMAUDIT aufgerufen wird; setzen Sie `PUBLIC_HOSTNAME` in der `.env` auf diesen Namen.
- Gespeichert wird es als `data/tls/custom/` (Kette + Schlüssel ohne Passwort, nur für den Programmbenutzer lesbar) – wie das selbstsignierte Zertifikat. Das Passwort wird nicht gespeichert. Die Sicherung des Ordners `data` enthält damit auch den Schlüssel.
- Verlängerung: einfach das neue Zertifikat hochladen.

**Alternative ohne Weboberfläche:** Dateien in den Ordner `certs` im SAMAUDIT-Ordner legen (bei PFX `TLS_PFX_PASSWORD` bzw. bei verschlüsseltem Schlüssel `TLS_KEY_PASSWORD` in der `.env`) und `sh update.sh --restart`. Ein hochgeladenes Zertifikat hat Vorrang. Details: `certs/README.txt`.

## Voraussetzungen im Netzwerk

| Vom Container zum DC | Zweck |
|---|---|
| TCP 636 (LDAPS) – oder 389 mit StartTLS | Anmeldung und Datenabfrage |
| TCP 445 (SMB) | SYSVOL/NETLOGON: GPOs, GPP-Passwörter, Skripte, Überwachungs- und Sicherheitsrichtlinien. Abschaltbar mit `SMB_CHECKS=false` (diese Prüfungen erscheinen dann als „nicht prüfbar“). |
| DNS | Der Container muss die DC-Namen auflösen können (`DOCKER_DNS` / `DOCKER_EXTRA_HOSTS` in der `.env`). |

## Ausgehende Verbindungen

SAMAUDIT verbindet sich nur zu den Domänencontrollern. Die programminterne Sperre (`EGRESS_GUARD=true`, Standard) lässt nur Verbindungen zu den DC-Adressen auf den LDAP-/SMB-Ports zu; jeder andere Versuch wird abgewiesen und im Protokoll als „Ausgehende Verbindung blockiert“ vermerkt. Weitere Ziele bei Bedarf mit `EGRESS_ALLOW` (IP, Netz oder Name, durch `;` getrennt). Wer den Container zusätzlich auf Netzwerkebene abschotten möchte, regelt das mit der eigenen Firewall (Docker-Netz `samaudit-net`, Bridge `br-samaudit`).

## Datenschutz (DSGVO)

SAMAUDIT überträgt keine Daten an Dritte, lädt nichts aus dem Internet, setzt nur technisch notwendige Cookies und löscht Berichte und Protokoll automatisch (`REPORT_RETENTION_DAYS`, `AUDIT_RETENTION_DAYS`). Die Seite **„Datenschutz“** (`/privacy`, auch ohne Anmeldung erreichbar) informiert Prüfer und Beschäftigte; die zuständige Stelle tragen Sie in `PRIVACY_CONTACT` ein.

Die Verantwortung für den datenschutzkonformen Einsatz bleibt beim Betreiber. [`DATENSCHUTZ.md`](DATENSCHUTZ.md) enthält eine Vorlage für das Verzeichnis von Verarbeitungstätigkeiten, die technischen und organisatorischen Maßnahmen sowie eine Checkliste (Datenschutzbeauftragte/r, Betriebsrat, Löschfristen).

## Wer darf sich anmelden?

SAMAUDIT wird bewusst **nicht** mit Admin-Konten benutzt. Wer sich in eine Webanwendung mit einem Domänen-Admin-Konto anmeldet, gibt das wertvollste Passwort der Domäne auf einem System ein, das kein Domänencontroller ist (Verstoß gegen das Tier-Modell). Für die Prüfung reichen normale Leserechte.

**1. Prüfer-Gruppe anlegen** und die normalen Benutzerkonten der Personen aufnehmen, die Berichte sehen dürfen (z. B. das Alltagskonto des IT-Leiters – nicht dessen Admin-Konto).

Windows AD:
```powershell
New-ADGroup -Name "SAMAUDIT-Benutzer" -GroupScope Global -GroupCategory Security -Description "Darf SAMAUDIT benutzen"
Add-ADGroupMember -Identity "SAMAUDIT-Benutzer" -Members "m.mustermann"
```

Samba AD:
```bash
samba-tool group add "SAMAUDIT-Benutzer" --description="Darf SAMAUDIT benutzen"
samba-tool group addmembers "SAMAUDIT-Benutzer" m.mustermann
```

**2. Regeln bei der Anmeldung**

| Prüfung | Ergebnis |
|---|---|
| Konto ist in einer privilegierten Gruppe (auch verschachtelt): Domänen-, Organisations-, Schema-Admins, Administratoren, Konten-/Server-/Druck-/Sicherungs-Operatoren, Richtlinien-Ersteller-Besitzer, (Organisations-)Schlüsseladministratoren, DnsAdmins, Domänencontroller – oder ist das eingebaute Administrator-Konto | **abgewiesen** |
| Konto ist in `ALLOWED_GROUPS` | angemeldet |
| sonst | abgewiesen |

Die Gruppen werden über RIDs/SIDs erkannt, also sprachunabhängig. Mit `DENIED_GROUPS` lassen sich weitere Gruppen sperren (z. B. eigene Tier-0-Gruppen); die eingebauten Sperren lassen sich nicht abschalten.

Weitere Schutzmechanismen: Sperre nach 5 Fehlversuchen (pro Benutzer und IP), Sitzungs-Timeout 30 Minuten, CSRF-Schutz, Cookies `HttpOnly` / `Secure` / `SameSite=Strict`, Content-Security-Policy, Protokoll aller Anmeldungen (auch abgewiesener), Scans und Zertifikatsereignisse.

**Was passiert mit dem Passwort?** Es wird nach der Anmeldung verschlüsselt (Schlüssel nur im Arbeitsspeicher) für die Dauer der Sitzung gehalten, damit ein Scan mit Ihren Rechten laufen kann. Es wird nie in die Datenbank, auf die Festplatte oder in Logs geschrieben.

## Windows AD oder Samba AD – automatische Erkennung

Mit `DOMAIN_TYPE=auto` (Standard) liest SAMAUDIT beim Verbinden das rootDSE des DCs. Samba meldet sich dort mit `vendorName: Samba Team`; zusätzlich wird das Betriebssystem der DC-Objekte geprüft. Der erkannte Typ steht unter **Verbindung** und im Bericht und steuert, welche Windows-spezifischen Prüfungen ausgeführt werden. Mit `windows` oder `samba` lässt er sich bei Bedarf fest einstellen.

`DC_HOSTS` ist optional: Ohne Angabe wird der Domänenname verwendet, der in AD und Samba auf alle DCs auflöst. Bei **mehreren Samba-DCs** mit jeweils eigenem selbstsigniertem Zertifikat sollten Sie `DC_HOSTS` mit den einzelnen DC-Namen setzen, damit das LDAPS-Autovertrauen pro DC funktioniert.

## Prüfkatalog (110 Prüfungen)

Der vollständige Katalog mit Beschreibung und Punkten steht in der Anwendung unter **Prüfkatalog**.

**Veraltete Objekte (22):** inaktive Benutzer und Computer, „Passwort läuft nie ab“, PASSWD_NOTREQD, umkehrbare Verschlüsselung, DES (Flag und Verschlüsselungstypen), AS-REP-Roasting, Kerberoasting, Betriebssysteme ohne Support (inkl. Windows 10 seit 14.10.2025, Server 2016 ab 01/2027), SID-Verlauf, versteckte Mitgliedschaft über primäre Gruppe, userPassword-Attribute, LAPS-Abdeckung, verwaiste adminCount-Markierungen, nicht erneuerte Maschinenkennwörter, Replikationskonflikte (CNF), fehlende AD-Subnetze, Konten, die noch Kerberos-RC4 brauchen, schwache Zertifikatszuordnungen (altSecurityIdentities).

**Privilegierte Konten (37):** Anzahl Admins, Schema-/Organisations-Admins, Operator-Gruppen, Key Admins / GPO-Ersteller, allgemeine Gruppen (Jeder, Domänen-Benutzer …) in Admin-Gruppen, Admins mit SPN oder ohne Vorauthentifizierung, Delegierungsschutz / Protected Users, inaktive, deaktivierte und alte Admin-Konten, Shadow Credentials, DCSync-Rechte, Schreibrechte auf Domänenobjekt, AdminSDHolder, OU „Domain Controllers“ und kritischen GPOs, Besitzer der DC-Objekte, RODC-Kennwortreplikation, DnsAdmins, uneingeschränkte / eingeschränkte / ressourcenbasierte Delegierung, „Prä-Windows 2000“-Gruppe, Entra ID Seamless SSO, AD CS: ESC1, ESC2, ESC3, ESC4, ESC5, ESC8, ESC9, ESC15, ESC17, delegierte Dienstkonten (dMSA, „BadSuccessor“).

**Vertrauensstellungen (7):** SID-Filterung, TGT-Delegierung, inaktive/defekte Trusts, Downlevel-Trusts, fehlendes AES, fremde Konten in Admin-Gruppen, fehlende selektive Authentifizierung.

**Anomalien (44):** Passwortrichtlinie (Länge, Sperre, Komplexität, Chronik, Mindestalter, umkehrbar) und PSOs, krbtgt-Passwortalter (inkl. RODC-krbtgt), Gastkonto, MachineAccountQuota, AD-Papierkorb, Funktionsebene, DC-Betriebssysteme, Anzahl/Zustand/Ort der DCs, AD-Sicherung, Tombstone-Lebensdauer, SYSVOL-Replikation (FRS), dSHeuristics (anonymer Zugriff, AdminSDHolder-Ausnahmen), DNS (unsichere Updates, ADIDNS-Rechte), CA-Zertifikate (SHA-1/MD5, Schlüssellänge, Ablauf), GPP-Passwörter und Autologon, Passwörter in Anmeldeskripten, und auf Basis der Gruppenrichtlinien: LDAP-Signierung und Kanalbindung, NTLMv1/LM-Hashes, SMB-Signierung (Server und Client), Druckwarteschlange auf DCs, Überwachungsrichtlinie auf DCs, gefährliche Benutzerrechte auf DCs, ZeroLogon-Ausnahmen, RefusePasswordChange, Kerberos-Verschlüsselungstypen, WDigest, AlwaysInstallElevated, WSUS über HTTP, LLMNR, PowerShell-Protokollierung, LSA-Schutz; manipulierbare UPN/SPN (unsichtbare Zeichen, Namensgleichheit, Dubletten, Eindeutigkeitsprüfung).

Prüfungen, die in einer Umgebung nicht möglich sind (z. B. Windows-spezifische Punkte bei Samba oder SYSVOL ohne SMB-Zugang), erscheinen unter „Nicht prüfbar“ und zählen nicht in den Risikowert.

## Grenzen

- Der Scan läuft mit normalen Benutzerrechten. Einige wenige Daten sind dann nicht lesbar (Fine-Grained Password Policies, auf RODCs zwischengespeicherte Passwörter, vertrauliche Attribute wie `unixUserPassword`). Die betroffenen Prüfungen erscheinen als „nicht prüfbar“, nicht als „bestanden“.
- Der Bericht ist eine automatisierte Momentaufnahme und ersetzt keinen Penetrationstest.
- Einstellungen, die nur lokal in der Registry oder per RPC sichtbar sind, werden nicht live abgefragt. Signierung, NTLM-Stufe, Druckwarteschlange, Benutzerrechte und Überwachung werden aus den GPOs auf Domäne und OU „Domain Controllers“ abgeleitet; domänenweite Einstellungen (LLMNR, WSUS …) aus allen verknüpften GPOs.
- Die Prüfregeln, Texte und Bewertungen sind eigenständig erstellt und orientieren sich an öffentlich dokumentierten Angriffstechniken (MITRE ATT&CK, Microsoft-Empfehlungen, BSI, SpecterOps „Certified Pre-Owned“).

## Betrieb

```bash
docker logs -f samaudit                              # Logs
sh update.sh --restart                               # nach Änderungen an der .env
./update.sh                                          # nach Update neu bauen (siehe unten)
curl -k https://localhost:9400/healthz               # Version und Zustand
```

### Update

**Mit dem Image von GitHub:** `sh update.sh --pull` – holt `ghcr.io/soleil0815/samaudit:latest`, sichert vorher, startet die neue Version, prüft sie und fällt bei Problemen auf die bisherige zurück. Eine bestimmte Version: `sh update.sh --pull=1.9.8` oder ein Sicherheitsupdate davon, z. B. `--pull=1.9.8-s1`. Ist das Image schon aktuell, passiert nichts. Anderes Image (z. B. Fork): `SAMAUDIT_IMAGE=ghcr.io/<name>/<repo>` in der `.env`.

**Mit ZIP oder Quellcode (lokaler Build):**

ZIP-Datei der neuen Version in den SAMAUDIT-Ordner legen, dann:

```bash
sh update.sh samaudit-*.zip
```

Mit ZIP zeigt das Skript zuerst installierte und neue Version und fragt nach, sichert die bisherigen Programmdateien nach `backups/program-*.tgz`, spielt die neuen ein und entfernt veraltete Dateien (`.env`, `data/`, `certs/`, `backups/` und `base-image.lock` bleiben unberührt). Am Ende fragt es, ob die ZIP-Datei gelöscht werden soll. Ohne ZIP (`./update.sh`) wird nur neu gebaut und gestartet. Danach
1. legt eine **Sicherung** in `backups/` an (konsistente Kopie der Datenbank + Zertifikate; die letzten 5 bleiben),
2. **baut** das Image aus den festen Versionen des Quellstands (dieselben wie auf GitHub; neuere Sicherheitsupdates kommen mit dem Image von GitHub oder einem neuen ZIP),
3. **startet** den Container neu und wartet, bis er als „healthy“ gemeldet wird (sonst Abbruch mit Log-Auszug),
4. räumt **alte Images** auf (die vorige Version bleibt für einen Rückschritt).

| Aufruf | Wirkung |
|---|---|
| `./update.sh --no-backup` | ohne Sicherung |
| `./update.sh --no-cache` | komplett neu bauen |

Fehlt die `.env`, legt das Skript sie aus der Vorlage an und bittet um `DOMAIN_FQDN`. Schlägt der Build fehl, bleibt der laufende Container unverändert.

**Versionen:** Basisimage, Debian- und Python-Pakete sind fest vorgegeben; jede Woche erneuert GitHub sie innerhalb des Unterbaus – siehe [Sicherheitsupdates und Versionen](#sicherheitsupdates-und-versionen).

**Datenordner und Sicherung:** Alles, was SAMAUDIT speichert, liegt in `./data` im SAMAUDIT-Ordner:

| Datei | Inhalt |
|---|---|
| `samaudit.db` + `-wal`/`-shm` | Berichte, Protokoll, gemerkte DC-Zertifikate |
| `tls/cert.pem`, `tls/key.pem` | selbstsigniertes Zertifikat der Weboberfläche |
| `tls/custom/` | über die Weboberfläche hochgeladenes Zertifikat (Kette + Schlüssel) |

`update.sh` sichert automatisch. Manuell – für eine konsistente Sicherung den Container kurz anhalten:

```bash
docker stop samaudit
sudo tar czf samaudit-backup-$(date +%F).tgz data
docker start samaudit
```

Der Ordner gehört im laufenden Betrieb dem Programmbenutzer (UID 10001) und ist nur für ihn lesbar; zum Ansehen auf dem Host `sudo` verwenden.

Datenbank, Backups und PDF-Exporte enthalten Schwachstellen Ihrer Domäne – entsprechend vertraulich behandeln.

## Alle Einstellungen

Alle Werte werden in der `.env` gesetzt (Schreibweise `NAME=wert`, Vorlage mit Erklärungen: `.env.example`). Nicht gesetzte Werte nehmen den Standard.

| Variable | Standard | Beschreibung |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS-Name der Domäne (Pflicht) |
| `DOMAIN_TYPE` | `auto` | `auto` (erkennen), `windows` oder `samba` |
| `DOMAIN_NETBIOS` | automatisch | NetBIOS-Name |
| `DC_HOSTS` | `DOMAIN_FQDN` | DCs, mit `;` getrennt (der erste erreichbare wird genutzt) |
| `LDAP_SSL` / `LDAP_PORT` | `true` / `636` | LDAPS |
| `LDAP_STARTTLS` | `false` | StartTLS auf 389 statt LDAPS |
| `LDAP_CERT_MODE` | `auto` | `auto` (automatisch vertrauen und merken), `trust`, `verify` |
| `PIN_RESET_WEB` | `false` | gemerkte DC-Zertifikate in der Weboberfläche zurücksetzen erlauben (sonst nur `docker exec samaudit python -m app.pins reset`) |
| `LDAP_CA_FILE` | – | CA-Zertifikat (PEM) im Ordner `certs`, nur für `verify` |
| `LDAP_TIMEOUT` | `10` | Sekunden |
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | Prüfer-Gruppe(n): Name, DN, SID oder `RID:x` |
| `DENIED_GROUPS` | – | zusätzlich gesperrte Gruppen (die eingebauten Sperren gelten immer) |
| `PORT` | `9400` | Port der Weboberfläche |
| `TLS_ENABLED` | `true` | HTTPS im Container. Hinter einem Reverse-Proxy: `false`, `TRUSTED_PROXIES=<Proxy-IP>`, `COOKIE_SECURE=true` |
| `TLS_PFX_PASSWORD` | – | Passwort der PFX-Datei im Ordner `certs` |
| `TLS_KEY_PASSWORD` | – | Passwort eines verschlüsselten privaten Schlüssels |
| `TLS_PFX` / `TLS_CERT` / `TLS_KEY` | automatisch | nur nötig, wenn im Ordner `certs` mehrere Zertifikate liegen (Dateiname) |
| `PUBLIC_HOSTNAME` | Containername | Name im selbstsignierten Zertifikat |
| `TZ` | `Europe/Berlin` | Zeitzone für Anzeige, PDF und Logs |
| `SESSION_TIMEOUT_MIN` | `30` | Inaktivität bis zur Abmeldung |
| `MAX_LOGIN_ATTEMPTS` / `LOCKOUT_MIN` | `5` / `15` | Sperre nach Fehlversuchen |
| `INACTIVE_DAYS` | `180` | ab wann Konten als inaktiv gelten |
| `ADMIN_INACTIVE_DAYS` | `90` | dto. für Admins |
| `KRBTGT_MAX_DAYS` | `180` | maximales Alter des krbtgt-Passworts |
| `SMB_CHECKS` / `SMB_TIMEOUT` | `true` / `15` | SYSVOL-/NETLOGON-Prüfungen |
| `DEFAULT_LANG` | `de` | `de` oder `en` (umschaltbar in der Oberfläche) |
| `DEMO_MODE` | `false` | Beispieldaten, Anmeldung demo/demo |
| `EGRESS_GUARD` | `true` | programminterne Sperre ausgehender Verbindungen (nur DCs) |
| `EGRESS_ALLOW` | – | weitere erlaubte Ziele (IP, Netz, Name; `;`-getrennt) |
| `REPORT_RETENTION_DAYS` | `365` | Berichte nach x Tagen löschen (`0` = nie) |
| `AUDIT_RETENTION_DAYS` | `90` | Protokoll nach x Tagen löschen (`0` = nie) |
| `PRIVACY_CONTACT` | – | Ansprechpartner auf der Datenschutzseite |
| `LOG_LEVEL` | `INFO` | |

## Sicherheitsupdates und Versionen

**Feste Versionen.** Was ins Image kommt, steht vollständig im Repository: Basisimage mit Version und Digest (`Dockerfile`, `ARG PYTHON_IMAGE`), Debian-Paketstand als Datum auf snapshot.debian.org (`ARG DEBIAN_SNAPSHOT`) mit der erwarteten Paketliste (`locks/os-packages.txt`), alle Python-Pakete mit Version und Prüfsummen (`requirements.txt`, Testwerkzeuge in `requirements-dev.txt`). Die gewünschten Pakete stehen in `requirements.in`; `tools/update-locks.sh` berechnet daraus alles neu.

**Der Unterbau** ist in `tools/lock-policy.env` festgelegt: Debian 13 „trixie“ (steht im Namen des Basisimages, nie ein Tag, das sich still ändert) und Python 3.13. Er wird nie automatisch gewechselt.

**Wöchentliches Sicherheitsupdate** (`.github/workflows/security-update.yml`, montags 03:17 UTC, von Hand unter *Actions → Security update → Run workflow*):

1. neue Versionen ermitteln, **nur innerhalb des Unterbaus**: neueste Python-3.13-Version auf Debian 13, alle Debian-Pakete auf dem Stand des Tages (auch die des Basisimages), jedes Python-Paket innerhalb seiner Hauptversion – vor 1.0 innerhalb der Nebenversion. Kalenderversionen (tzdata, certifi) haben keine Grenze.
2. Hat sich nichts geändert: Ende, es wird nichts veröffentlicht.
3. ohne Cache bauen, pip und apt entfernen, Tests im fertigen Image, Trivy-Scan.
4. Nur wenn alles bestanden ist: Image bauen, genau dieses prüfen und als `<Version>-s<n>` und `latest` veröffentlichen, Eintrag in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md) mit den geänderten Paketen, Git-Tag und GitHub-Release. Der Zähler `n` beginnt bei jeder neuen Programmversion wieder bei 1 (`1.9.7-s1`, `1.9.7-s2`, … `1.9.8-s1`).

**Trivy** wird als feste Version mit geprüfter SHA-256-Prüfsumme geladen (keine Trivy-GitHub-Action – deren Tags waren im März 2026 kompromittiert, CVE-2026-33634). Nur Funde **CRITICAL/HIGH mit verfügbarer Korrektur** stoppen eine Veröffentlichung; alles andere steht im Bericht (Zusammenfassung und Artefakt `trivy-report`). Bewusst akzeptierte Funde stehen in `.trivyignore`, jeweils mit Begründung und Ablaufdatum (`CVE-… exp:JJJJ-MM-TT  # Grund`); nach dem Datum meldet Trivy sie wieder.

**Täglicher Scan** (`scan-published.yml`, 05:43 UTC): prüft das veröffentlichte `latest` erneut, weil Schwachstellen oft erst nach dem Bau bekannt werden.

**Unterbau-Warnung** (jeden Montag, Teil des Sicherheitsupdates): fragt bei endoflife.date ab, bis wann Python 3.13 und Debian 13 Sicherheitsupdates bekommen. Weniger als 12 Monate: Hinweis am Lauf. Weniger als 6 Monate: der Lauf wird rot.

**Wenn ein Lauf rot ist** – GitHub schickt dann eine E-Mail (an das Konto, das den Zeitplan zuletzt geändert hat). Es wurde nichts veröffentlicht, `latest` bleibt auf dem letzten geprüften Stand; der Grund steht oben am Lauf (Annotation und Zusammenfassung).

| Meldung | Was tun |
|---|---|
| *Trivy found CRITICAL/HIGH vulnerabilities* | Oft liefert Debian oder das Paket die Korrektur in den nächsten Tagen nach – den nächsten Montag abwarten oder den Lauf später von Hand starten. Bleibt er rot: das betroffene Paket gezielt anheben (neue Programmversion) oder den Fund nach Bewertung mit Begründung und Ablaufdatum in `.trivyignore` eintragen. |
| *Sicherheitsupdate: Versionen nicht ermittelbar* / Bau fehlgeschlagen | Meist war eine Quelle kurz nicht erreichbar – Lauf neu starten. Bleibt er rot, passt eine neue Paketversion nicht; dann gezielt prüfen. |
| Tests im Image fehlgeschlagen | Eine neue Paketversion verhält sich anders. Nichts veröffentlicht; Paket prüfen und ggf. in `requirements.in` begrenzen. |
| *Unterbau bald anheben* (Hinweis) | Wechsel auf die nächste Python- bzw. Debian-Version einplanen. |
| *Unterbau anheben* (rot) | Unterbau bewusst anheben: `tools/lock-policy.env` ändern, `tools/update-locks.sh --major`, testen und als neue Programmversion veröffentlichen. |
| Täglicher Scan rot | Im veröffentlichten Image wurde eine neue Schwachstelle bekannt. Gibt es eine Korrektur, das Sicherheitsupdate von Hand starten; sonst wie bei Trivy oben. |

## GitHub: Repository und Container-Image

Das Container-Image wird auf GitHub gebaut und in der GitHub Container Registry veröffentlicht (`.github/workflows/docker-image.yml` für Programmversionen, `security-update.yml` und `scan-published.yml` siehe oben):

| Ereignis | Ergebnis |
|---|---|
| Push auf `main` mit neuer Version in `app/version.py` | Image `<Version>` und `latest` (falls höchste Version), Git-Tag `v<Version>`, GitHub-Release (Text aus `app/docs/news.json`). Eine schon veröffentlichte Version wird nie neu gebaut oder überschrieben. |
| Pull Request | Selbsttests, Bau aus den festen Versionen, Tests im Image, Trivy – nichts wird veröffentlicht |
| Pull Request aus einem Branch `claude/…` (von Claude vorbereitet) | nach bestandenen Prüfungen automatisch übernommen und wie ein Push auf `main` veröffentlicht |
| montags 03:17 UTC | Sicherheitsupdate `<Version>-s<n>` (siehe oben) |
| täglich 05:43 UTC | Scan des veröffentlichten `latest` |

Gebaut wird für `linux/amd64` und `linux/arm64`, ohne Cache; das gebaute Image wird zuerst ohne Tag hochgeladen, genau dieses wird geprüft (Paketliste, Tests, Trivy) und erst dann mit Tags versehen. Es enthält SBOM und Provenance-Angaben.

**Privates Repository:** Das Image (Paket `samaudit` unter *Packages*) ist dann ebenfalls privat. Auf dem Server einmalig anmelden: `docker login ghcr.io -u <GitHub-Benutzer>` – als Passwort ein *Personal Access Token (classic)* mit dem Recht `read:packages`. Alternativ das Paket unter *Package settings* öffentlich schalten.

**Neue Version veröffentlichen:** Version in `app/version.py` erhöhen, Eintrag in `app/docs/news.json` ergänzen, auf `main` pushen bzw. den Pull Request zusammenführen – nach wenigen Minuten steht das Image als `latest` und `<Version>` bereit, Tag und Release entstehen automatisch. Sicherheitsupdates entstehen ohne Zutun jeden Montag. Server holen es mit `sh update.sh --pull`; Werkzeuge wie Dockhand oder Watchtower, die `latest` beobachten, ziehen es von selbst.

## Lizenz und Nutzung

Webseite: [helfi.space](https://helfi.space)

SAMAUDIT ist freie Software unter der **GNU Affero General Public License v3.0 oder später** (AGPL-3.0-or-later), Lizenztext in `LICENSE`, Copyright-Hinweis in `NOTICE`. Wer SAMAUDIT verändert und anderen über ein Netzwerk zur Verfügung stellt, muss den geänderten Quellcode ebenfalls bereitstellen. Verwendete Bibliotheken und Schriften: `THIRD-PARTY-NOTICES.md`.

**Nutzungshinweis:** SAMAUDIT ist ein Prüfwerkzeug für Administratoren und Sicherheitsverantwortliche. Verwenden Sie es nur in Domänen, für die Sie ausdrücklich berechtigt sind. Die Software wird **ohne jede Gewährleistung** bereitgestellt; die Bewertungen sind Hinweise und ersetzen keine fachliche Prüfung. Für Schäden durch Einsatz oder Fehlinterpretation der Ergebnisse wird keine Haftung übernommen (siehe Abschnitte 15 und 16 der Lizenz).

Microsoft, Windows und Active Directory sind Marken der Microsoft Corporation; Samba ist eine Marke der Software Freedom Conservancy. SAMAUDIT steht in keiner Verbindung zu diesen Unternehmen oder zu anderen AD-Prüfwerkzeugen.

**Sicherheitslücken** bitte nicht als öffentliches Issue melden, sondern wie in `SECURITY.md` beschrieben.

## Aufbau

```
app/
  version.py     Name und Version
  main.py        Webanwendung (Starlette), Routen, Sicherheits-Header
  auth.py        Sitzungen, Sperre bei Fehlversuchen, CSRF
  ruleids.py     Regel-IDs (STL/PRV/TRS/ANM) und Zuordnung alter IDs
  ldapsrc.py     LDAP-Anmeldung, Berechtigungsprüfung, Datensammlung
  pins.py        LDAPS-Autovertrauen (Zertifikat merken und prüfen)
  webcert.py     HTTPS-Zertifikat (eigenes aus certs/ oder selbstsigniert)
  mdhelp.py      Handbuch als Hilfe-Seite
  docs/          Handbuch (handbuch.de.md, manual.en.md)
  egress.py      Ausgangssperre (nur Verbindungen zu den DCs)
  sysvol.py      SYSVOL/NETLOGON über SMB (GPP, GptTmpl.inf, Registry.pol, audit.csv, Skripte)
  analysis.py    Gruppenauflösung, privilegierte Konten, GPO-Zuordnung
  rules.py       Prüfregeln Teil 1, rules2.py Teil 2 (Texte DE/EN)
  scanner.py     Scan-Ablauf und Bewertung
  pdfreport.py   PDF-Export (ReportLab)
  db.py          SQLite
  i18n.py        Oberflächentexte DE/EN
  demo.py        Beispieldomäne für DEMO_MODE
  templates/ static/ pdf_fonts/
.env.example                      Vorlage für Ihre Einstellungen (.env)
update.sh                         Neubau/Update mit Sicherung und Prüfung
requirements.txt     Python-Abhängigkeiten (Mindestversionen, installiert wird jeweils die neueste)
tools/clean-history.sh  Git-Historie ohne persönliche Namen/E-Mail-Adressen neu schreiben (vor einer Veröffentlichung)
DATENSCHUTZ.md                    Datenschutz-Unterlagen
```

Schriften: Inter und Poppins (Oberfläche), Carlito, Poppins und DejaVu Sans Mono (PDF) – SIL Open Font License bzw. freie Lizenz, Lizenztexte liegen bei.
