# Security policy / Sicherheitsrichtlinie

*Deutsche Fassung unten.*

## Project status

SAMAUDIT is a **hobby project**, maintained without warranty and without guaranteed response times (see the licence, sections 15 and 16). Security reports are nevertheless taken seriously and handled as soon as possible.

## Supported versions

Fixes are provided for the **current version only** (container image `latest` or the newest version number). In addition, a security update (`<version>-s<n>`) with updated Debian and Python packages within the base is published once a month on patch day (the second Tuesday), tested and scanned for vulnerabilities; the published image is scanned daily – please always run the current version.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Repository → Security → Report a vulnerability**.

Include the affected version, a description, steps to reproduce and the potential impact. Please do not send real domain data, passwords or reports.

Disclosure of the details is coordinated with you once a fix is available.

In scope: bypassing sign-in or the admin block, unauthorised access to reports, CSRF, XSS, injection, disclosure of passwords or session data, bypassing LDAPS certificate pinning, vulnerabilities in the published container image or in the update chain (`update.sh`, GitHub workflow). Findings that SAMAUDIT reports **about your domain** are not vulnerabilities in the software.

---

# Deutsch

## Status des Projekts

SAMAUDIT ist ein **Hobbyprojekt** und wird ohne Gewähr und ohne zugesagte Reaktionszeiten gepflegt (siehe Lizenz, Abschnitte 15 und 16). Sicherheitsmeldungen werden trotzdem ernst genommen und so bald wie möglich bearbeitet.

## Unterstützte Versionen

Korrekturen gibt es nur für die **jeweils aktuelle Version** (Container-Image `latest` bzw. die neueste Versionsnummer). Zusätzlich erscheint einmal im Monat am Patchday (zweiter Dienstag) ein Sicherheitsupdate (`<Version>-s<n>`) mit aktualisierten Debian- und Python-Paketen innerhalb des Unterbaus, getestet und auf Schwachstellen geprüft; das veröffentlichte Image wird täglich gescannt – bitte immer die aktuelle Version verwenden.

| Version | Unterstützt |
|---|---|
| aktuelle Version (`latest`) | ja |
| ältere Versionen | nein – bitte aktualisieren |

## Sicherheitslücke melden

Bitte **kein öffentliches Issue** anlegen. Nutzen Sie stattdessen die private Meldefunktion von GitHub:
**Repository → Security → Report a vulnerability** („Private vulnerability reporting“).

Hilfreich sind: betroffene Version, Beschreibung, Schritte zum Nachvollziehen und mögliche Auswirkungen. Bitte keine echten Domänendaten, Passwörter oder Berichte mitschicken.

Nach einer Korrektur wird die Veröffentlichung der Details mit Ihnen abgestimmt.

## Was als Sicherheitslücke gilt

- Umgehung der Anmeldung oder der Sperre für Admin-Konten
- Zugriff auf Berichte ohne Berechtigung, CSRF, XSS, Injection
- Preisgabe von Passwörtern oder Sitzungsdaten
- Umgehung der LDAPS-Zertifikatsprüfung (Pinning)
- Schwachstellen im veröffentlichten Container-Image oder in der Update-Kette (`update.sh`, GitHub-Workflow)

Befunde **in Ihrer Domäne**, die SAMAUDIT anzeigt, sind keine Sicherheitslücken der Software.
