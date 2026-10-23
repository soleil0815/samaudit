# Sicherheitsrichtlinie / Security policy

*English below.*

## Unterstützte Versionen

Sicherheitskorrekturen gibt es für die jeweils aktuelle Version von SAMAUDIT.

| Version | Unterstützt |
|---|---|
| 1.3.x | ja |
| < 1.3 | nein – bitte aktualisieren |

## Sicherheitslücke melden

Bitte **kein öffentliches Issue** anlegen. Nutzen Sie stattdessen die private Meldefunktion von GitHub:
**Repository → Security → Report a vulnerability** („Private vulnerability reporting“).

Hilfreich sind: betroffene Version, Beschreibung, Schritte zum Nachvollziehen und mögliche Auswirkungen. Bitte keine echten Domänendaten, Passwörter oder Berichte mitschicken.

Wir bestätigen den Eingang in der Regel innerhalb von 7 Tagen und stimmen eine Veröffentlichung nach Bereitstellung einer Korrektur mit Ihnen ab.

## Was als Sicherheitslücke gilt

- Umgehung der Anmeldung oder der Admin-Sperre
- Zugriff auf Berichte ohne Berechtigung, CSRF, XSS, Injection
- Preisgabe von Passwörtern oder Sitzungsdaten
- Umgehung der LDAPS-Zertifikatsprüfung (Pinning)

Befunde **in Ihrer Domäne**, die SAMAUDIT anzeigt, sind keine Sicherheitslücken der Software.

---

## Supported versions

Security fixes are provided for the current version of SAMAUDIT only (see table above).

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
**Repository → Security → Report a vulnerability**.

Include the affected version, a description, steps to reproduce and the potential impact. Please do not send real domain data, passwords or reports.

We usually acknowledge reports within 7 days and coordinate disclosure with you once a fix is available.

In scope: bypassing sign-in or the admin block, unauthorised access to reports, CSRF, XSS, injection, disclosure of passwords or session data, bypassing LDAPS certificate pinning. Findings that SAMAUDIT reports **about your domain** are not vulnerabilities in the software.
