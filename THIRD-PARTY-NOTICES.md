# Fremdkomponenten / Third-party components

SAMAUDIT selbst steht unter AGPL-3.0-or-later. Es nutzt folgende Komponenten mit eigenen Lizenzen:
SAMAUDIT itself is licensed under AGPL-3.0-or-later. It uses the following components under their own licences:

## Python-Bibliotheken (feste Versionen aus `requirements.txt`, beim Docker-Build aus PyPI installiert / pinned in `requirements.txt`, installed from PyPI at build time)

| Komponente | Lizenz | Zweck |
|---|---|---|
| Starlette | BSD-3-Clause | Web-Framework |
| Uvicorn | BSD-3-Clause | Webserver |
| Jinja2 | BSD-3-Clause | Vorlagen |
| ldap3 | LGPL-3.0-or-later | LDAP-Zugriff (unverändert als Bibliothek genutzt) |
| ReportLab (Open-Source-Version) | BSD-3-Clause | PDF-Export |
| cryptography | Apache-2.0 oder BSD-3-Clause | TLS, Zertifikate, Verschlüsselung |
| smbprotocol / pyspnego | MIT | SYSVOL-Zugriff über SMB |
| tzdata | Apache-2.0 | Zeitzonendaten |
| Pillow | MIT-CMU (HPND) | Bilder im PDF |
| typing-extensions | PSF-2.0 | Unterabhängigkeit |
| anyio, h11, cffi, charset-normalizer | MIT | Unterabhängigkeiten |
| idna, click, MarkupSafe, pycparser, pyasn1 | BSD-3-Clause / BSD-2-Clause (pyasn1) | Unterabhängigkeiten |

Genaue Versionen / exact versions: `requirements.txt`. Alle Lizenzen sind mit der AGPL-3.0 vereinbar. / All licences are compatible with AGPL-3.0.

Die jeweiligen Lizenztexte liegen den installierten Paketen bei. / Licence texts ship with the installed packages.

## Nur für die Tests auf GitHub / CI only (nicht im Image / not distributed)

ruff (MIT), mypy (MIT), PyYAML (MIT) – `requirements-dev.txt`; Trivy (Apache-2.0) wird nur im CI geladen / only downloaded in CI.

## Schriften (im Repository enthalten / included in the repository)

| Schrift | Lizenz | Datei |
|---|---|---|
| Inter | SIL Open Font License 1.1 | `app/static/fonts/LICENSE-Inter.txt` |
| Poppins | SIL Open Font License 1.1 | `app/static/fonts/LICENSE-Poppins.txt`, `app/pdf_fonts/LICENSE-Poppins.txt` |
| Carlito | SIL Open Font License 1.1 | `app/pdf_fonts/LICENSE-Carlito.txt` |
| DejaVu Sans Mono | Bitstream Vera / DejaVu-Lizenz (frei) | `app/pdf_fonts/LICENSE-DejaVu.txt` |

## Docker-Basisimage

`python:3.13-slim-trixie` (Debian 13; genaue Version und Digest im `Dockerfile`, Debian-Pakete in `locks/os-packages.txt`, Python-Pakete in `requirements.txt`) – enthält Software unter verschiedenen freien Lizenzen; Details im Image unter `/usr/share/doc/*/copyright`.

## Marken / Trademarks

Microsoft, Windows und Active Directory sind Marken der Microsoft Corporation. Samba ist eine Marke der Software Freedom Conservancy. Die Nennung erfolgt ausschließlich beschreibend; es besteht keine Verbindung zu diesen Unternehmen. PingCastle, Semperis und weitere als Quelle genannte Hersteller und Werkzeuge sind Marken ihrer jeweiligen Inhaber; SAMAUDIT ist von ihnen unabhängig und übernimmt keinen ihrer Texte oder Code.

Microsoft, Windows and Active Directory are trademarks of Microsoft Corporation. Samba is a trademark of the Software Freedom Conservancy. They are named for descriptive purposes only; SAMAUDIT is not affiliated with these companies. PingCastle, Semperis and other vendors and tools cited as references are trademarks of their respective owners; SAMAUDIT is independent of them and contains none of their text or code.
