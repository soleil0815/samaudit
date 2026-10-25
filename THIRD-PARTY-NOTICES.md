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
| anyio, idna, h11, click, MarkupSafe, cffi, pycparser, pyasn1, Pillow, charset-normalizer, typing-extensions | MIT / BSD / Apache-2.0 / HPND (Pillow) | Unterabhängigkeiten (genaue Versionen: `requirements.txt`) |

Die jeweiligen Lizenztexte liegen den installierten Paketen bei. / Licence texts ship with the installed packages.

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

Microsoft, Windows und Active Directory sind Marken der Microsoft Corporation. Samba ist eine Marke der Software Freedom Conservancy. Die Nennung erfolgt ausschließlich beschreibend; es besteht keine Verbindung zu diesen Unternehmen.
