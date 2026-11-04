# Third-party components

SAMAUDIT itself is licensed under AGPL-3.0-or-later. It uses the following components under their own licences. All of them are compatible with the AGPL-3.0.

## Python libraries

Pinned in `requirements.txt` (with exact versions and hashes) and installed from PyPI when the image is built.

| Component | Licence | Purpose |
|---|---|---|
| Starlette | BSD-3-Clause | web framework |
| Uvicorn | BSD-3-Clause | web server |
| Jinja2 | BSD-3-Clause | templates |
| ldap3 | LGPL-3.0-or-later | LDAP access (used unmodified as a library) |
| ReportLab (open-source edition) | BSD-3-Clause | PDF export |
| cryptography | Apache-2.0 or BSD-3-Clause | TLS, certificates, encryption |
| smbprotocol / pyspnego | MIT | SYSVOL access over SMB |
| tzdata | Apache-2.0 | time zone data |
| Pillow | MIT-CMU (HPND) | images in the PDF |
| typing-extensions | PSF-2.0 | dependency |
| anyio, h11, cffi, charset-normalizer | MIT | dependencies |
| idna, click, MarkupSafe, pycparser, pyasn1 | BSD-3-Clause / BSD-2-Clause (pyasn1) | dependencies |

The licence texts ship with the installed packages.

## CI only (not part of the image)

ruff (MIT), mypy (MIT), PyYAML (MIT) – `requirements-dev.txt`; Trivy (Apache-2.0) is only downloaded in CI.

## Fonts (included in the repository)

| Font | Licence | File |
|---|---|---|
| Inter | SIL Open Font License 1.1 | `app/static/fonts/LICENSE-Inter.txt` |
| Poppins | SIL Open Font License 1.1 | `app/static/fonts/LICENSE-Poppins.txt`, `app/pdf_fonts/LICENSE-Poppins.txt` |
| Carlito | SIL Open Font License 1.1 | `app/pdf_fonts/LICENSE-Carlito.txt` |
| DejaVu Sans Mono | Bitstream Vera / DejaVu licence (free) | `app/pdf_fonts/LICENSE-DejaVu.txt` |

## Docker base image

`python:3.13-slim-trixie` (Debian 13; exact version and digest in the `Dockerfile`, Debian packages in `locks/os-packages.txt`, Python packages in `requirements.txt`) – contains software under various free licences; details inside the image under `/usr/share/doc/*/copyright`.

## Trademarks

Microsoft, Windows and Active Directory are trademarks of Microsoft Corporation. Samba is a trademark of the Software Freedom Conservancy. They are named for descriptive purposes only; SAMAUDIT is not affiliated with these companies. PingCastle, Semperis and other vendors and tools cited as references are trademarks of their respective owners; SAMAUDIT is independent of them and contains none of their text or code.
