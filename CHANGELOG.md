# Changelog – SAMAUDIT

*Deutsche Version: [CHANGELOG.de.md](CHANGELOG.de.md)*

Program versions. Weekly security updates (same program, new package versions only) are listed in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md) (German).

## 2.1.8 – leaner image

- The leftovers of apt (`libapt-pkg`, `sqv`, `debian-archive-keyring`) are removed from the image. apt and pip were already removed; these three remained unused and could only cause scanner noise. `verify-image.sh` checks they stay gone.

## 2.1.7 – new coffee link

- The "Buy me a coffee" link now points to [buymeacoffee.com/soleil0815](https://buymeacoffee.com/soleil0815) (in the app, README, release notes and the GitHub Sponsor button).

## 2.1.6 – compact coffee button

- Compact "Buy me a coffee" button (yellow pill with the official cup icon, stored locally) at the bottom of the sidebar on every page, including the overview, and on the Help page.

## 2.1.5 – coffee button

- The official "Buy me a coffee" button sits at the bottom of the sidebar (every page except the overview) and on the Help page, stored locally (no request to their servers; the Content Security Policy stays `img-src 'self'`).
- GitHub: Sponsor button (`.github/FUNDING.yml`), the same button at the top of the README and a link at the end of each release note.

## 2.1.4 – English auditor group name

- **New default auditor group `SAMAUDIT-Users`** (was `SAMAUDIT-Benutzer`), so English-speaking admins know what to create.
- **Nothing to do for existing installations:** if `ALLOWED_GROUPS` is set in `.env`, exactly that group applies as before. Without the setting, both `SAMAUDIT-Users` and the former `SAMAUDIT-Benutzer` are accepted. Privileged accounts are still always rejected.
- `.env.example` no longer sets the group explicitly; the sign-in and privacy pages list all accepted groups.

## 2.1.3 – first public version

- **SAMAUDIT is now open source** at [github.com/soleil0815/samaudit](https://github.com/soleil0815/samaudit).
- **English for operators and developers:** the server log, the messages of `update.sh` and of `restore`, the automatic texts on GitHub (security update entries, release notes, workflow messages) and all code comments are now in English. Example: `START REFUSED` instead of `START ABGEBROCHEN`. `update.sh` and `restore` still accept German answers (`j`/`ja`). The web interface, PDF and manual stay bilingual.
- **Fix:** error messages when uploading your own certificate and some scan errors now follow the chosen interface language (previously German only).

## 2.1.2 – ready for open source

- **GitHub page in English** with a three-step quick start (two files, one setting, `docker compose up -d`); German version in [README.de.md](README.de.md). The version history moved into this file.
- **Help page:** licence, link to the source code and a voluntary "buy me a coffee" link (not on the overview). The sign-in page links to the source code (AGPL).
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) with DCO sign-off, issue forms that warn against posting real domain data, private reporting of vulnerabilities.
- **Licences:** third-party list checked against the current packages; licence header in every source file; trademark notice extended. Demo data now only uses reserved example domains.

## 2.1.1 – automatic code checks

- **Static checks on every pull request:** ruff (programming errors and Bandit's security rules) and mypy (type checking) run on GitHub before the self-tests. A finding turns the run red – then nothing is published. Deliberately accepted spots are marked in the code with a reason; the rules are in `pyproject.toml`.
- **Bugs found and fixed along the way:** a sign-in with an unreadable group SID in the token could abort with an internal error instead of being checked properly. The overview crashed if the latest report was being deleted at that moment. A translation entry without German text caused an error instead of showing the key. The certificate upload did not understand field names in RFC 2231 notation.
- **Updated packages:** anyio 4.16.0 and Debian package state of 1 Nov 2026 (within the base Debian 13 / Python 3.13).
- Otherwise no change in behaviour; checks and reports are unchanged.

## 2.1.0 – five new checks (now 115)

- **ESC13 (PRV-38):** certificate templates whose issuance policy is linked to an AD group – whoever may enroll gets the group's rights without membership (critical if the group is privileged).
- **Golden gMSA/dMSA (PRV-39):** anyone besides Domain/Enterprise Admins and DCs who may read the KDS root key (or grant themselves that right) can compute all gMSA and dMSA passwords forever. The key itself is never retrieved. With an ordinary account the key objects are usually invisible; SAMAUDIT then checks the inherited rights and reports the rest as "not checkable".
- **gMSA password retrievable by too many (PRV-40):** broad groups such as Domain Users or Domain Computers in msDS-GroupMSAMembership; for privileged gMSAs also individual non-admins.
- **Certighost, CVE-2026-54121 (PRV-41):** users may create computer accounts and an enterprise CA offers a logon template (e.g. "Machine") to domain computers or all users – domain takeover is possible as long as the CA lacks the July 2026 update. As SAMAUDIT cannot see the patch level and this is the default in many domains, the check is a low-weighted reminder.
- **Group Policy weakens logon protection (ANM-45):** blank passwords for network logon, anonymous SAM enumeration, Everyone permissions for anonymous users, anonymous access to named pipes/shares (like PingCastle A-LimitBlankPasswordUse / A-AnonymousAuthorizedGPO).
- **Windows Server 2016 (STL-11):** scored from 90 days before end of support (12 Jan 2027), more urgent for domain controllers; afterwards the systems automatically count as unsupported (previously they would have stayed "expiring" forever).
- **NTLMv1 (ANM-17):** note on the October 2026 update that blocks NTLMv1-derived SSO credentials by default.
- **Updated packages:** Python 3.13.18, pyasn1 0.6.5 (fixes four high-severity flaws Trivy found on the first release attempt), new time zone data.

## 2.0.0 – installation and updates the usual Docker way

- **Only three things on the server:** `docker-compose.yml`, `.env` and the data folder. The program lives entirely in the image – no ZIP, no program folder, no local build. Installation: fetch two files, fill in `.env`, `docker compose up -d`.
- **Updates as usual:** with a container manager (Dockhand, Watchtower, Tugtainer …) or `docker compose pull && docker compose up -d`. The version is set in `.env` (`SAMAUDIT_VERSION`, default `latest`).
- **The program backs itself up:** on the first start of a new version SAMAUDIT backs up the database (`data/backups/samaudit-vor-<version>-…db`) and only then adapts the database – however the update arrived. If an older version starts on a database of a newer one, it stops with a clear message naming the backup to restore (`docker compose run --rm samaudit restore`).
- **Stable `docker-compose.yml`:** the file carries a version number; if it is outdated, SAMAUDIT shows a notice. Own additions (DNS, fixed host entries) go into `docker-compose.override.yml`. Inside the container SAMAUDIT always listens on port 9400; `PORT` in `.env` only sets the port on the server.
- **New `update.sh`** (for updating by hand, runs with `/bin/sh`, also on a NAS): remembers the previous version, checks the new one and starts the previous one again on problems; without internet via `--load` from the release's image file; `--restore` restores a backup; `--cleanup` removes files of earlier versions.
- **Without internet:** every release contains the image files for amd64 and arm64 with checksums.
- **Removed:** ZIP packages, local build by `update.sh`, start via `docker run`, `DOCKER_DNS`/`DOCKER_EXTRA_HOSTS` in `.env` (moved into `docker-compose.override.yml` automatically when switching).
- **Switching** existing installations: run `sh update.sh` once, then `sh update.sh --cleanup` – see [Switching from version 1.x](#switching-from-version-1x).
- Releases are published only after explicit approval; pull requests are no longer merged automatically.

## 1.9.8

- **Docker Compose template:** `docker-compose.example.yml` starts SAMAUDIT with the same security settings as `update.sh` – e.g. as a stack in Dockhand or Portainer or with `docker compose up -d`. See [With Docker Compose or Dockhand](#with-docker-compose-or-dockhand). The template also ships inside the image (`/app/dist/`) and is kept current by `update.sh --pull`.

## 1.9.7 – pinned versions and weekly security updates

- **Reproducible build:** instead of "always the newest version", everything is now pinned: the base image by version **and** digest (`python:3.13.17-slim-trixie@sha256:…`), the Debian packages via a fixed snapshot.debian.org state, and every Python package including sub-dependencies with exact version and hashes (`requirements.txt`, generated from `requirements.in`). The same source gives the same image. The Debian package list is kept in `locks/os-packages.txt` and compared on every build. `tools/update-locks.sh` recomputes the versions.
- **Weekly security update on GitHub** (early Monday, can also be started manually): updates only within the base, builds without cache, tests inside the image, scans with Trivy and publishes only on success – as `latest` and `<version>-s<n>` (e.g. `1.9.7-s1`). The changed packages are listed in [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md). See [Security updates and versions](#security-updates-and-versions).
- **Less in the image:** pip and apt are removed after the build – they are not needed at runtime.
- **Daily scan** of the published image and a **base warning** (end of support of Python and Debian according to endoflife.date).
- **Hardened GitHub workflows:** actions pinned to commit hashes, each job only with the permissions it needs, no stored git credentials, publishing only from `main`, never two at once, published versions are never overwritten, `latest` only for the highest version. Self-tests in `tests/test_pipeline.py`.
- The web UI, the PDF and `/healthz` (field `image`) show the image version, e.g. `1.9.7-s2`. The issues of the old Monday run are gone; GitHub reports a failed run by email.

## 1.9.6

- **Everything in the image stays current:** besides Debian and Python, every Python package (including sub-dependencies) is now installed in its newest version on every build – including the weekly rebuild. `requirements.txt` only holds minimum versions. The smoke test now runs inside the finished image, i.e. with exactly the package versions that would be published; together with the Trivy scan it decides whether `latest` is renewed. The versions of each image are listed in `/app/package-versions.txt` and in the summary of the GitHub run.
- **Lifting the base:** only moving to the next Python minor version remains a deliberate step. From May 2029 the weekly run reminds you with an issue that Python 3.13 reaches end of life on 2029-10-31.
- `update.sh` fetches the current base image on every local build; `--lock` and `--refresh-base` are no longer needed.

## 1.9.5

- **Python is updated too:** the image is based on `python:3.13-slim` instead of fixed 3.13.16. The weekly rebuild therefore picks up the newest Python 3.13 release automatically (currently 3.13.17) – bug and security fixes of Python itself, no jump to 3.14. As before, every rebuild is tested and checked with Trivy before it becomes `latest`.

## 1.9.4

- **Security updates inside the image, every week:** the build now installs all available Debian security updates of the base image. GitHub rebuilds `main` every Monday, tests it, checks it with Trivy and publishes it as `latest` only on success – so the image keeps receiving security updates even without program changes. If the test or scan fails, `latest` stays unchanged and a GitHub issue states the reason (e.g. a Python package that needs a new version, which is then updated specifically).

## 1.9.3

- **Vulnerability scan with Trivy:** every image is scanned before it is published. Critical or high vulnerabilities that already have a fix stop the release – `latest` then stays on the last clean build. Everything else (e.g. vulnerabilities without a fix yet) is listed in the run's report (summary and artifact `trivy-report`). Deliberately accepted exceptions go into `.trivyignore`, with a reason.
- **Weekly re-scan:** on Mondays the published `latest` is checked again, because vulnerabilities often become known after the build. For this, `main` is rebuilt automatically every Monday – with the current base image (Debian security updates) –, tested and checked with Trivy; only if everything is green is the result published as `latest` (the version number stays). Otherwise `latest` is left unchanged and a GitHub issue "Wöchentlicher Neubau …" states the reason (e.g. a Python package that needs a new version) and mentions the repository owner. The next successful rebuild closes the issue.
- Trivy is downloaded as a fixed version with a verified checksum, not via the Trivy GitHub Action, whose version tags were compromised in March 2026 (CVE-2026-33634).

## 1.9.2 – code audit

Four independent reviews (web interface, LDAP/SYSVOL, check rules, build/update/CI); every confirmed high-impact finding is fixed.

- **Sign-in:**
  - Enterprise, Schema and Domain Admins of **any** domain in the forest are rejected, also in child domains. SID history is checked as well.
  - The "Who am I" cross-check now also compares the domain.
  - LDAP no longer follows referrals. Before, a referral could have sent the password again, possibly unencrypted.
  - Deny groups that cannot be resolved now reject the sign-in instead of letting it pass.
- **LDAPS trust:**
  - The DC certificate must be a server certificate carrying the DNS name seen on first contact. A certificate the enterprise CA issued for any computer or user is rejected.
  - A new address of an already pinned name (e.g. the second DC when the first one fails) is only accepted if its certificate belongs to a DC of the domain (known from the last scan).
  - `python -m app.pins reset firma.local` now also removes all "firma.local [IP]" entries.
  - Resetting pins works only on the server by default (`PIN_RESET_WEB`).
- **Login lockout:** now holds even against many parallel attempts. Repeated locked-out attempts no longer flood the log.
- **Robustness:**
  - A malformed PEM file can no longer hang the app.
  - Requests are read only up to the size limit.
  - Long values no longer break the PDF.
- **Sensitive actions:** uploading/removing certificates and deleting reports re-check in AD first that the auditor is still authorised.
- **SYSVOL:**
  - `GptTmpl.inf` is parsed the way Windows does. Before, a single line without "=" discarded the whole file, so the spooler, LDAP signing and user rights results were often wrong.
  - Case no longer matters.
  - One broken file no longer stops the scan.
  - GPOs the auditor cannot read now give "not checkable" instead of a wrong result.
- **More honest results:** if a data section could not be read (search error), the dependent checks are "not checkable", not "passed".
- **Check rules – false positives removed:**
  - trust accounts
  - sMSAs
  - built-in Administrator (inactive or in Schema Admins)
  - AZUREADSSOACC$
  - Windows 10 LTSC (end of support by build)
  - old expired CA certificates after a renewal
  - the Exchange default right on DCs
  - MIT Kerberos realms
  - FullSecureChannelProtection (no effect since 2021)
  - double counting of DCSync/domain ACL and ESC1/9/15/17
- **Check rules – gaps closed:**
  - delegation to DC services with three-part SPNs
  - primary group "Domain Admins" in German domains
  - missing tombstone lifetime (= 60 days)
  - NTLMv1 at level 3/4
  - AD CS in child domains
- **Other corrections:**
  - ESC8 reports "not checkable", because `/certsrv` is not recorded in AD.
  - The STL-21 text now matches KB5073381.
- **update.sh:**
  - A new `update.sh` from the image is never run unasked any more (not even with `-y`); it is saved as `update.sh.new`.
  - Interrupted updates are detected on the next run and the last working version is restored; Ctrl+C during the swap rolls back.
  - ZIP packages with symlinks or unsafe paths are rejected.
  - Before a schema change the app backs up its database itself (`data/samaudit.db.vor-*.bak`).
- **GitHub:**
  - A smoke test (`tests/smoke.py`) runs before building.
  - Auto-merge takes exactly the tested commit.
  - Publish runs are no longer cancelled.
  - Published version numbers are not overwritten.
  - Dependabot keeps the GitHub Actions up to date.

## 1.9.1

- **What's new in the app:** bottom left, **What's new** lists the changes per version – marked as feature, security, fix or notice (e.g. on the RC4 deprecation). New entries are indicated by a small dot (orange for security) and, once, by a slim dismissible line on the overview. The entries ship with the update (`app/docs/news.json`); nothing is loaded from the internet, only a cookie remembers the last version seen.

## 1.9.0

- **5 new checks (now 110)** covering 2025/2026 developments:
  - **STL-21 Kerberos RC4:** service accounts without AES keys and accounts pinned to RC4 – they break with Microsoft's RC4 deprecation (CVE-2026-20833, since April/July 2026).
  - **STL-22 Weak certificate mapping:** `altSecurityIdentities` using subject, issuer+subject or e-mail (fully enforced since September 2025, KB5014754).
  - **PRV-36 ESC17:** certificate templates that let regular accounts obtain a server certificate for any name (e.g. to take over WSUS over HTTPS; TROOPERS 2026).
  - **PRV-37 dMSA / "BadSuccessor":** who may create delegated managed service accounts on Windows Server 2025 DCs and which dMSAs link to privileged accounts.
  - **ANM-44 UPN/SPN abuse ("KerberLoss", "ResetNightmare", 2026):** invisible Unicode characters in UPN/SPN, UPNs equal to another account's logon name, duplicate names, uniqueness checks disabled.
- Additionally read: `altSecurityIdentities`, group creation dates, OUs and dMSAs (only if the schema knows Windows Server 2025).

## 1.8.1

- **Windows line endings are repaired:** if `update.sh` was copied or edited via Windows (CRLF), `sh update.sh` aborted with "Syntax error: "(" unexpected". The script now converts itself (and `entrypoint.sh`, `Dockerfile`, package lists) automatically; `.gitattributes` makes Git check the files out with LF even on Windows.
- **Licence:** `LICENSE` holds the full GNU AGPL v3 text, the copyright notice is in `NOTICE`; both are also shipped in the container image.

## 1.8.0

- **Ready for GitHub:** the container image is built by GitHub Actions and published as `ghcr.io/soleil0815/samaudit` (amd64 + arm64, with SBOM). See [GitHub: repository and container image](#github-repository-and-container-image).
- **`sh update.sh --pull`:** fetches the ready-made image from GitHub instead of building locally – with backup, health check and automatic fallback as before. `update.sh` and `.env.example` ship inside the image and are updated along the way. The classic way via ZIP or local build still works.
- Dockhand label removed.

## 1.7.5

- **Installation files in English:** `update.sh` (all messages and prompts, answer with `y`/`n`), `.env.example`, `Dockerfile`, `entrypoint.sh`, `requirements.*`, `certs/README.txt`. The web interface, reports and manual stay bilingual.
- Backups of the program files are now called `backups/program-*.tgz`.

## 1.7.4

- **Host firewall removed:** `samaudit-firewall.sh` and the systemd unit `samaudit-firewall` are gone; `update.sh` no longer sets iptables rules and does not need root/sudo for it. On the first update it removes the rules and unit of earlier versions automatically. The in-app guard (`EGRESS_GUARD`) stays: SAMAUDIT itself still only connects to the domain controllers.

## 1.7.3

- **Lower-case package name:** `samaudit-v1.7.3.zip` with the folder `samaudit/` – update with `sh update.sh samaudit-*.zip`.
- **Safe switch on update:** the previous container is only removed once the new one runs and has been verified. If the new one does not start or does not become "healthy", the previous version is started again automatically.
- `.env` may contain Windows line endings (CRLF) and a BOM (e.g. after editing with WinSCP/Notepad); comments after values are ignored correctly everywhere.

## 1.7.2

- **Docker Compose is no longer required** – just Docker. `update.sh` builds and starts the container itself (with the same security settings as before). `docker-compose.yml` and `docker-compose.override.example.yml` are gone; an existing container started with Compose is simply replaced on update.
- After changing `.env`: `sh update.sh --restart` (no rebuild).
- DNS servers and fixed DC names, if needed, via `DOCKER_DNS` and `DOCKER_EXTRA_HOSTS` in `.env` (from 2.0: `docker-compose.override.yml`).

## 1.7.1

- **One-command update:** put the ZIP file into the SAMAUDIT folder and run `sh update.sh samaudit-*.zip`. The script shows the installed and new version, asks for confirmation, backs up the current program files, installs the new ones (your `.env`, `data/`, `certs/` etc. stay untouched), removes obsolete files, builds, starts, verifies – and finally asks whether to delete the ZIP file.

## 1.7.0

- **Manual** in German and English – for auditors (usage, reading the report, messages) and operators (installation, update, network lockdown, backup, troubleshooting). In the web interface under **Help** (available without sign-in) and as files under `app/docs/`.
- Certificate upload rejects certificates that are not issued for web servers (missing "Server Authentication" usage).

## 1.6.0

- **Reproducible build:** every Python package is pinned exactly – including all sub-dependencies (`requirements.txt`, installed without re-resolution, verified with `pip check`). Python is pinned to **3.13.16**; on the first build `update.sh` additionally pins the base image to its immutable digest (`base-image.lock`). Time zone data comes from the pinned package instead of apt.
- **`update.sh`:** backup → rebuild → **set network lockdown** → start → health check → **verify no internet** → clean up old images, in one step. The lockdown is also installed as a systemd unit that runs before Docker at every boot. See [Update](#update).
- Less third-party code in the image: Uvicorn without extras (`uvloop`, `httptools`, `websockets`, `watchfiles`, `pyyaml`, `python-dotenv` dropped).
- **Connection** page: hint and warning about intermediate certificates removed.
- Correction: the network lockdown does **not** need to be disabled for a rebuild – builds do not run in the `samaudit-net` network.

## 1.5.2 – security and bug review

- **Sign-in:** the account whose rights are checked must unambiguously match the signed-in account (unique search plus an LDAP "Who am I" cross-check). Ambiguous sign-in names are rejected.
- **Multiple DCs:** if the domain name points to several DCs, each DC is trusted individually (entry "firma.local [IP]" under **Connection**). Previously a change of the answering DC could be wrongly reported as "certificate changed". Existing entries are carried over.
- **Network lockdown:** now also blocks connections from the container to services on the Docker host itself (unless the host is a DC).
- **HTTPS:** only strong cipher suites (TLS 1.2 with forward secrecy/AEAD, TLS 1.3); uploaded certificates with weak keys (RSA < 2048 bit) are rejected.
- **Privacy:** deleted reports are physically removed from the database file immediately; no page is stored in the browser cache any more; scan data no longer stays in memory after the scan.
- **Fixed:** deleting a running scan removed its partial results; retention failed with very many old reports; the redirect after switching language could be bent to external sites; reloading after a certificate upload re-submitted the form.

## 1.5.1

- **Upload the certificate via the web interface:** under **Connection**, select a PFX file or certificate + key, enter the password, done – active immediately, no restart. Checked before installing, recorded in the activity log, with a "Remove" button.
- Web interface now requires TLS 1.2 or newer.

## 1.5.0

- **Your own HTTPS certificate without a reverse proxy:** put the file(s) into the `certs` folder, run `docker compose restart` – done. PFX files (e.g. from a Windows CA) and certificate + key (PEM/DER, encrypted keys too) are detected; intermediate certificates are sent along automatically. The `certs` folder is now mounted by default.
- Under **Connection**, SAMAUDIT shows the active web certificate with issuer, expiry date and warnings (expired, expiring soon, wrong host name).
- `LDAP_CA_FILE` can now simply be a file name in the `certs` folder (e.g. `ca.pem`).

## 1.4.2

- **The sign-in page shows the target domain** right in the sign-in box – with the detected type (Windows AD / Samba AD) and domain controller.
- **Old names removed:** Only the group `SAMAUDIT-Benutzer` may sign in (the former group name is no longer accepted). A database file from earlier versions is renamed to `samaudit.db` automatically on start; all reports are kept. After the update you need to sign in again; re-select language and light/dark if needed.

## 1.4.1

- **Settings in `.env`:** All settings now live in the `.env` file instead of docker-compose.yml. `.env` is not part of the package and is never overwritten by an update – docker-compose.yml can simply be replaced. Your own compose additions (`dns`, `extra_hosts`, certificates) go into `docker-compose.override.yml`.
- **Upgrading from 1.4.0:** once run `cp .env.example .env` and transfer the values you changed in docker-compose.yml (at least `DOMAIN_FQDN`) into `.env`. Move your own `dns:`/`extra_hosts:` entries into a `docker-compose.override.yml` (template: `docker-compose.override.example.yml`).
- Sign-out button next to the user name.

## 1.4.0

- **Container without internet:** the firewall script `samaudit-firewall.sh` blocks all outbound traffic of the container on the Docker host except to the domain controllers; in addition SAMAUDIT itself rejects any other connection (`EGRESS_GUARD`).
- **Privacy (GDPR):** automatic retention for reports and the audit log, public privacy page `/privacy`, limited container logs, templates for the record of processing activities and works council in [`DATENSCHUTZ.md`](DATENSCHUTZ.md) (German).
- Dedicated Docker network `samaudit-net` (bridge `br-samaudit`, no IPv6).

## 1.3.2

- New name **SAMAUDIT** (matching SAMONBOARDING); the auditor group is now `SAMAUDIT-Benutzer`
- Own rule ID scheme: `STL-xx` (stale objects), `PRV-xx` (privileged accounts), `TRS-xx` (trusts), `ANM-xx` (anomalies). Older reports are mapped automatically.
- Open source under **GNU AGPL-3.0-or-later**, with a security policy (`SECURITY.md`) and third-party licence overview (`THIRD-PARTY-NOTICES.md`)

## 1.2.0

- **No more admin accounts:** Only members of the auditor group `SAMAUDIT-Benutzer` may sign in. Accounts in Domain, Enterprise or Schema Admins, Administrators, the operator groups, DnsAdmins etc. are **always rejected** – even if they are also in the auditor group. A Tier 0 password is therefore never typed into the web interface.
- **Scan with normal user rights:** Data a normal account cannot read (e.g. PSOs, passwords cached on RODCs) results in "not checkable" instead of a false "passed".
- **Windows AD / Samba AD are detected automatically** (`DOMAIN_TYPE=auto`); `DC_HOSTS` is optional.

## 1.1.0

- Name **SAMAUDIT** with version number in the UI, PDF and `/healthz`
- **LDAPS without CA import:** The DC certificate is trusted and pinned automatically (see below)
- Time zone **Europe/Berlin** for all views, reports and logs
- Web port **9400**
- Check catalogue extended from 61 to **105 checks**: DNS, AD CS (ESC1–ESC9/15), GPO permissions, user rights and auditing on DCs, registry policies (LLMNR, WDigest, WSUS, AlwaysInstallElevated …), logon scripts, AD backup, RODC, shadow credentials and more
- New look in the style of SAMONBOARDING (dark by default, light theme available)
- New "Connection" page listing the pinned DC certificates
