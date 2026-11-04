# SAMAUDIT – Manual

SAMAUDIT assesses the security of your Active Directory (Windows AD or Samba AD). It reads the domain with the rights of a **normal** user account, applies 115 checks and presents the result as a risk score, a detailed report with remediation advice, and a PDF.

The manual has two parts: **Part A** for auditors who use SAMAUDIT in the browser, **Part B** for running it on the server.

## Part A – Using SAMAUDIT

### Signing in

1. Open SAMAUDIT in the browser, e.g. `https://samaudit.firma.local:9400`.
2. The sign-in box shows which **domain** you are signing in to.
3. Sign in with your **normal** domain account – as `user`, `DOMAIN\user` or `user@domain`.

Only members of the auditor group (default `SAMAUDIT-Benutzer`) may sign in.

> **Admin accounts are always rejected** – even if they are in the auditor group. This is deliberate: the password of a highly privileged account is never typed into a web interface. Use your normal work account.

Your password is not stored. It is kept encrypted in memory only while you are signed in, so a scan can run with your rights. After 30 minutes of inactivity (configurable), or after 12 hours at the latest, you are signed out. To sign out, use the arrow button next to your name at the bottom left.

### Overview

The start page shows the **latest scan**: overall score, the four areas, the most important findings and – from the second scan on – the trend. **Start scan** begins a new assessment.

### Running a scan

1. **Overview** → **Start scan**.
2. Progress is shown (a few seconds to a few minutes, depending on the size of the domain).
3. The report then opens automatically.

Before every scan SAMAUDIT checks again that you still belong to the auditor group. Only one scan runs at a time; if someone else starts one, you see its progress.

### Reading the report

**Risk score (0–100):** 0 means no findings, 100 a very high risk. Each of the four areas has its own score (at most 100); the overall score is the **highest** area score – so a single serious weakness determines the overall picture.

| Score | Rating |
|---|---|
| 0–14 | Very good |
| 15–34 | Good |
| 35–59 | Action needed |
| 60–100 | Critical |

**The four areas:**

| Area | What it covers |
|---|---|
| Stale objects | inactive accounts and computers, old operating systems, passwords that never expire, old functional levels |
| Privileged accounts | admin groups, delegation, dangerous permissions, DCSync, AD Certificate Services (ESC1–ESC15) |
| Trusts | trusts to other domains, SID filtering, outdated trusts |
| Anomalies | policies, GPOs, password policy, auditing, scripts containing passwords, DNS, backup |

**A finding**, when expanded, shows what the problem is, how to fix it (often with a PowerShell example and a **Copy** button), the affected objects (with a filter box for long lists) and references. The colour on the left stands for the **severity** (Critical, High, Medium, Low, Info), `+points` for the contribution to the area score.

**new** marks findings that did not occur in the previous scan. **Resolved since previous scan** lists items that have been fixed.

**Not checkable** does not mean "passed": the information was not available – usually because a normal account may not read it, SYSVOL was not reachable via SMB, or the check does not apply to this domain type (Windows/Samba). The reason is shown next to it.

### PDF export

In the report, top right: **Download PDF**. The PDF contains a cover page, summary, domain overview, all findings with remediation and the appendix. It is generated in the currently selected language.

> Reports and PDFs describe the weaknesses of your domain. Treat them as confidential and store them only in protected places.

### Reports

**Reports** lists all scans with date, scores and number of findings. Individual reports can be **deleted** (not while a scan is running). Reports are also deleted automatically after the configured retention period (default 365 days).

### Check catalogue

All 115 checks with ID, area, severity and description. IDs start with `STL-` (stale objects), `PRV-` (privileged accounts), `TRS-` (trusts) and `ANM-` (anomalies).

### Connection

- **Domain and DCs:** domain name, detected type (Windows AD / Samba AD), domain controllers used, LDAPS mode.
- **HTTPS certificate of the web interface:** shows the active certificate (source, issuer, expiry date, fingerprint) and warnings (expired, expiring soon, server name missing from the certificate).
  - **Upload your own certificate:** select a PFX file (e.g. exported from a Windows CA) with its password **or** certificate + private key → **Upload and activate**. It becomes active immediately, without a restart; reload the page afterwards. Before installing, SAMAUDIT checks that certificate and key match, that it is valid and that the key is strong enough (RSA at least 2048 bits).
  - **Remove uploaded certificate** restores the previous one.
- **Trusted DC certificates:** SAMAUDIT remembers each DC's certificate and DNS name on first contact and later rejects a foreign certificate (protection against man-in-the-middle) – including one the same enterprise CA issued for another computer or user. Normal renewals stay valid. After an **intended** certificate or CA change (or a new DC), reset it – for security reasons on the server: `docker exec samaudit python -m app.pins reset <DC>`. With `PIN_RESET_WEB=true` in `.env` the **Reset** button here works as well.

### Activity log

All sign-ins (including rejected ones), scans, PDF exports, deletions, certificate changes and blocked network connections with time, user and IP address. Entries are deleted automatically after the configured retention period (default 90 days).

### What's new

Bottom left, **What's new** lists what changed with each version: new **features**, **security** improvements, **fixes** and **notices** about new Active Directory risks (e.g. deprecations by Microsoft). If there is something you have not seen yet, a small dot appears next to it (orange for security topics) and the overview shows a slim line once. **×** or visiting the page clears both. The news ships with the update – SAMAUDIT loads nothing from the internet for it. Only a cookie in your browser remembers which version you last saw.

### Language, appearance, privacy

Bottom left: **DE / EN** switches the language, **Dark / Light** the appearance. **Privacy** shows which data SAMAUDIT processes, how long it is kept and who is responsible – this page is available without signing in.

### Sign-in messages

| Message | Meaning / remedy |
|---|---|
| Wrong username or password | Check your input. After several failed attempts sign-in is blocked briefly (default 5 attempts / 15 minutes). |
| Access denied: not a member of the auditor group | Have the account added to `SAMAUDIT-Benutzer`, then sign in again. |
| Admin accounts may not sign in | Use a normal account (see above). |
| The auditor group does not exist | Create the group in the domain (operations, Part B). |
| The account is locked / disabled / must change its password | Resolve in the domain (e.g. change the password on a PC). |
| No domain controller reachable | Check network and `DC_HOSTS` (Part B). |
| The domain controller's certificate has changed | Possible attack **or** intended certificate change / new DC. If intended: on the server `docker exec samaudit python -m app.pins reset <DC>`. |
| Session expired | Sign in again. |

## Part B – Operations

### Requirements

- Server or NAS with Docker and Docker Compose (or a container manager such as Dockhand or Portainer).
- From the server to the DCs: TCP 636 (LDAPS), TCP 445 (SMB/SYSVOL), DNS.
- A group **`SAMAUDIT-Benutzer`** in the domain containing the auditors' normal accounts:
  - Windows: `New-ADGroup SAMAUDIT-Benutzer -GroupScope Global` and `Add-ADGroupMember SAMAUDIT-Benutzer -Members max.muster`
  - Samba: `samba-tool group add SAMAUDIT-Benutzer` and `samba-tool group addmembers SAMAUDIT-Benutzer max.muster`

### Installation

The server only holds `docker-compose.yml`, `.env` and the data folder – the program lives in the image.

```bash
mkdir -p /opt/samaudit && cd /opt/samaudit
curl -fsSLO https://github.com/soleil0815/samaudit/releases/latest/download/docker-compose.yml
curl -fsSL -o .env https://github.com/soleil0815/samaudit/releases/latest/download/env.example
nano .env            # enter at least DOMAIN_FQDN (English UI: DEFAULT_LANG=en)
docker compose up -d
```

Without `curl`, copy the files out of the image: `docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.yml > docker-compose.yml` (and `/app/dist/.env.example > .env`). Then open `https://<PUBLIC_HOSTNAME>:9400` in the browser. On first access the browser warns about the self-signed certificate – upload your own certificate under **Connection**.

**With Dockhand, Portainer & co.:** create a stack from the content of `docker-compose.yml`, store the settings of `.env` with the stack and replace the paths `./data` and `./certs` with a fixed folder (e.g. `/opt/samaudit/data`).

**DCs not resolvable via DNS?** Put a file `docker-compose.override.yml` next to `docker-compose.yml` – Compose reads it automatically:

```yaml
services:
  samaudit:
    dns: [10.0.10.10]
    extra_hosts: ["dc01.firma.local:10.0.10.10"]
```

**Try it without a domain:** set `DEMO_MODE=true` in `.env` and sign in with `demo` / `demo`.

### Settings (`.env`)

All settings live in the `.env` file (annotated template: `.env.example`). After a change: `docker compose up -d`. The most important ones:

| Setting | Default | Meaning |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS name of the domain (required) |
| `DC_HOSTS` | `DOMAIN_FQDN` | fixed DCs, separated by `;` |
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | auditor group(s) |
| `DENIED_GROUPS` | – | additionally blocked groups |
| `PUBLIC_HOSTNAME` | – | name used to open SAMAUDIT |
| `PORT` | `9400` | port of the web interface on the server |
| `SAMAUDIT_VERSION` | `latest` | image version, e.g. `2.0.0` |
| `LDAP_CERT_MODE` | `auto` | pin the DC certificate (`auto`), always trust (`trust`), verify against a CA (`verify`) |
| `INACTIVE_DAYS` | `180` | when an account counts as inactive |
| `SMB_CHECKS` | `true` | SYSVOL checks via SMB |
| `REPORT_RETENTION_DAYS` | `365` | delete reports automatically after … days (0 = never) |
| `AUDIT_RETENTION_DAYS` | `90` | delete the activity log automatically after … days (0 = never) |
| `PRIVACY_CONTACT` | – | contact shown on the privacy page |
| `DEFAULT_LANG` | `de` | default language |

The complete list is in the README.

### Update

**With a container manager (recommended):** Dockhand, Watchtower, Tugtainer or similar keep the container `samaudit` up to date. Recommendation: schedule updates **at night** – a restart aborts a scan that is running.

**By hand:**

```bash
docker compose pull && docker compose up -d
```

or `sh update.sh`: remembers the running version, checks the new one and starts the previous one again on problems; brings a newer `docker-compose.yml` along if needed (the previous one is kept as `docker-compose.yml.alt`). Also runs on a NAS. If the repository is private, run `docker login ghcr.io` once on the server (password: a GitHub token with `read:packages`).

**On every version change** SAMAUDIT itself backs up the database on first start to `data/backups/samaudit-vor-<version>-<time>.db` (the last 5 are kept) – however the update arrived.

**Pinning a version:** set `SAMAUDIT_VERSION=2.0.0` in `.env` (or a security update such as `2.0.0-s1`), then `docker compose up -d`. Back to the newest: `SAMAUDIT_VERSION=latest`.

**Going back to an older version:** an older version does not start on the database of a newer one but names the backup to restore in the log (`docker compose logs`). Order:

```bash
docker compose stop
docker compose run --rm samaudit restore    # choose a backup, e.g. "samaudit-vor-2.1.0-…" to go back from 2.1.0
nano .env                                   # SAMAUDIT_VERSION=2.0.0
docker compose up -d
```

Or in one step: `sh update.sh --restore --version=2.0.0`.

**Without internet:** get the image file (`samaudit-<version>-amd64.tar.gz`, on ARM `-arm64`) and `SHA256SUMS` from the GitHub release, copy them into the SAMAUDIT folder and run `sh update.sh --load samaudit-<version>-amd64.tar.gz`.

**Switching from version 1.x** (previously `update.sh` with ZIP or `--pull`):

1. Get the new `update.sh`: `docker pull ghcr.io/soleil0815/samaudit:latest` and `docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/update.sh > update.sh`
2. `sh update.sh` – switches to Docker Compose once (data stay, `DOCKER_DNS`/`DOCKER_EXTRA_HOSTS` are moved into `docker-compose.override.yml`).
3. `sh update.sh --cleanup` – lists the files of earlier versions that are no longer needed and deletes them after asking. Data, backups, `.env`, Compose files and mounted folders are never touched.

### Security updates and versions

Every component of the image has a pinned version: the base image (Debian 13 "trixie", Python 3.13) with its checksum, the Debian packages and the Python packages. Early every Monday GitHub checks whether there are newer packages within this base. If so, it rebuilds without cache, tests inside the image and scans with Trivy. Only if everything passes is a security update published with the version `<version>-s<n>`, e.g. `2.0.0-s1`, and as `latest`. The changed packages are listed in `CHANGELOG-SECURITY.md`. If there is nothing new, nothing happens. The running version is shown bottom left and at `/healthz` (field `image`).

Anyone using `latest` (container manager or `docker compose pull && docker compose up -d`) gets the update. To stay on a version, specify it explicitly.

In addition, the published image is scanned daily, and every week it is checked how long Python 3.13 and Debian 13 still receive security updates: less than 12 months gives a notice, less than 6 months a red run. Python and Debian are never moved to a new major release automatically.

**When a run is red:** GitHub sends an email. Nothing was published; running installations stay on the last checked state. The reason is shown briefly at the top of the run:

| Reason | What to do |
|---|---|
| Trivy reports CRITICAL/HIGH | The fix usually arrives within days – wait for next Monday or rerun later via *Actions → Security update → Run workflow*. If it stays red: have the package raised specifically, or assess the finding and add it to `.trivyignore` with a reason and an expiry date. |
| *Security update: versions not determinable* / *Build failed* | Usually a source was briefly unreachable – rerun. If it stays red, have it checked. |
| *Tests in the image failed* | A new package version does not fit – have it checked. |
| Lift the base soon / now | Plan and deliberately carry out the move to the next Python or Debian release (`tools/lock-policy.env`, `tools/update-locks.sh --major`, new program version). |
| Daily scan red | New vulnerability in the published image – start the security update manually, otherwise as for Trivy. |

### Outbound connections

SAMAUDIT itself only connects to the domain controllers (LDAP, LDAPS, Global Catalog, SMB). Any other connection attempt is rejected and recorded in the **activity log** (`EGRESS_GUARD`, on by default). If you also want to isolate the container at network level, use your own firewall (Docker network `samaudit-net`, bridge `br-samaudit`).

### Data, backup and restore

Everything SAMAUDIT stores is in the `data/` folder: the database `samaudit.db` (reports, activity log, remembered DC certificates), under `backups/` the automatic backups before every version change and under `tls/` the web UI certificates.

**Restoring a backup:**

```bash
docker compose stop
docker compose run --rm samaudit restore    # list of backups, choose a number
docker compose up -d
```

The database from before the restore is kept as `samaudit-ersetzt-<time>.db`. **Full backup** (e.g. before moving): `docker compose stop`, `sudo tar czf samaudit-backup.tgz data .env`, `docker compose start`.

### Privacy

SAMAUDIT sends no data to third parties, loads nothing from the internet and deletes reports and the activity log automatically. For your documentation (record of processing activities, coordination with the data protection officer and works council) see `DATENSCHUTZ.md` (German).

### Troubleshooting

| Problem | Solution |
|---|---|
| Container does not start, log: "START REFUSED: The database comes from SAMAUDIT …" | An older version runs on the database of a newer one – restore the backup named there (see above) or use the newer version again. |
| Note "docker-compose.yml is outdated" | Get the current file (`sh update.sh` or `/app/dist/docker-compose.yml` from the image), own additions into `docker-compose.override.yml`, `docker compose up -d`. |
| No DC reachable | DNS inside the container: add `dns`/`extra_hosts` in `docker-compose.override.yml` (see Installation), then `docker compose up -d`. |
| Many checks "not checkable (SMB)" | Allow TCP 445 to the DCs or set `SMB_CHECKS=false`. |
| View logs | `docker compose logs -f` |
| Check version | `curl -k https://localhost:9400/healthz` |

---

SAMAUDIT is free software under the GNU AGPL-3.0-or-later and is provided without warranty. Scores are indications and do not replace expert review. Website: [helfi.space](https://helfi.space)
