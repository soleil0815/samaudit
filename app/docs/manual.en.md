# SAMAUDIT – Manual

SAMAUDIT assesses the security of your Active Directory (Windows AD or Samba AD). It reads the domain with the rights of a **normal** user account, applies 110 checks and presents the result as a risk score, a detailed report with remediation advice, and a PDF.

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

All 110 checks with ID, area, severity and description. IDs start with `STL-` (stale objects), `PRV-` (privileged accounts), `TRS-` (trusts) and `ANM-` (anomalies).

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

- Linux server with Docker (Docker Compose is not required).
- From the server to the DCs: TCP 636 (LDAPS), TCP 445 (SMB/SYSVOL), DNS.
- A group **`SAMAUDIT-Benutzer`** in the domain containing the auditors' normal accounts:
  - Windows: `New-ADGroup SAMAUDIT-Benutzer -GroupScope Global` and `Add-ADGroupMember SAMAUDIT-Benutzer -Members max.muster`
  - Samba: `samba-tool group add SAMAUDIT-Benutzer` and `samba-tool group addmembers SAMAUDIT-Benutzer max.muster`

### Installation

```bash
unzip samaudit-v*.zip -d /opt && cd /opt/samaudit
cp .env.example .env
nano .env            # enter at least DOMAIN_FQDN and PUBLIC_HOSTNAME
./update.sh
```

`update.sh` builds the image, starts the container and checks that everything works. Then open `https://<PUBLIC_HOSTNAME>:9400` in the browser. On first access the browser warns about the self-signed certificate – upload your own certificate under **Connection**.

**Try it without a domain:** set `DEMO_MODE=true` in `.env` and sign in with `demo` / `demo`.

### Settings (`.env`)

All settings live in the `.env` file (annotated template: `.env.example`). After a change, `sh update.sh --restart` is enough. The most important ones:

| Setting | Default | Meaning |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS name of the domain (required) |
| `DC_HOSTS` | `DOMAIN_FQDN` | fixed DCs, separated by `;` |
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | auditor group(s) |
| `DENIED_GROUPS` | – | additionally blocked groups |
| `PUBLIC_HOSTNAME` | – | name used to open SAMAUDIT |
| `PORT` | `9400` | port of the web interface |
| `LDAP_CERT_MODE` | `auto` | pin the DC certificate (`auto`), always trust (`trust`), verify against a CA (`verify`) |
| `INACTIVE_DAYS` | `180` | when an account counts as inactive |
| `SMB_CHECKS` | `true` | SYSVOL checks via SMB |
| `REPORT_RETENTION_DAYS` | `365` | delete reports automatically after … days (0 = never) |
| `AUDIT_RETENTION_DAYS` | `90` | delete the activity log automatically after … days (0 = never) |
| `PRIVACY_CONTACT` | – | contact shown on the privacy page |
| `DEFAULT_LANG` | `de` | default language |

The complete list is in the README.

### Update

**Ready-made image from GitHub (recommended):**

```bash
sh update.sh --pull
```

Fetches the newest version from `ghcr.io/soleil0815/samaudit`, backs up the database and certificates first, starts the new version, verifies it and automatically starts the previous one again on problems. `update.sh` itself is updated along the way. A specific version: `sh update.sh --pull=1.9.7` (or one of its security updates, e.g. `1.9.7-s1`). If the repository is private, run `docker login ghcr.io` once on the server (password: a GitHub token with `read:packages`).

**Via ZIP file (local build):**

Copy the new ZIP file into the SAMAUDIT folder (e.g. with WinSCP) and run there:

```bash
sh update.sh samaudit-*.zip
```

The script shows the installed and the new version and asks for confirmation. It then backs up the current program files (`backups/program-*.tgz`), installs the new ones and removes files that no longer exist in the new version. Your `.env`, `data/`, `certs/` and `backups/` are never changed. Finally it asks whether to delete the ZIP file. Without a ZIP (`./update.sh`) it only rebuilds and restarts, with `--restart` it only restarts.

On every run the script also backs up the database and certificates to `backups/` (the last 5 are kept), rebuilds, starts, checks that it works and removes old images. If the new version does not run, the previous one is started again automatically. Your `.env`, `data/`, `certs/` and `backups/` are kept. Options: `--no-backup`, `--no-cache`, `--help`. It builds from the pinned versions of the program source – the same as on GitHub.

### Security updates and versions

Every component of the image has a pinned version: the base image (Debian 13 "trixie", Python 3.13) with its checksum, the Debian packages and the Python packages. Early every Monday GitHub checks whether there are newer packages within this base. If so, it rebuilds without cache, tests inside the image and scans with Trivy. Only if everything passes is a security update published with the version `<version>-s<n>`, e.g. `1.9.7-s1`, and as `latest`. The changed packages are listed in `CHANGELOG-SECURITY.md`. If there is nothing new, nothing happens. The running version is shown bottom left and at `/healthz` (field `image`).

Anyone watching `latest` (e.g. Dockhand, Watchtower) or running `sh update.sh --pull` gets the update. To stay on a version, specify it explicitly.

In addition, the published image is scanned daily, and every week it is checked how long Python 3.13 and Debian 13 still receive security updates: less than 12 months gives a notice, less than 6 months a red run. Python and Debian are never moved to a new major release automatically.

**When a run is red:** GitHub sends an email. Nothing was published; running installations stay on the last checked state. The reason is shown briefly at the top of the run:

| Reason | What to do |
|---|---|
| Trivy reports CRITICAL/HIGH | The fix usually arrives within days – wait for next Monday or rerun later via *Actions → Security update → Run workflow*. If it stays red: have the package raised specifically, or assess the finding and add it to `.trivyignore` with a reason and an expiry date. |
| Versions could not be determined / build failed | Usually a source was briefly unreachable – rerun. If it stays red, have it checked. |
| Tests inside the image failed | A new package version does not fit – have it checked. |
| Lift the base soon / now | Plan and deliberately carry out the move to the next Python or Debian release (`tools/lock-policy.env`, `tools/update-locks.sh --major`, new program version). |
| Daily scan red | New vulnerability in the published image – start the security update manually, otherwise as for Trivy. |

### Outbound connections

SAMAUDIT itself only connects to the domain controllers (LDAP, LDAPS, Global Catalog, SMB). Any other connection attempt is rejected and recorded in the **activity log** (`EGRESS_GUARD`, on by default). If you also want to isolate the container at network level, use your own firewall (Docker network `samaudit-net`, bridge `br-samaudit`).

### Data, backup and restore

Everything SAMAUDIT stores lives in the `data/` folder inside the SAMAUDIT folder: the database `samaudit.db` (reports, activity log, pinned DC certificates) and, under `tls/`, the certificates of the web interface.

**Backup:** automatic on every `./update.sh`, stored in `backups/`. **Restore:**

```bash
docker stop samaudit
sudo rm -f data/samaudit.db-wal data/samaudit.db-shm
sudo tar xzf backups/samaudit-<version>-<date>.tgz -C data
docker start samaudit
```

### Privacy

SAMAUDIT sends no data to third parties, loads nothing from the internet and deletes reports and the activity log automatically. For your documentation (record of processing activities, coordination with the data protection officer and works council) see `DATENSCHUTZ.md` (German).

### Troubleshooting

| Problem | Solution |
|---|---|
| `update.sh` says ".env was missing" | `.env` was created from the template – enter `DOMAIN_FQDN`, run again. |
| No DC reachable | DNS inside the container: add the DCs in `.env` via `DOCKER_EXTRA_HOSTS=dc01.firma.local:10.0.0.10` or set `DOCKER_DNS`, then `sh update.sh --restart`. |
| Many checks "not checkable (SMB)" | Allow TCP 445 to the DCs or set `SMB_CHECKS=false`. |
| View logs | `docker logs -f samaudit` |
| Check version | `curl -k https://localhost:9400/healthz` |

---

SAMAUDIT is free software under the GNU AGPL-3.0-or-later and is provided without warranty. Scores are indications and do not replace expert review. Website: [helfi.space](https://helfi.space)
