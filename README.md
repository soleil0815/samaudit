# SAMAUDIT – Active Directory security assessment

**English** · [Deutsch](README.de.md) · [Manual](app/docs/manual.en.md) · [Changelog](CHANGELOG.md) · [Support the project ☕](#support)

Self-hosted web application that reads a Windows or Samba AD domain, runs **115 security checks** and presents the result as a risk score (0–100), a detailed report with remediation advice, and a PDF export – in English or German. It runs as a single Docker container, signs in with a normal (non-admin) domain account and sends no data anywhere.

> **Status: beta – hobby project, no warranty.** SAMAUDIT was built for the author's own use and has mainly been tested with test data; results may be incomplete or wrong and do not replace expert review. Feedback is welcome, but no support or response times are promised. Please report security vulnerabilities privately (see [SECURITY.md](SECURITY.md)).

![Overview: risk score, rating of the four areas and the most important findings](docs/images/en-overview.webp)
*Overview after a scan – risk score, the four areas and the findings to address first*

![Expanded finding with explanation, recommended action, affected objects and references](docs/images/en-finding.webp)
*Finding in the report – what it is about, what to do, which objects are affected*

![PDF report: cover page with summary and list of findings](docs/images/en-pdf.webp)
*PDF export – cover page with summary and list of all findings*

All images show demo mode with made-up sample data (`DEMO_MODE=true`).

## Quick start

You need a Linux server (or NAS) with Docker and Docker Compose that can reach your domain controllers on TCP 636 (LDAPS) and 445 (SMB).

**1. Get two files**

```bash
mkdir -p /opt/samaudit && cd /opt/samaudit
curl -fsSLO https://github.com/soleil0815/samaudit/releases/latest/download/docker-compose.yml
curl -fsSL -o .env https://github.com/soleil0815/samaudit/releases/latest/download/env.example
```

**2. Enter your domain** – open `.env` (e.g. `nano .env`) and set the one required value:

```ini
DOMAIN_FQDN=yourdomain.local
DEFAULT_LANG=en
```

`DEFAULT_LANG=en` makes English the default language (it can also be switched in the interface). Everything else has sensible defaults and is explained in the file.

**3. Start**

```bash
docker compose up -d
```

Open `https://<server>:9400`. On first start SAMAUDIT creates a self-signed certificate, so the browser warns once ([use your own certificate](#your-own-https-certificate)).

**Before the first sign-in** create the auditor group `SAMAUDIT-Users` in AD and add the *normal* user accounts that may see the reports – admin accounts are always rejected, by design ([details](#who-may-sign-in)):

```powershell
New-ADGroup -Name "SAMAUDIT-Users" -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity "SAMAUDIT-Users" -Members "j.doe"
```

**Just want to look?** Set `DEMO_MODE=true` in `.env`, run `docker compose up -d` and sign in with `demo` / `demo` – no domain needed. Set it back to `false` for real use.

**Updates:** `docker compose pull && docker compose up -d` – or let a container manager (Dockhand, Watchtower, Portainer …) do it. Your settings and data stay; SAMAUDIT backs up its database before every version change.

<details>
<summary><b>More: Dockhand/Portainer, DNS problems, which file belongs to whom</b></summary>

**With Dockhand, Portainer & co.:** create a stack from the content of `docker-compose.yml`, store the settings from `.env` as the stack's environment file and replace the paths `./data` and `./certs` with a fixed folder, e.g. `/opt/samaudit/data`.

**What lives where?**

| File | Belongs to | On updates |
|---|---|---|
| `.env` | you – all settings | kept |
| `docker-compose.override.yml` | you – own additions (optional) | kept |
| `data/` | you – database, backups (`data/backups/`), web UI certificates | kept |
| `certs/` | you – own HTTPS certificate (optional) | kept |
| `docker-compose.yml` | SAMAUDIT – do not edit | may be replaced by a newer one |
| `update.sh` | SAMAUDIT – optional, for updating by hand | |

After changing `.env`: `docker compose up -d`.

**Own additions** – e.g. if the container cannot resolve the DC names – go into `docker-compose.override.yml` next to `docker-compose.yml`; Compose reads it automatically:

```yaml
services:
  samaudit:
    dns: [10.0.10.10, 10.0.10.11]
    extra_hosts: ["dc01.firma.local:10.0.10.10", "dc02.firma.local:10.0.10.11"]
```

Without `curl`: the two files are also attached to every [release](https://github.com/soleil0815/samaudit/releases) (save `env.example` as `.env`), or copy them out of the image: `docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.yml > docker-compose.yml` (and `/app/dist/.env.example > .env`).

</details>

## At a glance

| | |
|---|---|
| **Sign-in** | With your own **normal** domain account directly against the domain controller (LDAPS). **No service account, no admin account.** |
| **Access** | Only members of the auditor group (`ALLOWED_GROUPS`, default `SAMAUDIT-Users`). Privileged accounts are always rejected. Checked via the effective groups (`tokenGroups`, including nesting). |
| **Scan** | Started manually with the rights of the signed-in auditor. Authorisation is re-checked before every scan. |
| **Domain type** | Windows AD or Samba AD is detected automatically. |
| **Scoring** | Four areas (stale objects, privileged accounts, trusts, anomalies), 0–100 points each. Overall score = highest area score. |
| **Report** | Findings with explanation, remediation, PowerShell example, affected objects and references. Comparison with the previous scan (new / resolved). |
| **Export** | PDF with cover page, summary, domain overview, all findings and appendix. |
| **Storage** | SQLite (WAL mode) in the `data` folder inside the SAMAUDIT folder. |

## LDAPS: automatic trust

The default is `LDAP_CERT_MODE=auto` – **no CA certificate needs to be imported**:

1. On first contact with a DC, SAMAUDIT reads its certificate chain and remembers the topmost verifiable issuer (usually your enterprise CA; for Samba, its self-generated certificate).
2. Every later connection must chain back to that pinned certificate – checked **before** the password is sent.
3. If the CA renews the DC certificate, trust is kept. If someone presents a certificate from a different CA (man-in-the-middle), the sign-in is aborted and logged.

The first contact should happen in your normal network, because at that moment the certificate is necessarily trusted without verification.

If a name points to several DCs (e.g. the domain name without `DC_HOSTS`), each DC is trusted individually; entries are then called "firma.local [10.0.0.10]". A newly added DC is pinned on first contact and recorded in the activity log. If you do not want that, list the DCs in `DC_HOSTS` or use `LDAP_CERT_MODE=verify`.

The pinned certificates are listed under **Connection**. After an intentional CA change, reset them there or via the command line:

```bash
docker exec samaudit python -m app.pins list
docker exec samaudit python -m app.pins reset                  # all
docker exec samaudit python -m app.pins reset dc01.firma.local # one DC
```

Other modes: `trust` (always trust, no check – test labs only) and `verify` (classic validation against `LDAP_CA_FILE`, e.g. `ca.pem` in the `certs` folder). Unencrypted LDAP binds are blocked.

## Your own HTTPS certificate

No reverse proxy needed – SAMAUDIT serves HTTPS itself. The easiest way is the web interface:

1. Open **Connection** → section **HTTPS certificate of the web interface**.
2. Under **Upload your own certificate**, select the file(s):
   - a **PFX file** (e.g. exported from a Windows CA) + password, **or**
   - **certificate + private key** (PEM or DER; an encrypted key needs the password).
3. **Upload and activate** – the certificate is active immediately, without a restart. Reload the page if needed.

Before installing, SAMAUDIT checks that certificate and key match, that the certificate has not expired and that it loads as a server certificate; if not, the current one stays active and the page shows the reason. Issuer, expiry date, fingerprint and warnings (expiring soon, `PUBLIC_HOSTNAME` missing from the certificate) are shown. **Remove uploaded certificate** reverts to the previous one. Uploads and removals are recorded in the activity log.

- The certificate must contain the name used to open SAMAUDIT; set `PUBLIC_HOSTNAME` in `.env` to that name.
- It is stored in `data/tls/custom/` (chain + key without password, readable only by the program user) – like the self-signed certificate. The password is not stored. Backups of the `data` folder therefore contain the key.
- Renewal: simply upload the new certificate.

**Alternative without the web interface:** put the files into the `certs` folder inside the SAMAUDIT folder (for PFX set `TLS_PFX_PASSWORD`, for an encrypted key `TLS_KEY_PASSWORD` in `.env`) and run `docker compose restart`. An uploaded certificate takes precedence. Details: `certs/README.txt`.

## Network requirements

| From container to DC | Purpose |
|---|---|
| TCP 636 (LDAPS) – or 389 with StartTLS | Sign-in and data collection |
| TCP 445 (SMB) | SYSVOL/NETLOGON: GPOs, GPP passwords, scripts, audit and security policies. Can be disabled with `SMB_CHECKS=false` (these checks then show as "not checkable"). |
| DNS | The container must be able to resolve the DC names (otherwise `dns` / `extra_hosts` in `docker-compose.override.yml`, see [Quick start](#quick-start)). |

## Outbound connections

SAMAUDIT only connects to the domain controllers. The in-app guard (`EGRESS_GUARD=true`, default) only allows connections to the DC addresses on the LDAP/SMB ports; any other attempt is rejected and recorded in the activity log as "Outbound connection blocked". Allow further targets with `EGRESS_ALLOW` if needed (IP, network or name, separated by `;`). If you want to isolate the container at network level as well, use your own firewall (Docker network `samaudit-net`, bridge `br-samaudit`).

## Privacy (GDPR)

SAMAUDIT sends no data to third parties, loads nothing from the internet, sets only strictly necessary cookies and deletes reports and audit log entries automatically (`REPORT_RETENTION_DAYS`, `AUDIT_RETENTION_DAYS`). The **Privacy** page (`/privacy`, reachable without sign-in) informs auditors and employees; set the responsible contact in `PRIVACY_CONTACT`.

Responsibility for GDPR-compliant use remains with the operator. [`DATENSCHUTZ.md`](DATENSCHUTZ.md) (German) contains a template for the record of processing activities, the technical and organisational measures and a checklist (data protection officer, works council, retention).

## Who may sign in?

SAMAUDIT is deliberately **not** used with admin accounts. Signing in to a web application with a Domain Admin account means typing the most valuable password of the domain on a system that is not a domain controller (a violation of the tier model). Normal read permissions are sufficient for the assessment.

**1. Create the auditor group** and add the normal user accounts of the people who may see the reports (e.g. the IT manager's everyday account – not their admin account).

Windows AD:
```powershell
New-ADGroup -Name "SAMAUDIT-Users" -GroupScope Global -GroupCategory Security -Description "May use SAMAUDIT"
Add-ADGroupMember -Identity "SAMAUDIT-Users" -Members "j.doe"
```

Samba AD:
```bash
samba-tool group add "SAMAUDIT-Users" --description="May use SAMAUDIT"
samba-tool group addmembers "SAMAUDIT-Users" j.doe
```

The group name can be changed with `ALLOWED_GROUPS` (e.g. `SAMAUDIT-Users`).

**2. Sign-in rules**

| Check | Result |
|---|---|
| Account is in a privileged group (including nested): Domain, Enterprise, Schema Admins, Administrators, Account/Server/Print/Backup Operators, Group Policy Creator Owners, (Enterprise) Key Admins, DnsAdmins, Domain Controllers – or is the built-in Administrator account | **rejected** |
| Account is in `ALLOWED_GROUPS` | signed in |
| otherwise | rejected |

Groups are identified by RID/SID, so detection works regardless of the domain language. `DENIED_GROUPS` blocks additional groups (e.g. your own Tier 0 groups); the built-in blocks cannot be disabled.

Further protection: lockout after 5 failed attempts (per user and IP), 30-minute session timeout, CSRF protection, `HttpOnly` / `Secure` / `SameSite=Strict` cookies, Content Security Policy, and an activity log of all sign-ins (including rejected ones), scans and certificate events.

**What happens to the password?** After sign-in it is kept encrypted (key held in memory only) for the duration of the session, so that a scan can run with your rights. It is never written to the database, to disk or to logs.

## Windows AD or Samba AD – automatic detection

With `DOMAIN_TYPE=auto` (default), SAMAUDIT reads the DC's rootDSE when connecting. Samba identifies itself there with `vendorName: Samba Team`; the operating system of the DC objects is checked as well. The detected type is shown under **Connection** and in the report and controls which Windows-specific checks are run. You can force it with `windows` or `samba` if needed.

`DC_HOSTS` is optional: without it the domain name is used, which resolves to all DCs in both AD and Samba. With **several Samba DCs**, each with its own self-signed certificate, set `DC_HOSTS` to the individual DC names so that automatic LDAPS trust works per DC.

## Check catalogue (115 checks)

The full catalogue with descriptions and points is available in the application under **Check catalogue**.

**Stale objects (22):** inactive users and computers, "password never expires", PASSWD_NOTREQD, reversible encryption, DES (flag and encryption types), AS-REP roasting, Kerberoasting, unsupported operating systems (including Windows 10 since 14 Oct 2025, Server 2016 from 01/2027), SID history, hidden membership via primary group, userPassword attributes, LAPS coverage, orphaned adminCount flags, machine passwords not rotated, replication conflicts (CNF), missing AD subnets, accounts still depending on Kerberos RC4, weak certificate mappings (altSecurityIdentities).

**Privileged accounts (41):** number of admins, Schema/Enterprise Admins, operator groups, Key Admins / GPO creators, broad groups (Everyone, Domain Users …) in admin groups, admins with SPN or without pre-authentication, delegation protection / Protected Users, inactive, disabled and old admin accounts, shadow credentials, DCSync rights, write permissions on the domain object, AdminSDHolder, the "Domain Controllers" OU and critical GPOs, owner of DC objects, RODC password replication, DnsAdmins, unconstrained / constrained / resource-based delegation, "Pre-Windows 2000" group, Entra ID Seamless SSO, AD CS: ESC1, ESC2, ESC3, ESC4, ESC5, ESC8, ESC9, ESC13, ESC15, ESC17, Certighost (CVE-2026-54121), delegated managed service accounts (dMSA, "BadSuccessor"), read access to the KDS root key (Golden gMSA/dMSA), gMSA password retrieval by too many.

**Trusts (7):** SID filtering, TGT delegation, inactive/broken trusts, downlevel trusts, missing AES, foreign principals in admin groups, missing selective authentication.

**Anomalies (45):** password policy (length, lockout, complexity, history, minimum age, reversible) and PSOs, krbtgt password age (including RODC krbtgt), guest account, MachineAccountQuota, AD Recycle Bin, functional level, DC operating systems, number/state/location of DCs, AD backup, tombstone lifetime, SYSVOL replication (FRS), dSHeuristics (anonymous access, AdminSDHolder exclusions), DNS (insecure updates, ADIDNS permissions), CA certificates (SHA-1/MD5, key length, expiry), GPP passwords and autologon, passwords in logon scripts, and based on group policies: LDAP signing and channel binding, NTLMv1/LM hashes, SMB signing (server and client), print spooler on DCs, audit policy on DCs, dangerous user rights on DCs, ZeroLogon exceptions, RefusePasswordChange, Kerberos encryption types, WDigest, AlwaysInstallElevated, WSUS over HTTP, LLMNR, PowerShell logging, LSA protection, blank passwords and anonymous access via GPO; manipulable UPN/SPN (invisible characters, name collisions, duplicates, uniqueness checks).

Checks that cannot be performed in an environment (e.g. Windows-specific items on Samba, or SYSVOL without SMB access) are listed under "Not checkable" and do not count towards the risk score.

## Limitations

- The scan runs with normal user rights. A few data items are not readable then (fine-grained password policies, passwords cached on RODCs, confidential attributes such as `unixUserPassword`). The affected checks show as "not checkable", never as "passed".
- The report is an automated snapshot and does not replace a penetration test.
- Settings that are only visible in the local registry or via RPC are not queried live. Signing, NTLM level, print spooler, user rights and auditing are derived from the GPOs linked to the domain and the "Domain Controllers" OU; domain-wide settings (LLMNR, WSUS …) from all linked GPOs.
- The check rules, texts and scoring were written independently and are based on publicly documented attack techniques (MITRE ATT&CK, Microsoft guidance, BSI, SpecterOps "Certified Pre-Owned").
- The user interface and PDF are available in German and English; the default language is set with `DEFAULT_LANG` and can be switched in the interface.

## Operations

```bash
docker compose ps                         # state (healthy = ready)
docker compose logs -f                    # logs
docker compose up -d                      # after changing .env
docker compose restart                    # after changes in the certs/ folder
curl -k https://localhost:9400/healthz    # version and state
```

### Update

**With a container manager (recommended):** let Dockhand, Watchtower, Tugtainer or similar update the container `samaudit`. With `SAMAUDIT_VERSION=latest` every new version and every weekly security update arrives automatically. **Recommendation: schedule updates at night** (e.g. 03:00) – a restart aborts a scan that is running (it is marked as aborted and can be started again).

**By hand:**

```bash
docker compose pull && docker compose up -d
```

or `sh update.sh` – which additionally remembers the running version as `previous`, waits for the health check and starts the previous version again on problems (after asking, automatically with `-y`). If the `docker-compose.yml` inside the image is newer, it stores it and keeps the previous one as `docker-compose.yml.alt`. `update.sh` runs with `/bin/sh`, also on a NAS (e.g. Synology), and needs Docker with Compose.

**On every version change – however the update arrives –** SAMAUDIT backs up the database on first start to `data/backups/samaudit-vor-<version>-<time>.db` and only then adapts the database. The last 5 of these backups are kept (`BACKUP_KEEP`). If `docker-compose.yml` is outdated, a notice appears in the log and on the overview.

### Pinning a version and going back

To use a specific version: set e.g. `SAMAUDIT_VERSION=2.0.0` in `.env` (or one of its security updates, e.g. `2.0.0-s1`; the versions are listed under *Releases* on GitHub), then `docker compose up -d` – or `sh update.sh --version=2.0.0`. Back to the newest version: `SAMAUDIT_VERSION=latest`.

**Going back to an older version:** an older version does not start on the database of a newer one but states in the log which backup to restore. So in this order:

```bash
docker compose stop
docker compose run --rm samaudit restore      # list backups, choose a number
# e.g. from 2.1.0 back to 2.0.0: choose the backup "samaudit-vor-2.1.0-…"
# (state before 2.1.0 took over the database)
nano .env                                     # SAMAUDIT_VERSION=2.0.0
docker compose up -d
```

With `update.sh` in one step: `sh update.sh --restore --version=2.0.0` (lists the backups, restores the chosen one and then starts 2.0.0). The database from before the restore is kept as `samaudit-ersetzt-<time>.db`. Reports created after the backup are gone afterwards. Versions before 2.0 do not have this check yet – before going back to 1.x always restore the backup `samaudit-vor-2.0.0-…` first.

### Without internet

1. On a computer with internet, download from the GitHub release: the image file for the server (`samaudit-<version>-amd64.tar.gz`; server/NAS with an ARM processor: `…-arm64.tar.gz`) and `SHA256SUMS`, for a new installation also `docker-compose.yml`, `env.example` (save as `.env.example`) and `update.sh`.
2. Copy the files into the SAMAUDIT folder on the server.
3. `sh update.sh --load samaudit-<version>-amd64.tar.gz` – checks the checksum, loads the image (`docker load`), writes `SAMAUDIT_VERSION` into `.env`, starts and checks. Without `update.sh`: `docker load -i <file>`, `SAMAUDIT_VERSION=<version>` in `.env`, `docker compose up -d`.

### Switching from version 1.x

Up to 1.9, `update.sh` started the container itself (`docker run`), with ZIP packages and program files in the folder. Switch once:

1. Get the new `update.sh` (replaces the old one):
   ```bash
   cd /opt/samaudit
   docker pull ghcr.io/soleil0815/samaudit:latest
   docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/update.sh > update.sh
   ```
2. `sh update.sh` – detects the old installation, creates `docker-compose.yml`, moves `DOCKER_DNS`/`DOCKER_EXTRA_HOSTS` into `docker-compose.override.yml`, replaces the old container (the data stay), SAMAUDIT backs up the database (`samaudit-vor-2.0.0-…`) and starts. If the new version does not start, the old one runs again.
3. `sh update.sh --cleanup` – lists the files of earlier versions that are no longer needed (program files, ZIP packages, unpacked version folders, leftovers, the host firewall of older versions, locally built images), asks, and deletes only those. Never touched: `.env`, `docker-compose*.yml`, `data/`, `backups/`, `certs/`, `update.sh` and anything a container mounts – not even via symbolic links.
4. From now on: container manager or `docker compose pull && docker compose up -d`. The old backups in `backups/` stay and can be deleted by hand if needed.

**Is the container already managed as a stack in Dockhand/Portainer?** Then replace the stack content with the new `docker-compose.yml` (adjust the paths, add `dns`/`extra_hosts` if needed) and restart the stack – `update.sh` is not needed for that and does not touch foreign stacks.

### Data folder and backup

Everything SAMAUDIT stores is in `./data`:

| File | Content |
|---|---|
| `samaudit.db` + `-wal`/`-shm` | reports, audit log, remembered DC certificates |
| `backups/samaudit-vor-<version>-<time>.db` | automatic backup before every version change (the last 5) |
| `tls/cert.pem`, `tls/key.pem` | self-signed web UI certificate |
| `tls/custom/` | certificate uploaded via the web UI (chain + key) |

A full backup is the whole folder – for a consistent copy stop the container briefly:

```bash
docker compose stop
sudo tar czf samaudit-backup-$(date +%F).tgz data .env
docker compose start
```

While running, the folder belongs to the program user (UID 10001) and is readable only by it; use `sudo` to look at it on the host. Database, backups and PDF exports contain vulnerabilities of your domain – treat them as confidential.

**Building it yourself (developers):** `docker build -t samaudit:dev .` in the source, then `SAMAUDIT_IMAGE=samaudit` and `SAMAUDIT_VERSION=dev` in `.env` and `docker compose up -d`.

## All settings

All values are set in `.env` (format `NAME=value`, annotated template: `.env.example`). Unset values use the default.

| Variable | Default | Description |
|---|---|---|
| `DOMAIN_FQDN` | – | DNS name of the domain (required) |
| `DOMAIN_TYPE` | `auto` | `auto` (detect), `windows` or `samba` |
| `DOMAIN_NETBIOS` | automatic | NetBIOS name |
| `DC_HOSTS` | `DOMAIN_FQDN` | DCs separated by `;` (the first reachable one is used) |
| `LDAP_SSL` / `LDAP_PORT` | `true` / `636` | LDAPS |
| `LDAP_STARTTLS` | `false` | StartTLS on 389 instead of LDAPS |
| `LDAP_CERT_MODE` | `auto` | `auto` (trust automatically and pin), `trust`, `verify` |
| `PIN_RESET_WEB` | `false` | allow resetting remembered DC certificates in the web interface (otherwise only `docker exec samaudit python -m app.pins reset`) |
| `LDAP_CA_FILE` | – | CA certificate (PEM) in the `certs` folder, only for `verify` |
| `LDAP_TIMEOUT` | `10` | seconds |
| `ALLOWED_GROUPS` | `SAMAUDIT-Users` | auditor group(s): name, DN, SID or `RID:x`. Without the setting, the former name `SAMAUDIT-Benutzer` is accepted as well. |
| `DENIED_GROUPS` | – | additional blocked groups (the built-in blocks always apply) |
| `PORT` | `9400` | port of the web interface on the server (always 9400 inside the container) |
| `TLS_ENABLED` | `true` | HTTPS inside the container. Behind a reverse proxy: `false`, `TRUSTED_PROXIES=<proxy IP>`, `COOKIE_SECURE=true` |
| `TLS_PFX_PASSWORD` | – | password of the PFX file in the `certs` folder |
| `TLS_KEY_PASSWORD` | – | password of an encrypted private key |
| `TLS_PFX` / `TLS_CERT` / `TLS_KEY` | automatic | only needed if the `certs` folder holds several certificates (file name) |
| `PUBLIC_HOSTNAME` | container name | name in the self-signed certificate |
| `TZ` | `Europe/Berlin` | time zone for views, PDF and logs |
| `SESSION_TIMEOUT_MIN` | `30` | inactivity until sign-out |
| `MAX_LOGIN_ATTEMPTS` / `LOCKOUT_MIN` | `5` / `15` | lockout after failed attempts |
| `INACTIVE_DAYS` | `180` | when accounts count as inactive |
| `ADMIN_INACTIVE_DAYS` | `90` | same for admins |
| `KRBTGT_MAX_DAYS` | `180` | maximum age of the krbtgt password |
| `SMB_CHECKS` / `SMB_TIMEOUT` | `true` / `15` | SYSVOL/NETLOGON checks |
| `DEFAULT_LANG` | `de` | `de` or `en` (can be switched in the interface) |
| `DEMO_MODE` | `false` | sample data, sign-in demo/demo |
| `EGRESS_GUARD` | `true` | in-app outbound lock (DCs only) |
| `EGRESS_ALLOW` | – | additional allowed targets (IP, network, name; `;`-separated) |
| `REPORT_RETENTION_DAYS` | `365` | delete reports after x days (`0` = never) |
| `AUDIT_RETENTION_DAYS` | `90` | delete audit log after x days (`0` = never) |
| `PRIVACY_CONTACT` | – | contact shown on the privacy page |
| `LOG_LEVEL` | `INFO` | |
| `SAMAUDIT_VERSION` | `latest` | image version (e.g. `2.0.0` or `2.0.0-s1`) |
| `SAMAUDIT_IMAGE` | `ghcr.io/soleil0815/samaudit` | other image, e.g. a fork |
| `BACKUP_KEEP` | `5` | number of automatic backups before version changes (`0` = keep all) |

## Security updates and versions

**Pinned versions.** Everything that goes into the image is recorded in the repository: base image with version and digest (`Dockerfile`, `ARG PYTHON_IMAGE`), the Debian package state as a snapshot.debian.org date (`ARG DEBIAN_SNAPSHOT`) with the expected package list (`locks/os-packages.txt`), every Python package with version and hashes (`requirements.txt`, test tools in `requirements-dev.txt`). The wanted packages are listed in `requirements.in`; `tools/update-locks.sh` recomputes everything from it.

**The base** is defined in `tools/lock-policy.env`: Debian 13 "trixie" (part of the base image name, never a tag that changes silently) and Python 3.13. It is never changed automatically.

**Weekly security update** (`.github/workflows/security-update.yml`, Mondays 03:17 UTC, manually via *Actions → Security update → Run workflow*):

1. determine new versions, **only within the base**: newest Python 3.13 release on Debian 13, all Debian packages as of that day (including those of the base image), every Python package within its major version – before 1.0 within its minor version. Calendar versions (tzdata, certifi) have no limit.
2. Nothing changed: stop, nothing is published.
3. build without cache, remove pip and apt, tests inside the finished image, Trivy scan.
4. Only if everything passed: build the image, check exactly that image and publish it as `<version>-s<n>` and `latest`, add an entry with the changed packages to [CHANGELOG-SECURITY.md](CHANGELOG-SECURITY.md), git tag and GitHub release. The counter `n` starts at 1 again with every new program version (`1.9.7-s1`, `1.9.7-s2`, … `1.9.8-s1`).

**Trivy** is downloaded as a fixed version with a verified SHA-256 checksum (no Trivy GitHub Action – its tags were compromised in March 2026, CVE-2026-33634). Only **CRITICAL/HIGH findings with an available fix** stop a release; everything else is listed in the report (summary and artifact `trivy-report`). Deliberately accepted findings are listed in `.trivyignore`, each with a reason and an expiry date (`CVE-… exp:YYYY-MM-DD  # reason`); after that date Trivy reports them again.

**Daily scan** (`scan-published.yml`, 05:43 UTC): checks the published `latest` again, because vulnerabilities often become known after the build.

**Base warning** (every Monday, part of the security update): asks endoflife.date until when Python 3.13 and Debian 13 receive security updates. Less than 12 months: a notice at the run. Less than 6 months: the run turns red.

**When a run is red** – GitHub then sends an email (to the account that last changed the schedule). Nothing was published, `latest` stays on the last checked state; the reason is shown at the top of the run (annotation and summary).

| Message | What to do |
|---|---|
| *Trivy found CRITICAL/HIGH vulnerabilities* | Debian or the package often ships the fix within days – wait for next Monday or start the run manually later. If it stays red: raise the affected package specifically (new program version) or, after assessing it, add the finding to `.trivyignore` with a reason and an expiry date. |
| *Security update: versions not determinable* / build failed | Usually a source was briefly unreachable – rerun. If it stays red, a new package version does not fit; check it specifically. |
| Tests inside the image failed | A new package version behaves differently. Nothing published; check the package and limit it in `requirements.in` if needed. |
| *Lift the base soon* (notice) | Plan the move to the next Python or Debian release. |
| *Lift the base* (red) | Lift the base deliberately: change `tools/lock-policy.env`, run `tools/update-locks.sh --major`, test and publish as a new program version. |
| Daily scan red | A new vulnerability became known in the published image. If a fix exists, start the security update manually; otherwise as for Trivy above. |

## GitHub: repository and container image

The container image is built on GitHub and published to the GitHub Container Registry (`.github/workflows/docker-image.yml` for program versions, `security-update.yml` and `scan-published.yml` see above):

| Event | Result |
|---|---|
| pull request, push to `main` | self-tests, build from the pinned versions, tests inside the image, a real run of the update path with Docker Compose (switching, rollback, restore, cleanup), Trivy – nothing is published. Pull requests are merged by the owner, never automatically. |
| manual start on `main` (*Actions → Container image → Run workflow*) | if `app/version.py` contains a new version: image `<version>` and `latest` (if it is the highest version), git tag `v<version>`, GitHub release (text from `app/docs/news.json`) with image files for amd64/arm64, `SHA256SUMS`, `docker-compose.yml`, `env.example` and `update.sh`. A version that is already published is never rebuilt or overwritten. |
| Mondays 03:17 UTC | security update `<version>-s<n>` (see above) |
| daily 05:43 UTC | scan of the published `latest` |

It builds for `linux/amd64` and `linux/arm64` without cache; the built image is first uploaded without a tag, exactly that image is checked (package list, tests, Trivy) and only then tagged. It carries SBOM and provenance attestations.

**Publishing a new version:** raise the version in `app/version.py`, add an entry to `app/docs/news.json`, merge the pull request – then start the run *Container image* on `main` by hand. After a few minutes image (`latest` and `<version>`), tag and release are ready. Security updates appear every Monday without any action. Container managers watching `latest` pick up both by themselves.

## Support

SAMAUDIT is free and stays free. If it saves you time and you would like to say thanks, you can buy me a coffee: **[buymeacoffee.com/soleil0815v](https://buymeacoffee.com/soleil0815v)**. Bug reports and ideas are just as welcome – see [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence and use

Website: [helfi.space](https://helfi.space)

SAMAUDIT is free software under the **GNU Affero General Public License v3.0 or later** (AGPL-3.0-or-later); licence text in `LICENSE`, copyright notice in `NOTICE`. Anyone who modifies SAMAUDIT and makes it available to others over a network must also provide the modified source code. Libraries and fonts used: `THIRD-PARTY-NOTICES.md`.

**Usage notice:** SAMAUDIT is an assessment tool for administrators and security staff. Only use it on domains you are explicitly authorised to assess. The software is provided **without any warranty**; scores are indications and do not replace expert review. No liability is accepted for damage caused by using it or misinterpreting its results (see sections 15 and 16 of the licence).

Microsoft, Windows and Active Directory are trademarks of Microsoft Corporation; Samba is a trademark of the Software Freedom Conservancy. SAMAUDIT is not affiliated with these companies or with other AD assessment tools.

**Security vulnerabilities:** please do not open a public issue; follow `SECURITY.md` instead.

## Structure

```
app/
  version.py     name and version
  main.py        web application (Starlette), routes, security headers
  auth.py        sessions, lockout after failed attempts, CSRF
  ruleids.py     rule IDs (STL/PRV/TRS/ANM) and mapping of old IDs
  ldapsrc.py     LDAP sign-in, authorisation check, data collection
  pins.py        automatic LDAPS trust (pin and verify certificates)
  webcert.py     HTTPS certificate (your own from certs/ or self-signed)
  mdhelp.py      manual as help page
  docs/          manual (handbuch.de.md, manual.en.md)
  egress.py      outbound lock (connections to DCs only)
  sysvol.py      SYSVOL/NETLOGON via SMB (GPP, GptTmpl.inf, Registry.pol, audit.csv, scripts)
  analysis.py    group resolution, privileged accounts, GPO mapping
  rules.py       check rules part 1, rules2.py part 2 (texts DE/EN)
  scanner.py     scan flow and scoring
  pdfreport.py   PDF export (ReportLab)
  db.py          SQLite
  i18n.py        UI texts DE/EN
  demo.py        sample domain for DEMO_MODE
  templates/ static/ pdf_fonts/
  datastate.py   backup before version changes, downgrade protection, Compose version check
  restore.py     restore a backup (docker compose run --rm samaudit restore)
docker-compose.yml                start with Docker Compose (ships with the image)
.env.example                      template for your settings (.env)
update.sh                         update by hand: previous, rollback, --load, --restore, --cleanup
requirements.in / requirements.txt  Python dependencies (wish list / pinned versions with hashes)
tools/clean-history.sh  rewrite the Git history without personal names/e-mail addresses (in place or into a new repository)
DATENSCHUTZ.md                    privacy documentation (German)
```

Fonts: Inter and Poppins (web interface), Carlito, Poppins and DejaVu Sans Mono (PDF) – SIL Open Font License or other free licences; licence texts are included.
