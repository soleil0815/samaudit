# SAMAUDIT v1.9.3 – Active Directory security assessment

*Deutsche Version: [README.md](README.md)* · **Manual:** [app/docs/manual.en.md](app/docs/manual.en.md) (also in the web interface under **Help**)

Self-hosted web application that reads a Windows or Samba AD domain, runs **110 security checks** and presents the result as a risk score (0–100), a detailed report with remediation advice, and a PDF export – in German or English.

## New in 1.9.3

- **Vulnerability scan with Trivy:** every image is scanned before it is published. Critical or high vulnerabilities that already have a fix stop the release – `latest` then stays on the last clean build. Everything else (e.g. vulnerabilities without a fix yet) is listed in the run's report (summary and artifact `trivy-report`). Deliberately accepted exceptions go into `.trivyignore`, with a reason.
- **Weekly re-scan:** on Mondays the published `latest` is checked again, because vulnerabilities often become known after the build. Fixable findings automatically trigger a rebuild with the current base image (Debian security updates), which is scanned again before publishing. If that does not fix it, the run fails and GitHub notifies you by e-mail.
- Trivy is downloaded as a fixed version with a verified checksum, not via the Trivy GitHub Action, whose version tags were compromised in March 2026 (CVE-2026-33634).

## New in 1.9.2 – code audit

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

## New in 1.9.1

- **What's new in the app:** bottom left, **What's new** lists the changes per version – marked as feature, security, fix or notice (e.g. on the RC4 deprecation). New entries are indicated by a small dot (orange for security) and, once, by a slim dismissible line on the overview. The entries ship with the update (`app/docs/news.json`); nothing is loaded from the internet, only a cookie remembers the last version seen.

## New in 1.9.0

- **5 new checks (now 110)** covering 2025/2026 developments:
  - **STL-21 Kerberos RC4:** service accounts without AES keys and accounts pinned to RC4 – they break with Microsoft's RC4 deprecation (CVE-2026-20833, since April/July 2026).
  - **STL-22 Weak certificate mapping:** `altSecurityIdentities` using subject, issuer+subject or e-mail (fully enforced since September 2025, KB5014754).
  - **PRV-36 ESC17:** certificate templates that let regular accounts obtain a server certificate for any name (e.g. to take over WSUS over HTTPS; TROOPERS 2026).
  - **PRV-37 dMSA / "BadSuccessor":** who may create delegated managed service accounts on Windows Server 2025 DCs and which dMSAs link to privileged accounts.
  - **ANM-44 UPN/SPN abuse ("KerberLoss", "ResetNightmare", 2026):** invisible Unicode characters in UPN/SPN, UPNs equal to another account's logon name, duplicate names, uniqueness checks disabled.
- Additionally read: `altSecurityIdentities`, group creation dates, OUs and dMSAs (only if the schema knows Windows Server 2025).

## New in 1.8.1

- **Windows line endings are repaired:** if `update.sh` was copied or edited via Windows (CRLF), `sh update.sh` aborted with "Syntax error: "(" unexpected". The script now converts itself (and `entrypoint.sh`, `Dockerfile`, package lists) automatically; `.gitattributes` makes Git check the files out with LF even on Windows.
- **Licence:** `LICENSE` holds the full GNU AGPL v3 text, the copyright notice is in `NOTICE`; both are also shipped in the container image.

## New in 1.8.0

- **Ready for GitHub:** the container image is built by GitHub Actions and published as `ghcr.io/soleil0815/samaudit` (amd64 + arm64, with SBOM). See [GitHub: repository and container image](#github-repository-and-container-image).
- **`sh update.sh --pull`:** fetches the ready-made image from GitHub instead of building locally – with backup, health check and automatic fallback as before. `update.sh` and `.env.example` ship inside the image and are updated along the way. The classic way via ZIP or local build still works.
- Dockhand label removed.

## New in 1.7.5

- **Installation files in English:** `update.sh` (all messages and prompts, answer with `y`/`n`), `.env.example`, `Dockerfile`, `entrypoint.sh`, `requirements.*`, `certs/README.txt`. The web interface, reports and manual stay bilingual.
- Backups of the program files are now called `backups/program-*.tgz`.

## New in 1.7.4

- **Host firewall removed:** `samaudit-firewall.sh` and the systemd unit `samaudit-firewall` are gone; `update.sh` no longer sets iptables rules and does not need root/sudo for it. On the first update it removes the rules and unit of earlier versions automatically. The in-app guard (`EGRESS_GUARD`) stays: SAMAUDIT itself still only connects to the domain controllers.

## New in 1.7.3

- **Lower-case package name:** `samaudit-v1.7.3.zip` with the folder `samaudit/` – update with `sh update.sh samaudit-*.zip`.
- **Safe switch on update:** the previous container is only removed once the new one runs and has been verified. If the new one does not start or does not become "healthy", the previous version is started again automatically.
- `.env` may contain Windows line endings (CRLF) and a BOM (e.g. after editing with WinSCP/Notepad); comments after values are ignored correctly everywhere.

## New in 1.7.2

- **Docker Compose is no longer required** – just Docker. `update.sh` builds and starts the container itself (with the same security settings as before). `docker-compose.yml` and `docker-compose.override.example.yml` are gone; an existing container started with Compose is simply replaced on update.
- After changing `.env`: `sh update.sh --restart` (no rebuild).
- DNS servers and fixed DC names, if needed, via `DOCKER_DNS` and `DOCKER_EXTRA_HOSTS` in `.env`.

## New in 1.7.1

- **One-command update:** put the ZIP file into the SAMAUDIT folder and run `sh update.sh samaudit-*.zip`. The script shows the installed and new version, asks for confirmation, backs up the current program files, installs the new ones (your `.env`, `data/`, `certs/` etc. stay untouched), removes obsolete files, builds, starts, verifies – and finally asks whether to delete the ZIP file.

## New in 1.7.0

- **Manual** in German and English – for auditors (usage, reading the report, messages) and operators (installation, update, network lockdown, backup, troubleshooting). In the web interface under **Help** (available without sign-in) and as files under `app/docs/`.
- Certificate upload rejects certificates that are not issued for web servers (missing "Server Authentication" usage).

## New in 1.6.0

- **Reproducible build:** every Python package is pinned exactly – including all sub-dependencies (`requirements.txt`, installed without re-resolution, verified with `pip check`). Python is pinned to **3.13.16**; on the first build `update.sh` additionally pins the base image to its immutable digest (`base-image.lock`). Time zone data comes from the pinned package instead of apt.
- **`update.sh`:** backup → rebuild → **set network lockdown** → start → health check → **verify no internet** → clean up old images, in one step. The lockdown is also installed as a systemd unit that runs before Docker at every boot. See [Update](#update).
- Less third-party code in the image: Uvicorn without extras (`uvloop`, `httptools`, `websockets`, `watchfiles`, `pyyaml`, `python-dotenv` dropped).
- **Connection** page: hint and warning about intermediate certificates removed.
- Correction: the network lockdown does **not** need to be disabled for a rebuild – builds do not run in the `samaudit-net` network.

## New in 1.5.2 – security and bug review

- **Sign-in:** the account whose rights are checked must unambiguously match the signed-in account (unique search plus an LDAP "Who am I" cross-check). Ambiguous sign-in names are rejected.
- **Multiple DCs:** if the domain name points to several DCs, each DC is trusted individually (entry "firma.local [IP]" under **Connection**). Previously a change of the answering DC could be wrongly reported as "certificate changed". Existing entries are carried over.
- **Network lockdown:** now also blocks connections from the container to services on the Docker host itself (unless the host is a DC).
- **HTTPS:** only strong cipher suites (TLS 1.2 with forward secrecy/AEAD, TLS 1.3); uploaded certificates with weak keys (RSA < 2048 bit) are rejected.
- **Privacy:** deleted reports are physically removed from the database file immediately; no page is stored in the browser cache any more; scan data no longer stays in memory after the scan.
- **Fixed:** deleting a running scan removed its partial results; retention failed with very many old reports; the redirect after switching language could be bent to external sites; reloading after a certificate upload re-submitted the form.

## New in 1.5.1

- **Upload the certificate via the web interface:** under **Connection**, select a PFX file or certificate + key, enter the password, done – active immediately, no restart. Checked before installing, recorded in the activity log, with a "Remove" button.
- Web interface now requires TLS 1.2 or newer.

## New in 1.5.0

- **Your own HTTPS certificate without a reverse proxy:** put the file(s) into the `certs` folder, run `docker compose restart` – done. PFX files (e.g. from a Windows CA) and certificate + key (PEM/DER, encrypted keys too) are detected; intermediate certificates are sent along automatically. The `certs` folder is now mounted by default.
- Under **Connection**, SAMAUDIT shows the active web certificate with issuer, expiry date and warnings (expired, expiring soon, wrong host name).
- `LDAP_CA_FILE` can now simply be a file name in the `certs` folder (e.g. `ca.pem`).

## New in 1.4.2

- **The sign-in page shows the target domain** right in the sign-in box – with the detected type (Windows AD / Samba AD) and domain controller.
- **Old names removed:** Only the group `SAMAUDIT-Benutzer` may sign in (the former group name is no longer accepted). A database file from earlier versions is renamed to `samaudit.db` automatically on start; all reports are kept. After the update you need to sign in again; re-select language and light/dark if needed.

## New in 1.4.1

- **Settings in `.env`:** All settings now live in the `.env` file instead of docker-compose.yml. `.env` is not part of the package and is never overwritten by an update – docker-compose.yml can simply be replaced. Your own compose additions (`dns`, `extra_hosts`, certificates) go into `docker-compose.override.yml`.
- **Upgrading from 1.4.0:** once run `cp .env.example .env` and transfer the values you changed in docker-compose.yml (at least `DOMAIN_FQDN`) into `.env`. Move your own `dns:`/`extra_hosts:` entries into a `docker-compose.override.yml` (template: `docker-compose.override.example.yml`).
- Sign-out button next to the user name.

## New in 1.4.0

- **Container without internet:** the firewall script `samaudit-firewall.sh` blocks all outbound traffic of the container on the Docker host except to the domain controllers; in addition SAMAUDIT itself rejects any other connection (`EGRESS_GUARD`).
- **Privacy (GDPR):** automatic retention for reports and the audit log, public privacy page `/privacy`, limited container logs, templates for the record of processing activities and works council in [`DATENSCHUTZ.md`](DATENSCHUTZ.md) (German).
- Dedicated Docker network `samaudit-net` (bridge `br-samaudit`, no IPv6).

## New in 1.3.2

- New name **SAMAUDIT** (matching SAMONBOARDING); the auditor group is now `SAMAUDIT-Benutzer`
- Own rule ID scheme: `STL-xx` (stale objects), `PRV-xx` (privileged accounts), `TRS-xx` (trusts), `ANM-xx` (anomalies). Older reports are mapped automatically.
- Open source under **GNU AGPL-3.0-or-later**, with a security policy (`SECURITY.md`) and third-party licence overview (`THIRD-PARTY-NOTICES.md`)

## New in 1.2.0

- **No more admin accounts:** Only members of the auditor group `SAMAUDIT-Benutzer` may sign in. Accounts in Domain, Enterprise or Schema Admins, Administrators, the operator groups, DnsAdmins etc. are **always rejected** – even if they are also in the auditor group. A Tier 0 password is therefore never typed into the web interface.
- **Scan with normal user rights:** Data a normal account cannot read (e.g. PSOs, passwords cached on RODCs) results in "not checkable" instead of a false "passed".
- **Windows AD / Samba AD are detected automatically** (`DOMAIN_TYPE=auto`); `DC_HOSTS` is optional.

## New in 1.1.0

- Name **SAMAUDIT** with version number in the UI, PDF and `/healthz`
- **LDAPS without CA import:** The DC certificate is trusted and pinned automatically (see below)
- Time zone **Europe/Berlin** for all views, reports and logs
- Web port **9400**
- Check catalogue extended from 61 to **105 checks**: DNS, AD CS (ESC1–ESC9/15), GPO permissions, user rights and auditing on DCs, registry policies (LLMNR, WDigest, WSUS, AlwaysInstallElevated …), logon scripts, AD backup, RODC, shadow credentials and more
- New look in the style of SAMONBOARDING (dark by default, light theme available)
- New "Connection" page listing the pinned DC certificates

## At a glance

| | |
|---|---|
| **Sign-in** | With your own **normal** domain account directly against the domain controller (LDAPS). **No service account, no admin account.** |
| **Access** | Only members of the auditor group (`ALLOWED_GROUPS`, default `SAMAUDIT-Benutzer`). Privileged accounts are always rejected. Checked via the effective groups (`tokenGroups`, including nesting). |
| **Scan** | Started manually with the rights of the signed-in auditor. Authorisation is re-checked before every scan. |
| **Domain type** | Windows AD or Samba AD is detected automatically. |
| **Scoring** | Four areas (stale objects, privileged accounts, trusts, anomalies), 0–100 points each. Overall score = highest area score. |
| **Report** | Findings with explanation, remediation, PowerShell example, affected objects and references. Comparison with the previous scan (new / resolved). |
| **Export** | PDF with cover page, summary, domain overview, all findings and appendix. |
| **Storage** | SQLite (WAL mode) in the `data` folder inside the SAMAUDIT folder. |

## Quick start

**Option A – ready-made image from GitHub (recommended, no build on the server):**

```bash
mkdir -p /opt/samaudit && cd /opt/samaudit
docker login ghcr.io          # only needed while repository/package are private (see below)
IMG=ghcr.io/soleil0815/samaudit:latest
docker run --rm --entrypoint cat $IMG /app/dist/update.sh   > update.sh
docker run --rm --entrypoint cat $IMG /app/dist/.env.example > .env.example
cp .env.example .env && nano .env      # enter DOMAIN_FQDN etc.
sh update.sh --pull
```

Later updates: `sh update.sh --pull` (fetches the newest image and also updates `update.sh` itself).

**Option B – build it yourself from the source code** (clone the repository or unpack the ZIP):

```bash
# 1. Create the auditor group and add normal (non-admin) accounts – see below
# 2. Create your settings and enter DOMAIN_FQDN (everything else is optional)
cp .env.example .env
nano .env
# 3. Build and start
./update.sh
# 4. Open in the browser
https://<docker-host>:9400
```

On first start a self-signed HTTPS certificate is generated for the web interface (one-time browser warning). Your own certificate: see [Your own HTTPS certificate](#your-own-https-certificate).

**Try it without a domain:** set `DEMO_MODE=true` in `.env` and sign in with `demo` / `demo` (sign-in with `administrator` / `demo` shows how admin accounts are rejected). Set it back to `false` for production.

**What lives where?**

| File | Owner | On updates |
|---|---|---|
| `.env` | you – all settings | kept (not in the package) |
| `certs/` | you – your own certificates | kept (only `README.txt` in the package) |
| `data/` | you – database, certificates | kept |
| `.env.example`, `update.sh`, program files | SAMAUDIT | replaced – do not edit |

After changing `.env`, `sh update.sh --restart` is enough (no rebuild needed).

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

**Alternative without the web interface:** put the files into the `certs` folder inside the SAMAUDIT folder (for PFX set `TLS_PFX_PASSWORD`, for an encrypted key `TLS_KEY_PASSWORD` in `.env`) and run `sh update.sh --restart`. An uploaded certificate takes precedence. Details: `certs/README.txt`.

## Network requirements

| From container to DC | Purpose |
|---|---|
| TCP 636 (LDAPS) – or 389 with StartTLS | Sign-in and data collection |
| TCP 445 (SMB) | SYSVOL/NETLOGON: GPOs, GPP passwords, scripts, audit and security policies. Can be disabled with `SMB_CHECKS=false` (these checks then show as "not checkable"). |
| DNS | The container must be able to resolve the DC names (`DOCKER_DNS` / `DOCKER_EXTRA_HOSTS` in `.env`). |

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
New-ADGroup -Name "SAMAUDIT-Benutzer" -GroupScope Global -GroupCategory Security -Description "May use SAMAUDIT"
Add-ADGroupMember -Identity "SAMAUDIT-Benutzer" -Members "j.doe"
```

Samba AD:
```bash
samba-tool group add "SAMAUDIT-Benutzer" --description="May use SAMAUDIT"
samba-tool group addmembers "SAMAUDIT-Benutzer" j.doe
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

## Check catalogue (110 checks)

The full catalogue with descriptions and points is available in the application under **Check catalogue**.

**Stale objects (22):** inactive users and computers, "password never expires", PASSWD_NOTREQD, reversible encryption, DES (flag and encryption types), AS-REP roasting, Kerberoasting, unsupported operating systems (including Windows 10 since 14 Oct 2025, Server 2016 from 01/2027), SID history, hidden membership via primary group, userPassword attributes, LAPS coverage, orphaned adminCount flags, machine passwords not rotated, replication conflicts (CNF), missing AD subnets, accounts still depending on Kerberos RC4, weak certificate mappings (altSecurityIdentities).

**Privileged accounts (37):** number of admins, Schema/Enterprise Admins, operator groups, Key Admins / GPO creators, broad groups (Everyone, Domain Users …) in admin groups, admins with SPN or without pre-authentication, delegation protection / Protected Users, inactive, disabled and old admin accounts, shadow credentials, DCSync rights, write permissions on the domain object, AdminSDHolder, the "Domain Controllers" OU and critical GPOs, owner of DC objects, RODC password replication, DnsAdmins, unconstrained / constrained / resource-based delegation, "Pre-Windows 2000" group, Entra ID Seamless SSO, AD CS: ESC1, ESC2, ESC3, ESC4, ESC5, ESC8, ESC9, ESC15, ESC17, delegated managed service accounts (dMSA, "BadSuccessor").

**Trusts (7):** SID filtering, TGT delegation, inactive/broken trusts, downlevel trusts, missing AES, foreign principals in admin groups, missing selective authentication.

**Anomalies (44):** password policy (length, lockout, complexity, history, minimum age, reversible) and PSOs, krbtgt password age (including RODC krbtgt), guest account, MachineAccountQuota, AD Recycle Bin, functional level, DC operating systems, number/state/location of DCs, AD backup, tombstone lifetime, SYSVOL replication (FRS), dSHeuristics (anonymous access, AdminSDHolder exclusions), DNS (insecure updates, ADIDNS permissions), CA certificates (SHA-1/MD5, key length, expiry), GPP passwords and autologon, passwords in logon scripts, and based on group policies: LDAP signing and channel binding, NTLMv1/LM hashes, SMB signing (server and client), print spooler on DCs, audit policy on DCs, dangerous user rights on DCs, ZeroLogon exceptions, RefusePasswordChange, Kerberos encryption types, WDigest, AlwaysInstallElevated, WSUS over HTTP, LLMNR, PowerShell logging, LSA protection; manipulable UPN/SPN (invisible characters, name collisions, duplicates, uniqueness checks).

Checks that cannot be performed in an environment (e.g. Windows-specific items on Samba, or SYSVOL without SMB access) are listed under "Not checkable" and do not count towards the risk score.

## Limitations

- The scan runs with normal user rights. A few data items are not readable then (fine-grained password policies, passwords cached on RODCs, confidential attributes such as `unixUserPassword`). The affected checks show as "not checkable", never as "passed".
- The report is an automated snapshot and does not replace a penetration test.
- Settings that are only visible in the local registry or via RPC are not queried live. Signing, NTLM level, print spooler, user rights and auditing are derived from the GPOs linked to the domain and the "Domain Controllers" OU; domain-wide settings (LLMNR, WSUS …) from all linked GPOs.
- The check rules, texts and scoring were written independently and are based on publicly documented attack techniques (MITRE ATT&CK, Microsoft guidance, BSI, SpecterOps "Certified Pre-Owned").
- The user interface and PDF are available in German and English; the default language is set with `DEFAULT_LANG` and can be switched in the interface.

## Operations

```bash
docker logs -f samaudit                              # logs
sh update.sh --restart                               # after changing .env
./update.sh                                          # rebuild after an update (see below)
curl -k https://localhost:9400/healthz               # version and status
```

### Update

**With the image from GitHub:** `sh update.sh --pull` – pulls `ghcr.io/soleil0815/samaudit:latest`, backs up first, starts the new version, verifies it and falls back to the previous one on problems. A specific version: `sh update.sh --pull=1.9.3`. If the image is already current, nothing happens. Other image (e.g. a fork): `SAMAUDIT_IMAGE=ghcr.io/<name>/<repo>` in `.env`.

**With a ZIP or the source code (local build):**

Put the ZIP file of the new version into the SAMAUDIT folder, then:

```bash
sh update.sh samaudit-*.zip
```

With a ZIP, the script first shows the installed and new version and asks for confirmation, backs up the current program files to `backups/program-*.tgz`, installs the new ones and removes obsolete files (`.env`, `data/`, `certs/`, `backups/` and `base-image.lock` stay untouched). At the end it asks whether to delete the ZIP file. Without a ZIP (`./update.sh`) it only rebuilds and restarts. Then it
1. creates a **backup** in `backups/` (consistent copy of the database + certificates; the last 5 are kept),
2. **builds** the image with the pinned base image and pinned packages,
3. **restarts** the container and waits until it reports "healthy" (otherwise aborts with a log excerpt),
4. removes **old images** (the previous version is kept for a rollback).

| Call | Effect |
|---|---|
| `./update.sh --no-backup` | without backup |
| `./update.sh --no-cache` | full rebuild |
| `./update.sh --refresh-base` | fetch the Python base image again (Debian security updates) and pin it anew |
| `./update.sh --lock` | re-resolve `requirements.txt` from `requirements.in` (e.g. after a version change) |

If `.env` is missing, the script creates it from the template and asks for `DOMAIN_FQDN`. If the build fails, the running container stays unchanged.

**Reproducibility:** Python version (tag + digest in `base-image.lock`) and every package are pinned exactly; the image is built without re-resolution. Local builds therefore use the same base as the first build. The GitHub image is built from the pinned tag `python:3.13.16-slim` (no `base-image.lock` in the repository), and package contents are not hash-checked – the result is version-identical, not bit-for-bit reproducible.

**Data folder and backup:** Everything SAMAUDIT stores is in `./data` inside the SAMAUDIT folder:

| File | Content |
|---|---|
| `samaudit.db` + `-wal`/`-shm` | reports, activity log, pinned DC certificates |
| `tls/cert.pem`, `tls/key.pem` | self-signed certificate of the web interface |
| `tls/custom/` | certificate uploaded via the web interface (chain + key) |

`update.sh` backs up automatically. Manually – for a consistent backup, stop the container briefly:

```bash
docker stop samaudit
sudo tar czf samaudit-backup-$(date +%F).tgz data
docker start samaudit
```

While running, the folder belongs to the program user (UID 10001) and is readable only by it; use `sudo` to look at it on the host.

The database, backups and PDF exports describe weaknesses of your domain – treat them as confidential.

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
| `ALLOWED_GROUPS` | `SAMAUDIT-Benutzer` | auditor group(s): name, DN, SID or `RID:x` |
| `DENIED_GROUPS` | – | additional blocked groups (the built-in blocks always apply) |
| `PORT` | `9400` | port of the web interface |
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

## GitHub: repository and container image

The repository contains a GitHub Actions workflow (`.github/workflows/docker-image.yml`) that builds the container image on GitHub and publishes it to the GitHub Container Registry:

| Event | Image tags |
|---|---|
| push to `main` | `latest`, `<version from app/version.py>`, `sha-<commit>` – afterwards the workflow creates the git tag `v<version>` and a GitHub release automatically (text from `app/docs/news.json`) if the version does not exist yet |
| git tag `v1.9.3` | `1.9.3` (must match `app/version.py`) |
| pull request | built only (test), not published |
| every run | Trivy vulnerability scan of the image – critical/high vulnerabilities with an available fix stop the run before anything is published |
| weekly (Mon) and on demand | scan of the published `latest`; fixable findings trigger an automatic rebuild with the current base image (workflow "Security scan") |
| pull request from a branch `claude/…` (prepared by Claude) | merged automatically after a successful test build and published like a push to `main` |

It builds for `linux/amd64` and `linux/arm64`, using the pinned base image (from `base-image.lock` if present) and the pinned packages; the image carries SBOM and provenance attestations.

**Private repository:** the image (package `samaudit` under *Packages*) is private as well. On the server, log in once: `docker login ghcr.io -u <github-user>` – password: a *personal access token (classic)* with the `read:packages` scope. Alternatively make the package public under *Package settings*.

**Publishing a new version:** raise the version in `app/version.py`, add an entry to `app/docs/news.json`, push to `main` or merge the pull request – after a few minutes the image is available as `latest` and `<version>`, tag and release are created automatically. Servers fetch it with `sh update.sh --pull`; tools watching `latest` such as Dockhand or Watchtower pull it by themselves.

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
.env.example                      template for your settings (.env)
update.sh                         rebuild/update with backup and checks
requirements.in / requirements.txt  direct / fully pinned dependencies
DATENSCHUTZ.md                    privacy documentation (German)
```

Fonts: Inter and Poppins (web interface), Carlito, Poppins and DejaVu Sans Mono (PDF) – SIL Open Font License or other free licences; licence texts are included.
