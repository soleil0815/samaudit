# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Central configuration – set exclusively through environment variables
(see docker-compose.yml / .env.example)."""
import os


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "ja", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default) or ""
    return [p.strip() for p in raw.replace(",", ";").split(";") if p.strip()]


# Domain, Enterprise and Schema Admins, Administrators, Account/Server/Print/Backup Operators,
# Group Policy Creator Owners, (Enterprise) Key Admins, Domain Controllers
DEFAULT_GROUP = "SAMAUDIT-Users"
LEGACY_GROUP = "SAMAUDIT-Benutzer"     # default up to 2.1.3

DEFAULT_DENIED = ["RID:512", "RID:519", "RID:518", "RID:544", "RID:548", "RID:549", "RID:550", "RID:551",
                  "RID:520", "RID:526", "RID:527", "RID:516", "RID:521", "DnsAdmins"]


class Settings:
    def __init__(self) -> None:
        # --- Domain -------------------------------------------------------
        # auto = Windows AD or Samba AD is detected on connect (default)
        self.domain_type = os.environ.get("DOMAIN_TYPE", "auto").strip().lower()
        if self.domain_type not in ("auto", "windows", "samba"):
            self.domain_type = "auto"
        self.domain_fqdn = os.environ.get("DOMAIN_FQDN", "").strip().lower()
        self.netbios = os.environ.get("DOMAIN_NETBIOS", "").strip().upper()
        # Without DC_HOSTS the domain name itself is used – in AD it resolves to all DCs.
        self.dc_hosts = _list("DC_HOSTS", os.environ.get("DC_HOST", "")) or ([self.domain_fqdn] if self.domain_fqdn else [])
        self.base_dn = os.environ.get("BASE_DN", "").strip() or (
            ",".join(f"DC={p}" for p in self.domain_fqdn.split(".") if p) if self.domain_fqdn else ""
        )

        # --- LDAP connection ---------------------------------------------
        self.ldap_ssl = _bool("LDAP_SSL", True)            # LDAPS (636)
        self.ldap_starttls = _bool("LDAP_STARTTLS", False)  # StartTLS on 389
        self.ldap_port = _int("LDAP_PORT", 636 if self.ldap_ssl else 389)
        # DC certificate:
        #   auto   = trust automatically and remember on first contact (pinning, default)
        #   trust  = always trust, check nothing (test environments only)
        #   verify = classic validation against a CA certificate (LDAP_CA_FILE) or the system store
        mode = os.environ.get("LDAP_CERT_MODE", "").strip().lower()
        if not mode:  # backwards compatibility
            mode = "verify" if (os.environ.get("LDAP_VERIFY_CERT", "").lower() in ("1", "true", "yes", "ja", "on")
                                and os.environ.get("LDAP_CA_FILE")) else "auto"
        self.ldap_cert_mode = mode if mode in ("auto", "trust", "verify") else "auto"
        # Allow resetting pinned DC certificates in the web interface? Default: no – otherwise any auditor could
        # trigger a new "first trust". Reset instead with: docker exec samaudit python -m app.pins reset
        self.pin_reset_web = _bool("PIN_RESET_WEB", False)
        self.ldap_timeout = _int("LDAP_TIMEOUT", 10)
        # A plain-text bind without TLS is deliberately possible only when explicitly allowed
        self.ldap_allow_plain = _bool("LDAP_ALLOW_PLAIN", False)

        # --- Access: auditors only, no administrators --------------------
        # Only members of one of these groups may sign in (sAMAccountName, DN, SID or RID:x).
        self.allowed_groups = _list("ALLOWED_GROUPS", DEFAULT_GROUP)
        # Without ALLOWED_GROUPS, the German group name used up to 2.1.3 is accepted as well, so existing
        # installations keep working. An explicit ALLOWED_GROUPS always means exactly those groups.
        self.legacy_groups = [] if "ALLOWED_GROUPS" in os.environ else [LEGACY_GROUP]
        # Members of these groups are ALWAYS rejected (tier-0 accounts do not belong in a web app).
        # RIDs are language-independent ("Domänen-Admins" == "Domain Admins"). Extendable via DENIED_GROUPS.
        self.denied_groups = DEFAULT_DENIED + [g for g in _list("DENIED_GROUPS", "") if g not in DEFAULT_DENIED]

        # --- Session & protection ----------------------------------------
        self.session_timeout_min = _int("SESSION_TIMEOUT_MIN", 30)
        self.max_login_attempts = _int("MAX_LOGIN_ATTEMPTS", 5)
        self.lockout_min = _int("LOCKOUT_MIN", 15)

        # --- Webserver -----------------------------------------------------
        self.tls_enabled = _bool("TLS_ENABLED", True)
        # Own certificate: put the files into the certs folder (details: app/webcert.py).
        # In the container entrypoint.sh copies the folder to /tmp/certs (readable for the program user).
        self.certs_dir = os.environ.get("CERTS_DIR", "/app/certs")
        # CA file for LDAP_CERT_MODE=verify: file name in the certs folder or full path
        ca = os.environ.get("LDAP_CA_FILE", "").strip()
        if ca.startswith("/app/certs/"):
            ca = ca[len("/app/certs/"):]
        self.ldap_ca_file = (ca if os.path.isabs(ca) else os.path.join(self.certs_dir, ca)) if ca else None
        self.cookie_secure = _bool("COOKIE_SECURE", self.tls_enabled)
        self.port = _int("PORT", 9400)
        self.trusted_proxies = os.environ.get("TRUSTED_PROXIES", "")

        # --- Data -------------------------------------------------------
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        self.db_path = os.path.join(self.data_dir, "samaudit.db")

        # --- Check parameters -------------------------------------------
        self.inactive_days = _int("INACTIVE_DAYS", 180)
        self.admin_inactive_days = _int("ADMIN_INACTIVE_DAYS", 90)
        self.krbtgt_max_days = _int("KRBTGT_MAX_DAYS", 180)
        self.smb_checks = _bool("SMB_CHECKS", True)
        self.smb_timeout = _int("SMB_TIMEOUT", 15)

        # --- Network & privacy ------------------------------------------
        # In-process egress guard: only connections to the DCs are allowed
        self.egress_guard = _bool("EGRESS_GUARD", True)
        # additional targets (IP, network or name), e.g. further DCs at other sites
        self.egress_allow = _list("EGRESS_ALLOW", "")
        # Retention periods (days, 0 = never delete automatically)
        self.report_retention_days = _int("REPORT_RETENTION_DAYS", 365)
        self.audit_retention_days = _int("AUDIT_RETENTION_DAYS", 90)
        # Controller / privacy contact for the privacy page (free text)
        self.privacy_contact = os.environ.get("PRIVACY_CONTACT", "").strip()

        # --- User interface ----------------------------------------------
        self.default_lang = os.environ.get("DEFAULT_LANG", "de").strip().lower()
        if self.default_lang not in ("de", "en"):
            self.default_lang = "de"
        self.org_name = os.environ.get("ORG_NAME", "").strip()
        self.tz = os.environ.get("TZ", "").strip() or "Europe/Berlin"

        # --- Demo (only for trying it out without a domain!) -------------
        self.demo_mode = _bool("DEMO_MODE", False)

    @property
    def accepted_groups(self) -> list[str]:
        """All auditor groups whose members may sign in (ALLOWED_GROUPS plus the legacy default)."""
        return self.allowed_groups + [g for g in self.legacy_groups if g not in self.allowed_groups]

    def validate(self) -> list[str]:
        """Configuration problems, for the server log only (English).

        The login page only says that there is a configuration error and points to the container log;
        it deliberately shows no details to visitors who are not signed in."""
        problems: list[str] = []
        if self.demo_mode:
            return problems
        if not self.domain_fqdn:
            problems.append("DOMAIN_FQDN is not set.")
        if not self.dc_hosts:
            problems.append("DC_HOSTS is not set.")
        if not self.allowed_groups:
            problems.append("ALLOWED_GROUPS is empty – nobody can sign in.")
        if not (self.ldap_ssl or self.ldap_starttls or self.ldap_allow_plain):
            problems.append("Neither LDAP_SSL nor LDAP_STARTTLS is enabled – passwords would be sent in plain text.")
        if self.ldap_cert_mode == "verify" and self.ldap_ca_file and not os.path.isfile(self.ldap_ca_file):
            problems.append(f"LDAP_CA_FILE {self.ldap_ca_file} not found – only the system certificate store is used.")
        return problems


settings = Settings()
