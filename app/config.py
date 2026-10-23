# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Zentrale Konfiguration – wird ausschließlich über Umgebungsvariablen gesetzt
(siehe docker-compose.yml / .env.example)."""
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


# Domänen-, Organisations-, Schema-Admins, Administratoren, Konten-/Server-/Druck-/Sicherungs-Operatoren,
# Richtlinien-Ersteller, (Organisations-)Schlüsseladministratoren, Domänencontroller
DEFAULT_DENIED = ["RID:512", "RID:519", "RID:518", "RID:544", "RID:548", "RID:549", "RID:550", "RID:551",
                  "RID:520", "RID:526", "RID:527", "RID:516", "RID:521", "DnsAdmins"]


class Settings:
    def __init__(self) -> None:
        # --- Domäne -------------------------------------------------------
        # auto = Windows AD oder Samba AD wird beim Verbinden erkannt (Standard)
        self.domain_type = os.environ.get("DOMAIN_TYPE", "auto").strip().lower()
        if self.domain_type not in ("auto", "windows", "samba"):
            self.domain_type = "auto"
        self.domain_fqdn = os.environ.get("DOMAIN_FQDN", "").strip().lower()
        self.netbios = os.environ.get("DOMAIN_NETBIOS", "").strip().upper()
        # Ohne DC_HOSTS wird der Domänenname selbst verwendet – er löst in AD auf alle DCs auf.
        self.dc_hosts = _list("DC_HOSTS", os.environ.get("DC_HOST", "")) or ([self.domain_fqdn] if self.domain_fqdn else [])
        self.base_dn = os.environ.get("BASE_DN", "").strip() or (
            ",".join(f"DC={p}" for p in self.domain_fqdn.split(".") if p) if self.domain_fqdn else ""
        )

        # --- LDAP-Verbindung ---------------------------------------------
        self.ldap_ssl = _bool("LDAP_SSL", True)            # LDAPS (636)
        self.ldap_starttls = _bool("LDAP_STARTTLS", False)  # StartTLS auf 389
        self.ldap_port = _int("LDAP_PORT", 636 if self.ldap_ssl else 389)
        # Zertifikat des DC:
        #   auto   = automatisch vertrauen und beim ersten Kontakt merken (Pinning, Standard)
        #   trust  = immer vertrauen, nichts prüfen (nur Testumgebungen)
        #   verify = klassische Prüfung gegen CA-Zertifikat (LDAP_CA_FILE) bzw. Systemspeicher
        mode = os.environ.get("LDAP_CERT_MODE", "").strip().lower()
        if not mode:  # Abwärtskompatibilität
            mode = "verify" if (os.environ.get("LDAP_VERIFY_CERT", "").lower() in ("1", "true", "yes", "ja", "on")
                                and os.environ.get("LDAP_CA_FILE")) else "auto"
        self.ldap_cert_mode = mode if mode in ("auto", "trust", "verify") else "auto"
        self.ldap_timeout = _int("LDAP_TIMEOUT", 10)
        # Klartext-Bind ohne TLS ist absichtlich nur mit expliziter Freigabe möglich
        self.ldap_allow_plain = _bool("LDAP_ALLOW_PLAIN", False)

        # --- Zugriff: nur Prüfer, keine Administratoren ------------------
        # Anmelden darf nur, wer Mitglied einer dieser Gruppen ist (sAMAccountName, DN, SID oder RID:x).
        self.allowed_groups = _list("ALLOWED_GROUPS", "SAMAUDIT-Benutzer")
        # Mitglieder dieser Gruppen werden IMMER abgewiesen (Tier-0-Konten gehören nicht in eine Web-App).
        # RIDs sind sprachunabhängig ("Domänen-Admins" == "Domain Admins"). Über DENIED_GROUPS erweiterbar.
        self.denied_groups = DEFAULT_DENIED + [g for g in _list("DENIED_GROUPS", "") if g not in DEFAULT_DENIED]

        # --- Sitzung & Schutz --------------------------------------------
        self.session_timeout_min = _int("SESSION_TIMEOUT_MIN", 30)
        self.max_login_attempts = _int("MAX_LOGIN_ATTEMPTS", 5)
        self.lockout_min = _int("LOCKOUT_MIN", 15)

        # --- Webserver -----------------------------------------------------
        self.tls_enabled = _bool("TLS_ENABLED", True)
        # Eigenes Zertifikat: Dateien in den Ordner certs legen (Details: app/webcert.py).
        # Im Container kopiert entrypoint.sh den Ordner nach /tmp/certs (lesbar für den Programmbenutzer).
        self.certs_dir = os.environ.get("CERTS_DIR", "/app/certs")
        # CA-Datei für LDAP_CERT_MODE=verify: Dateiname im Ordner certs oder voller Pfad
        ca = os.environ.get("LDAP_CA_FILE", "").strip()
        if ca.startswith("/app/certs/"):
            ca = ca[len("/app/certs/"):]
        self.ldap_ca_file = (ca if os.path.isabs(ca) else os.path.join(self.certs_dir, ca)) if ca else None
        self.cookie_secure = _bool("COOKIE_SECURE", self.tls_enabled)
        self.port = _int("PORT", 9400)
        self.trusted_proxies = os.environ.get("TRUSTED_PROXIES", "")

        # --- Daten -------------------------------------------------------
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        self.db_path = os.path.join(self.data_dir, "samaudit.db")

        # --- Prüfparameter ----------------------------------------------
        self.inactive_days = _int("INACTIVE_DAYS", 180)
        self.admin_inactive_days = _int("ADMIN_INACTIVE_DAYS", 90)
        self.krbtgt_max_days = _int("KRBTGT_MAX_DAYS", 180)
        self.smb_checks = _bool("SMB_CHECKS", True)
        self.smb_timeout = _int("SMB_TIMEOUT", 15)

        # --- Netzwerk & Datenschutz ---------------------------------------
        # Ausgangssperre im Programm: nur Verbindungen zu den DCs erlaubt
        self.egress_guard = _bool("EGRESS_GUARD", True)
        # zusätzliche Ziele (IP, Netz oder Name), z. B. weitere DCs anderer Standorte
        self.egress_allow = _list("EGRESS_ALLOW", "")
        # Löschfristen (Tage, 0 = nie automatisch löschen)
        self.report_retention_days = _int("REPORT_RETENTION_DAYS", 365)
        self.audit_retention_days = _int("AUDIT_RETENTION_DAYS", 90)
        # Verantwortliche Stelle / Datenschutzkontakt für die Datenschutzseite (Freitext)
        self.privacy_contact = os.environ.get("PRIVACY_CONTACT", "").strip()

        # --- Oberfläche ---------------------------------------------------
        self.default_lang = os.environ.get("DEFAULT_LANG", "de").strip().lower()
        if self.default_lang not in ("de", "en"):
            self.default_lang = "de"
        self.org_name = os.environ.get("ORG_NAME", "").strip()
        self.tz = os.environ.get("TZ", "").strip() or "Europe/Berlin"

        # --- Demo (nur zum Ausprobieren ohne Domäne!) --------------------
        self.demo_mode = _bool("DEMO_MODE", False)

    def validate(self) -> list[str]:
        problems = []
        if self.demo_mode:
            return problems
        if not self.domain_fqdn:
            problems.append("DOMAIN_FQDN ist nicht gesetzt.")
        if not self.dc_hosts:
            problems.append("DC_HOSTS ist nicht gesetzt.")
        if not self.allowed_groups:
            problems.append("ALLOWED_GROUPS ist leer – niemand kann sich anmelden.")
        if not (self.ldap_ssl or self.ldap_starttls or self.ldap_allow_plain):
            problems.append("Weder LDAP_SSL noch LDAP_STARTTLS aktiv – Passwörter würden im Klartext übertragen.")
        if self.ldap_cert_mode == "verify" and self.ldap_ca_file and not os.path.isfile(self.ldap_ca_file):
            problems.append(f"LDAP_CA_FILE {self.ldap_ca_file} nicht gefunden – es wird nur der System-Zertifikatsspeicher genutzt.")
        return problems


settings = Settings()
