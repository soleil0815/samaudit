# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Audit rules. On a finding, each rule returns a list of affected objects.

Scoring (based on the well-known four-category model):
  points per rule → sum per category (max. 100) → overall risk = highest category score.
  0 = no findings, 100 = very high risk.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .adutil import (
    GUID_CERT_AUTOENROLL, GUID_CERT_ENROLL, GUID_DS_REPL_GET_CHANGES_ALL, UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH, UAC_ENCRYPTED_TEXT_PWD_ALLOWED, UAC_NOT_DELEGATED, UAC_PASSWD_NOTREQD,
    UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION, UAC_USE_DES_KEY_ONLY,
    ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_GENERIC_ALL, ace_grants_control, classify_os, fmt_date, sid_domain,
)
from .analysis import Ctx

CATEGORIES = ["stale", "privileged", "trusts", "anomalies"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]


class NotApplicable(Exception):
    """Rule cannot be checked in this environment (reason = i18n key or text)."""


@dataclass
class Hit:
    items: list[dict]
    points: int | None = None
    severity: str | None = None
    count: int | None = None
    note: str | None = None  # short addendum (no translation needed: numbers/facts)


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    points: int
    title: dict
    desc: dict
    fix: dict
    columns: list[str]
    check: Callable[[Ctx], Hit | None]
    code: str = ""
    refs: list[tuple[str, str]] = field(default_factory=list)
    platforms: tuple = ("windows", "samba")
    legacy_id: str = ""            # internal name before the switch to STL-/PRV-… numbers


RULES: list[Rule] = []


def rule(**kw):
    def deco(fn):
        RULES.append(Rule(check=fn, **kw))
        return fn
    return deco


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def acc(a: dict, **extra) -> dict:
    d = {"account": a.get("sam", ""), "last_logon": fmt_date(a.get("last_logon")),
         "pwd_last_set": fmt_date(a.get("pwd_last_set"))}
    d.update(extra)
    return d


def enabled_users(ctx: Ctx):
    return [u for u in ctx.users if u.get("enabled") and u.get("rid") not in (502,)]


def enabled_computers(ctx: Ctx, include_dc=True):
    return [c for c in ctx.computers if c.get("enabled") and (include_dc or not (c.get("is_dc") or c.get("is_rodc")))]


def unprivileged(ctx: Ctx) -> bool:
    """Scan ran with normal user rights (default since v1.2)."""
    return bool((ctx.m.get("meta") or {}).get("unprivileged"))


def need_sysvol(ctx: Ctx) -> dict:
    sv = ctx.m.get("sysvol") or {}
    if sv.get("status") == "disabled":
        raise NotApplicable("na_smb_disabled")
    if sv.get("status") != "ok":
        raise NotApplicable("na_smb_error")
    return sv


def check_gpos_readable(ctx: Ctx, guids) -> None:
    """If an effective GPO is not readable for the auditor (e.g. security filtering), the setting cannot
    be assessed – then "not checkable" instead of a wrong result."""
    sv = need_sysvol(ctx)
    bad = {g.upper() for g in (sv.get("unreadable_gpos") or [])} & {g.upper() for g in guids}
    if bad:
        raise NotApplicable("na_gpo_unreadable")


def effective_dc_registry(ctx: Ctx, key_suffix: str) -> str | None:
    """Value from GptTmpl.inf of the GPOs on domain → DC OU (later ones override earlier ones)."""
    sv = need_sysvol(ctx)
    check_gpos_readable(ctx, ctx.gpo_guids("dc"))   # raises "not checkable" for unreadable links/GPOs
    secedit = sv.get("secedit", {})
    value = None
    links = (ctx.m.get("gpo_links") or {})
    for link in list(links.get("domain", [])) + list(links.get("dc_ou", [])):
        if not link.get("enabled"):
            continue
        data = secedit.get(link["guid"].upper()) or {}
        for k, v in (data.get("Registry Values") or {}).items():
            if k.lower().endswith(key_suffix.lower()):
                value = v.split(",", 1)[1].strip().strip('"') if "," in v else v
    return value


def pct(part: int, whole: int) -> float:
    return (100.0 * part / whole) if whole else 0.0


MS = "https://learn.microsoft.com"
ATT = "https://attack.mitre.org/techniques"

# ===========================================================================
# STALE OBJECTS
# ===========================================================================


@rule(id="S-InactiveUsers", category="stale", severity="medium", points=10,
      title={"de": "Inaktive, aber aktivierte Benutzerkonten",
             "en": "Inactive but enabled user accounts"},
      desc={"de": "Diese Konten haben sich länger als der eingestellte Zeitraum nicht angemeldet (oder noch nie), sind aber "
                  "weiterhin aktiviert. Verwaiste Konten fallen bei Missbrauch kaum auf und werden häufig für "
                  "Passwort-Spraying oder als unauffälliger Zugang genutzt.",
            "en": "These accounts have not logged on for longer than the configured period (or never) but are still "
                  "enabled. Orphaned accounts rarely attract attention when abused and are a classic target for "
                  "password spraying."},
      fix={"de": "Konten mit dem zuständigen Fachbereich klären, deaktivieren und nach einer Karenzzeit löschen. "
                 "Einen regelmäßigen Prozess für Austritte und Rezertifizierung einführen.",
           "en": "Confirm with the owners, disable the accounts and delete them after a grace period. Establish a "
                 "regular leaver and recertification process."},
      code="Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 180.00:00:00 |\n  Where-Object Enabled |\n  Disable-ADAccount -WhatIf",
      columns=["account", "last_logon", "created", "dn"],
      refs=[("MITRE ATT&CK T1078.002", f"{ATT}/T1078/002/")])
def _inactive_users(ctx: Ctx):
    days = ctx.cfg.inactive_days
    # excluding gMSAs and the built-in Administrator account (as an emergency account it should NOT be used)
    eu = [u for u in enabled_users(ctx) if not u.get("is_gmsa") and u.get("rid") != 500]
    hits = [u for u in eu if ctx.inactive(u, days)]
    if not hits:
        return None
    share = pct(len(hits), len(eu))
    items = [acc(u, created=fmt_date(u.get("created")), dn=u["dn"]) for u in hits]
    if share >= 15:
        return Hit(items, points=15, severity="high", note=f"{share:.0f} %")
    if share >= 5:
        return Hit(items, points=10, note=f"{share:.0f} %")
    return Hit(items, points=5, severity="low", note=f"{share:.0f} %")


@rule(id="S-InactiveComputers", category="stale", severity="medium", points=10,
      title={"de": "Inaktive, aber aktivierte Computerkonten", "en": "Inactive but enabled computer accounts"},
      desc={"de": "Computerkonten, die sich lange nicht mehr gemeldet haben, gehören meist zu ausgemusterten Geräten. "
                  "Ihre Konten (inkl. Maschinenpasswort und Delegierungsrechten) bleiben nutzbar und verfälschen "
                  "zudem Inventar und Patch-Statistiken.",
            "en": "Computer accounts that have not checked in for a long time usually belong to retired devices. Their "
                  "accounts remain usable and distort inventory and patch statistics."},
      fix={"de": "Geräte im Inventar abgleichen, Konten deaktivieren und in eine Quarantäne-OU verschieben, später löschen.",
           "en": "Reconcile with the inventory, disable and move to a quarantine OU, delete later."},
      code="Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan 180.00:00:00 |\n  Where-Object Enabled | Disable-ADAccount -WhatIf",
      columns=["account", "os", "last_logon", "dn"])
def _inactive_computers(ctx: Ctx):
    ec = [c for c in enabled_computers(ctx, include_dc=False) if (c.get("sam") or "").upper() != "AZUREADSSOACC$"]
    hits = [c for c in ec if ctx.inactive(c, ctx.cfg.inactive_days)]
    if not hits:
        return None
    share = pct(len(hits), len(ec))
    items = [acc(c, os=c.get("os"), dn=c["dn"]) for c in hits]
    return Hit(items, points=10 if share >= 5 else 5, severity="medium" if share >= 5 else "low", note=f"{share:.0f} %")


@rule(id="S-PwdNeverExpires", category="stale", severity="low", points=5,
      title={"de": "Passwort läuft nie ab", "en": "Password never expires"},
      desc={"de": "Bei diesen Konten ist „Kennwort läuft nie ab“ gesetzt. Ein einmal kompromittiertes Passwort bleibt "
                  "damit unbegrenzt gültig. Häufig betrifft das Dienstkonten mit sehr alten Passwörtern.",
            "en": "These accounts have 'password never expires' set, so a compromised password stays valid "
                  "indefinitely. Often affects service accounts with very old passwords."},
      fix={"de": "Dienstkonten auf gMSA (Group Managed Service Accounts) umstellen. Bei Benutzern das Flag entfernen "
                 "oder lange Passphrasen mit regelmäßigem Wechsel bzw. MFA einsetzen.",
           "en": "Migrate service accounts to gMSA. For users, remove the flag or use long passphrases with MFA."},
      code="Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' -Properties PasswordLastSet |\n  Select-Object SamAccountName, PasswordLastSet",
      columns=["account", "pwd_last_set", "last_logon"],
      refs=[("Microsoft: gMSA", f"{MS}/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview")])
def _pwd_never_expires(ctx: Ctx):
    hits = [u for u in enabled_users(ctx) if u["uac"] & UAC_DONT_EXPIRE_PASSWORD and not u.get("is_gmsa")]
    if not hits:
        return None
    return Hit([acc(u) for u in hits], points=5 if len(hits) > 5 else 2)


@rule(id="S-PwdNotRequired", category="stale", severity="medium", points=10,
      title={"de": "Konten ohne Passwortpflicht (PASSWD_NOTREQD)", "en": "Accounts without password requirement (PASSWD_NOTREQD)"},
      desc={"de": "Für diese Konten gilt die Passwortrichtlinie nicht – ein leeres Passwort ist erlaubt. Angreifer können "
                  "solche Konten ohne Passwort verwenden, falls eines gesetzt wurde, das leer ist.",
            "en": "The password policy does not apply to these accounts; an empty password is allowed."},
      fix={"de": "Flag entfernen und ein sicheres Passwort setzen.",
           "en": "Remove the flag and set a strong password."},
      code="Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=32)' |\n  ForEach-Object { Set-ADAccountControl $_ -PasswordNotRequired $false }",
      columns=["account", "type", "last_logon"])
def _pwd_not_required(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("enabled") and a["uac"] & UAC_PASSWD_NOTREQD]
    if not hits:
        return None
    return Hit([acc(a, type="@" + a["_kind"]) for a in hits])


@rule(id="S-ReversibleEncryption", category="stale", severity="high", points=15,
      title={"de": "Passwort mit umkehrbarer Verschlüsselung gespeichert", "en": "Password stored with reversible encryption"},
      desc={"de": "Für diese Konten wird das Passwort praktisch im Klartext in der AD-Datenbank abgelegt. Wer Zugriff auf "
                  "eine NTDS.dit-Kopie oder Replikationsrechte hat, erhält das Klartextpasswort.",
            "en": "Passwords for these accounts are stored in a decryptable form in the AD database."},
      fix={"de": "Option deaktivieren und anschließend das Passwort neu setzen (erst dann wird der alte Wert entfernt).",
           "en": "Disable the option and then reset the password."},
      code="Set-ADUser <Konto> -AllowReversiblePasswordEncryption $false\nSet-ADAccountPassword <Konto> -Reset",
      columns=["account", "pwd_last_set"],
      refs=[("MITRE ATT&CK T1003.006", f"{ATT}/T1003/006/")])
def _reversible(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("enabled") and a["uac"] & UAC_ENCRYPTED_TEXT_PWD_ALLOWED]
    return Hit([acc(a) for a in hits]) if hits else None


@rule(id="S-DesOnly", category="stale", severity="high", points=10,
      title={"de": "Kerberos nur mit DES", "en": "Kerberos DES-only accounts"},
      desc={"de": "DES ist kryptografisch gebrochen. Konten mit „Nur DES-Verschlüsselungstypen verwenden“ erzwingen "
                  "unsichere Kerberos-Tickets, die sich offline in kurzer Zeit knacken lassen.",
            "en": "DES is broken. Accounts set to 'use only DES encryption types' force weak Kerberos tickets."},
      fix={"de": "Flag entfernen und Passwort neu setzen, damit AES-Schlüssel erzeugt werden.",
           "en": "Remove the flag and reset the password so AES keys are generated."},
      code="Set-ADAccountControl <Konto> -UseDESKeyOnly $false",
      columns=["account", "last_logon"])
def _des_only(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("enabled") and a["uac"] & UAC_USE_DES_KEY_ONLY]
    return Hit([acc(a) for a in hits]) if hits else None


@rule(id="S-AsRepRoast", category="stale", severity="high", points=10,
      title={"de": "Kerberos-Vorauthentifizierung deaktiviert (AS-REP-Roasting)",
             "en": "Kerberos pre-authentication disabled (AS-REP roasting)"},
      desc={"de": "Für diese Konten kann jeder ohne Passwort ein verschlüsseltes Kerberos-Antwortpaket anfordern und das "
                  "Passwort anschließend offline per Brute Force ermitteln.",
            "en": "Anyone can request an encrypted Kerberos response for these accounts without a password and "
                  "crack it offline."},
      fix={"de": "„Keine Kerberos-Vorauthentifizierung erforderlich“ deaktivieren. Falls eine Altanwendung es benötigt: "
                 "sehr langes Zufallspasswort (25+ Zeichen) setzen.",
           "en": "Disable 'Do not require Kerberos preauthentication'. If a legacy app needs it, use a 25+ character random password."},
      code="Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' |\n  Set-ADAccountControl -DoesNotRequirePreAuth $false",
      columns=["account", "pwd_last_set", "last_logon"],
      refs=[("MITRE ATT&CK T1558.004", f"{ATT}/T1558/004/")])
def _asrep(ctx: Ctx):
    hits = [u for u in enabled_users(ctx) if u["uac"] & UAC_DONT_REQ_PREAUTH and not ctx.is_priv(u)]
    return Hit([acc(u) for u in hits]) if hits else None


@rule(id="S-Kerberoast", category="stale", severity="medium", points=5,
      title={"de": "Benutzerkonten mit SPN (Kerberoasting)", "en": "User accounts with SPN (Kerberoasting)"},
      desc={"de": "Jeder Domänenbenutzer kann für Benutzerkonten mit Service Principal Name ein Dienstticket anfordern und "
                  "das Passwort offline knacken. Besonders kritisch bei alten oder kurzen Passwörtern.",
            "en": "Any domain user can request service tickets for user accounts with an SPN and crack the password offline."},
      fix={"de": "Dienstkonten durch gMSA ersetzen oder Passwörter mit mindestens 25 Zeichen setzen und nur AES zulassen.",
           "en": "Replace with gMSA or use 25+ character passwords and allow AES only."},
      code="Get-ADUser -Filter 'ServicePrincipalName -like \"*\"' -Properties ServicePrincipalName, PasswordLastSet",
      columns=["account", "spn", "pwd_last_set"],
      refs=[("MITRE ATT&CK T1558.003", f"{ATT}/T1558/003/")])
def _kerberoast(ctx: Ctx):
    hits = [u for u in enabled_users(ctx) if u.get("spns") and not u.get("is_gmsa") and not ctx.is_priv(u)]
    if not hits:
        return None
    old = [u for u in hits if (ctx.age(u.get("pwd_last_set")) or 0) > 365 * 3]
    items = [acc(u, spn=", ".join(u["spns"][:2])) for u in hits]
    return Hit(items, points=10 if old else 5, severity="medium" if old else "low")


@rule(id="S-OS-Obsolete", category="stale", severity="high", points=15,
      title={"de": "Betriebssysteme ohne Herstellersupport", "en": "Operating systems out of support"},
      desc={"de": "Diese Systeme erhalten keine Sicherheitsupdates mehr (z. B. Windows 7/8, Server 2008/2012). Bekannte "
                  "Lücken bleiben dauerhaft offen und bieten einen einfachen Einstieg ins Netz.",
            "en": "These systems no longer receive security updates. Known vulnerabilities remain open."},
      fix={"de": "Systeme ersetzen oder aktualisieren. Wo das nicht sofort geht: isolieren (eigenes VLAN, Firewall) und "
                 "Anmeldung privilegierter Konten dort verhindern.",
           "en": "Replace or upgrade. Until then isolate them and prevent privileged logons."},
      columns=["account", "os", "last_logon"],
      refs=[("Microsoft Lifecycle", f"{MS}/lifecycle/products/")])
def _os_obsolete(ctx: Ctx):
    hits = [c for c in enabled_computers(ctx, include_dc=False)
            if classify_os(c.get("os"), c.get("os_version"), ctx.now) == "obsolete"]
    if not hits:
        return None
    active = [c for c in hits if not ctx.inactive(c, 45)]
    return Hit([acc(c, os=c.get("os")) for c in hits], points=15 if active else 5,
               severity="high" if active else "medium")


@rule(id="S-OS-Win10", category="stale", severity="medium", points=5,
      title={"de": "Windows 10 im Einsatz (Support endete am 14.10.2025)",
             "en": "Windows 10 in use (support ended 14 Oct 2025)"},
      desc={"de": "Windows 10 erhält ohne kostenpflichtiges ESU-Programm keine Sicherheitsupdates mehr.",
            "en": "Windows 10 receives no security updates without the paid ESU programme."},
      fix={"de": "Migration auf Windows 11 planen. Bis dahin ESU-Lizenzen prüfen und Geräte priorisiert umstellen.",
           "en": "Plan the migration to Windows 11; consider ESU until then."},
      columns=["account", "os", "last_logon"])
def _os_win10(ctx: Ctx):
    hits = [c for c in enabled_computers(ctx, include_dc=False)
            if classify_os(c.get("os"), c.get("os_version"), ctx.now) == "win10" and not ctx.inactive(c, ctx.cfg.inactive_days)]
    return Hit([acc(c, os=c.get("os")) for c in hits]) if hits else None


@rule(id="S-OS-Expiring", category="stale", severity="info", points=0,
      title={"de": "Windows Server 2016 – Support endet am 12.01.2027",
             "en": "Windows Server 2016 – support ends 12 Jan 2027"},
      desc={"de": "Diese Systeme (Windows Server 2016, Windows 10 Enterprise LTSC 2021) bekommen ab dem 13.01.2027 "
                  "keine Sicherheitsupdates mehr. Ab 90 Tagen vor dem Termin wird die Prüfung dringlicher, für "
                  "Domänencontroller besonders; nach dem Termin zählen die Systeme als „ohne Herstellersupport“.",
            "en": "These systems (Windows Server 2016, Windows 10 Enterprise LTSC 2021) receive no security updates "
                  "after 12 Jan 2027. From 90 days before, the finding becomes more urgent, especially for DCs; "
                  "afterwards they count as unsupported."},
      fix={"de": "Ablösung bzw. In-Place-Upgrade jetzt durchführen – Domänencontroller zuerst; wo das nicht rechtzeitig "
                 "geht, Extended Security Updates (ESU) prüfen.",
           "en": "Replace or upgrade now – domain controllers first; where that is not possible in time, consider "
                 "Extended Security Updates (ESU)."},
      columns=["account", "os", "last_logon"])
def _os_expiring(ctx: Ctx):
    hits = [c for c in enabled_computers(ctx)
            if classify_os(c.get("os"), c.get("os_version"), ctx.now) == "expiring"]
    if not hits:
        return None
    items = [acc(c, os=c.get("os")) for c in hits]
    from .adutil import EXPIRING_END
    if (EXPIRING_END - ctx.now).days > 90:
        return Hit(items)
    if any(c.get("is_dc") or c.get("is_rodc") for c in hits):
        return Hit(items, severity="medium", points=8, note=f"@n_days_left|{(EXPIRING_END - ctx.now).days}")
    return Hit(items, severity="low", points=3, note=f"@n_days_left|{(EXPIRING_END - ctx.now).days}")


@rule(id="S-SIDHistory", category="stale", severity="medium", points=5,
      title={"de": "Konten mit SID-Verlauf (sIDHistory)", "en": "Accounts with SID history"},
      desc={"de": "SID-Verlauf stammt meist aus Migrationen und verleiht die Rechte der alten SID weiter. Missbraucht "
                  "(insbesondere mit SIDs aus der eigenen Domäne) ist er ein unauffälliger Weg zu Admin-Rechten.",
            "en": "SID history usually stems from migrations and keeps granting the old SID's rights. Abused with "
                  "SIDs from the own domain it is a stealthy path to admin rights."},
      fix={"de": "Nach abgeschlossener Migration und Berechtigungsumstellung den SID-Verlauf entfernen.",
           "en": "Remove SID history once migration and ACL re-permissioning is complete."},
      code="Get-ADUser <Konto> -Properties SIDHistory |\n  ForEach-Object { Set-ADUser $_ -Remove @{SIDHistory=$_.SIDHistory.Value} }",
      columns=["account", "sid_history", "detail"],
      refs=[("MITRE ATT&CK T1134.005", f"{ATT}/T1134/005/")])
def _sid_history(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("sid_history")]
    if not hits:
        return None
    items, same = [], False
    for a in hits:
        own = [s for s in a["sid_history"] if sid_domain(s) in (ctx.domain_sid, ctx.root_sid)]
        same = same or bool(own)
        items.append({"account": a["sam"], "sid_history": ", ".join(a["sid_history"]),
                      "detail": "@v_own_domain" if own else "@v_foreign_domain"})
    return Hit(items, points=25 if same else 5, severity="critical" if same else "medium")


@rule(id="S-PrimaryGroup", category="stale", severity="medium", points=10,
      title={"de": "Ungewöhnliche primäre Gruppe (versteckte Mitgliedschaft)",
             "en": "Unusual primary group (hidden membership)"},
      desc={"de": "Mitgliedschaften über die primäre Gruppe erscheinen nicht im Attribut „member“ der Gruppe und werden "
                  "deshalb in vielen Werkzeugen übersehen. Ist z. B. „Domänen-Admins“ primäre Gruppe, ist das Konto "
                  "unauffällig Administrator.",
            "en": "Primary-group memberships do not show up in the group's 'member' attribute and are easily missed."},
      fix={"de": "Primäre Gruppe auf „Domänen-Benutzer“ (513) bzw. „Domänencomputer“ (515) zurücksetzen.",
           "en": "Reset the primary group to Domain Users (513) / Domain Computers (515)."},
      code="Set-ADUser <Konto> -Replace @{primaryGroupID=513}",
      columns=["account", "group", "type"])
def _primary_group(ctx: Ctx):
    items = []
    for u in ctx.users:
        if u.get("primary_gid") not in (None, 513, 514) and not u.get("is_gmsa") and u.get("rid") != 501:
            items.append({"account": u["sam"], "group": ctx.name(ctx.group_sid(u["primary_gid"])), "type": "@user"})
    for c in ctx.computers:
        if c.get("primary_gid") not in (None, 515, 516, 521):
            items.append({"account": c["sam"], "group": ctx.name(ctx.group_sid(c["primary_gid"])), "type": "@computer"})
    if not items:
        return None
    crit = any(a.get("primary_gid") in (512, 518, 519) for a in ctx.users + ctx.computers)
    return Hit(items, points=20 if crit else 10, severity="high" if crit else "medium")


@rule(id="S-UserPassword", category="stale", severity="medium", points=5,
      title={"de": "Attribut userPassword/unixUserPassword gesetzt", "en": "userPassword/unixUserPassword attribute set"},
      desc={"de": "Diese Attribute enthalten oft Passwörter in lesbarer oder schwach geschützter Form und sind je nach "
                  "Konfiguration für viele Benutzer lesbar.",
            "en": "These attributes often contain readable or weakly protected passwords."},
      fix={"de": "Attribute leeren und betroffene Passwörter ändern.", "en": "Clear the attributes and change the passwords."},
      code="Set-ADUser <Konto> -Clear userPassword, unixUserPassword",
      columns=["account", "last_logon"])
def _userpassword(ctx: Ctx):
    hits = [u for u in ctx.users if u.get("has_userpassword")]
    if not hits and unprivileged(ctx):
        raise NotApplicable("na_restricted")  # unixUserPassword is confidential
    return Hit([acc(u) for u in hits]) if hits else None


@rule(id="S-LAPS", category="stale", severity="medium", points=10,
      title={"de": "Lokale Administratorpasswörter nicht durch LAPS verwaltet",
             "en": "Local administrator passwords not managed by LAPS"},
      desc={"de": "Ohne LAPS haben lokale Administratoren oft auf vielen Rechnern dasselbe Passwort. Ein einziger "
                  "kompromittierter Rechner reicht dann für die Ausbreitung im ganzen Netz (Pass-the-Hash).",
            "en": "Without LAPS local admin passwords are often identical across machines, enabling lateral movement."},
      fix={"de": "Windows LAPS (in Windows 11/Server 2019+ integriert) per GPO aktivieren und Lesezugriff auf die "
                 "Passwörter auf wenige Gruppen beschränken.",
           "en": "Enable Windows LAPS via GPO and restrict who can read the passwords."},
      code="Update-LapsADSchema\nSet-LapsADComputerSelfPermission -Identity 'OU=Clients,DC=firma,DC=local'",
      columns=["account", "os", "last_logon"], platforms=("windows",),
      refs=[("Microsoft: Windows LAPS", f"{MS}/windows-server/identity/laps/laps-overview")])
def _laps(ctx: Ctx):
    cfg = ctx.m.get("config", {})
    targets = [c for c in enabled_computers(ctx, include_dc=False)
               if classify_os(c.get("os")) not in ("samba", "other", "unknown")
               and not ctx.inactive(c, ctx.cfg.inactive_days)]
    if not targets:
        return None
    if not (cfg.get("laps_legacy_schema") or cfg.get("laps_windows_schema")):
        # Windows LAPS can also back up to Entra ID (without AD schema) – not detectable from AD
        return Hit([acc(c, os=c.get("os")) for c in targets], points=10, severity="medium", note="@n_no_laps_schema")
    missing = [c for c in targets if not c.get("laps")]
    if not missing:
        return None
    share = pct(len(missing), len(targets))
    if len(missing) == len(targets) and unprivileged(ctx):
        return Hit([acc(c, os=c.get("os")) for c in missing], points=5, severity="low", note="@n_laps_unreadable")
    return Hit([acc(c, os=c.get("os")) for c in missing], points=10 if share > 20 else 5,
               severity="medium" if share > 20 else "low", note=f"{share:.0f} %")


@rule(id="S-AdminCountOrphan", category="stale", severity="low", points=2,
      title={"de": "Verwaiste adminCount-Markierung", "en": "Orphaned adminCount flag"},
      desc={"de": "Diese Konten waren früher privilegiert (adminCount=1), sind es aber nicht mehr. Die Vererbung von "
                  "Berechtigungen bleibt deaktiviert, wodurch z. B. Helpdesk-Delegierungen nicht greifen.",
            "en": "These accounts were privileged once (adminCount=1). Permission inheritance remains disabled."},
      fix={"de": "adminCount entfernen und Vererbung auf dem Objekt wieder aktivieren.",
           "en": "Clear adminCount and re-enable inheritance on the object."},
      code="Set-ADUser <Konto> -Clear adminCount\n# danach Vererbung im Reiter Sicherheit > Erweitert aktivieren",
      columns=["account", "last_logon"])
def _admincount(ctx: Ctx):
    hits = [u for u in ctx.users if u.get("admin_count") == 1 and not ctx.is_priv(u) and u.get("rid") not in (500, 502)]
    return Hit([acc(u) for u in hits]) if hits else None


# ===========================================================================
# PRIVILEGED ACCOUNTS
# ===========================================================================

def admin_item(ctx: Ctx, a: dict, **extra):
    return acc(a, group=", ".join(sorted(set(ctx.priv_map.get(a["dn"].lower(), [])))), **extra)


@rule(id="P-AdminCount", category="privileged", severity="medium", points=10,
      title={"de": "Zu viele Domänen-Administratoren", "en": "Too many domain administrators"},
      desc={"de": "Jedes Admin-Konto ist ein mögliches Ziel. Mehr als etwa 10 aktive Administratoren deuten darauf hin, "
                  "dass Admin-Rechte für Alltagsaufgaben vergeben wurden.",
            "en": "Every admin account is a target. More than about 10 active admins indicates rights used for daily tasks."},
      fix={"de": "Rechte nach dem Prinzip der minimalen Berechtigung delegieren (z. B. für Helpdesk-OU) und getrennte "
                 "Admin-Konten nur für Admin-Tätigkeiten nutzen (Tiering).",
           "en": "Delegate least-privilege rights and use dedicated admin accounts (tiering)."},
      columns=["account", "group", "last_logon"],
      refs=[("Microsoft: Enterprise Access Model", f"{MS}/security/privileged-access-workstations/privileged-access-access-model")])
def _admin_count(ctx: Ctx):
    admins = [a for a in ctx.admins if a.get("enabled") and a["_kind"] == "user"]
    if len(admins) <= 10:
        return None
    return Hit([admin_item(ctx, a) for a in admins], note=str(len(admins)))


@rule(id="P-SchemaEnterpriseAdmins", category="privileged", severity="medium", points=10,
      title={"de": "Schema- bzw. Organisations-Admins dauerhaft besetzt",
             "en": "Schema / Enterprise Admins permanently populated"},
      desc={"de": "Diese Gruppen werden nur für seltene Gesamtstruktur-Änderungen benötigt. Dauerhafte Mitglieder "
                  "vergrößern unnötig die Angriffsfläche.",
            "en": "These groups are only needed for rare forest-wide changes; permanent members increase exposure."},
      fix={"de": "Gruppen im Normalbetrieb leer halten und Mitglieder nur bei Bedarf und befristet aufnehmen.",
           "en": "Keep them empty and add members just-in-time."},
      code="Get-ADGroupMember 'Schema Admins' | ForEach-Object { Remove-ADGroupMember 'Schema Admins' $_ -WhatIf }",
      columns=["account", "group", "last_logon"])
def _schema_ea(ctx: Ctx):
    items = []
    for rid in (518, 519):
        g = ctx.group(rid)
        if not g:
            continue
        for a in ctx.members(g):
            if a.get("rid") == 500:
                continue                  # the built-in Administrator account is a member here by default
            items.append(acc(a, group=g.get("sam")))
    return Hit(items) if items else None


@rule(id="P-Operators", category="privileged", severity="medium", points=10,
      title={"de": "Mitglieder in Operator-Gruppen", "en": "Members in operator groups"},
      desc={"de": "Konten-, Server-, Druck- und Sicherungs-Operatoren können sich an DCs anmelden, Dienste ändern oder die "
                  "AD-Datenbank sichern und sind damit faktisch Domänen-Admins.",
            "en": "Account/Server/Print/Backup Operators can log on to DCs and effectively become domain admins."},
      fix={"de": "Gruppen leeren. Benötigte Rechte gezielt per Delegierung vergeben.",
           "en": "Empty the groups and delegate specific rights instead."},
      columns=["account", "group", "last_logon"])
def _operators(ctx: Ctx):
    items = []
    for rid in (548, 549, 550, 551):
        g = ctx.group(rid)
        if not g:
            continue
        for a in ctx.members(g):
            items.append(acc(a, group=g.get("sam")))
    return Hit(items) if items else None


@rule(id="P-KerberoastAdmin", category="privileged", severity="critical", points=30,
      title={"de": "Privilegierte Konten mit SPN (Kerberoasting)", "en": "Privileged accounts with SPN (Kerberoasting)"},
      desc={"de": "Jeder Domänenbenutzer kann für diese privilegierten Konten ein Ticket anfordern und das Passwort offline "
                  "knacken. Gelingt das, ist die Domäne übernommen.",
            "en": "Any domain user can request a ticket for these privileged accounts and crack the password offline."},
      fix={"de": "SPN vom privilegierten Konto entfernen und den Dienst unter einem gMSA ohne Admin-Rechte betreiben. "
                 "Sofort ein langes Zufallspasswort setzen.",
           "en": "Remove the SPN, run the service as a non-privileged gMSA and set a long random password immediately."},
      code="Set-ADUser <Konto> -ServicePrincipalNames @{Remove='MSSQLSvc/…'}",
      columns=["account", "group", "spn", "pwd_last_set"],
      refs=[("MITRE ATT&CK T1558.003", f"{ATT}/T1558/003/")])
def _kerberoast_admin(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("enabled") and u.get("spns") and not u.get("is_gmsa")
            and u.get("rid") != 502]
    return Hit([admin_item(ctx, u, spn=", ".join(u["spns"][:2])) for u in hits]) if hits else None


@rule(id="P-AsRepAdmin", category="privileged", severity="critical", points=30,
      title={"de": "Privilegierte Konten ohne Kerberos-Vorauthentifizierung",
             "en": "Privileged accounts without Kerberos pre-authentication"},
      desc={"de": "Für diese Admin-Konten kann jeder ohne Passwort angreifbares Material anfordern (AS-REP-Roasting).",
            "en": "Anyone can request crackable material for these admin accounts (AS-REP roasting)."},
      fix={"de": "Vorauthentifizierung sofort wieder aktivieren und Passwort ändern.",
           "en": "Re-enable pre-authentication immediately and change the password."},
      code="Set-ADAccountControl <Konto> -DoesNotRequirePreAuth $false",
      columns=["account", "group", "last_logon"])
def _asrep_admin(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("enabled") and u["uac"] & UAC_DONT_REQ_PREAUTH]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-AdminDelegatable", category="privileged", severity="medium", points=10,
      title={"de": "Admin-Konten nicht vor Delegierung geschützt", "en": "Admin accounts not protected against delegation"},
      desc={"de": "Meldet sich ein Admin an einem Server mit Delegierungsrechten an, kann dessen Ticket weiterverwendet "
                  "werden. Admin-Konten sollten als „vertraulich, kann nicht delegiert werden“ markiert oder Mitglied "
                  "von „Protected Users“ sein.",
            "en": "Admin tickets can be reused on servers with delegation rights. Mark admin accounts as sensitive or "
                  "add them to Protected Users."},
      fix={"de": "Option „Konto ist vertraulich und kann nicht delegiert werden“ setzen oder Konten in „Protected Users“ "
                 "aufnehmen (vorher Kompatibilität testen).",
           "en": "Set 'Account is sensitive and cannot be delegated' or add to Protected Users (test first)."},
      code="Get-ADGroupMember 'Domain Admins' -Recursive |\n  Set-ADAccountControl -AccountNotDelegated $true",
      columns=["account", "group", "last_logon"],
      refs=[("Microsoft: Protected Users", f"{MS}/windows-server/security/credentials-protection-and-management/protected-users-security-group")])
def _admin_delegatable(ctx: Ctx):
    pu = ctx.protected_users()
    hits = [u for u in ctx.admins if u["_kind"] == "user" and u.get("enabled") and not (u["uac"] & UAC_NOT_DELEGATED)
            and u["dn"].lower() not in pu]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-InactiveAdmin", category="privileged", severity="medium", points=10,
      title={"de": "Inaktive Admin-Konten", "en": "Inactive admin accounts"},
      desc={"de": "Privilegierte Konten, die lange nicht genutzt werden, werden offensichtlich nicht gebraucht, behalten "
                  "aber volle Rechte.",
            "en": "Privileged accounts that are not used keep full rights anyway."},
      fix={"de": "Aus den Admin-Gruppen entfernen und deaktivieren.", "en": "Remove from admin groups and disable."},
      columns=["account", "group", "last_logon"])
def _inactive_admin(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("enabled") and u.get("rid") not in (500,)
            and ctx.inactive(u, ctx.cfg.admin_inactive_days)]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-AdminPwdOld", category="privileged", severity="medium", points=10,
      title={"de": "Admin-Passwörter älter als 3 Jahre", "en": "Admin passwords older than 3 years"},
      desc={"de": "Alte Admin-Passwörter tauchen mit höherer Wahrscheinlichkeit in Leaks oder alten Skripten auf.",
            "en": "Old admin passwords are more likely to appear in leaks or old scripts."},
      fix={"de": "Passwörter ändern. Für Admins lange Passphrasen und idealerweise Smartcard/FIDO2 einsetzen.",
           "en": "Change the passwords; use passphrases and ideally smartcard/FIDO2."},
      columns=["account", "group", "pwd_last_set"])
def _admin_pwd_old(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("enabled") and (ctx.age(u.get("pwd_last_set")) or 0) > 3 * 365]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-BuiltinAdminUsed", category="privileged", severity="low", points=5,
      title={"de": "Eingebautes Administrator-Konto wird aktiv genutzt", "en": "Built-in Administrator account in active use"},
      desc={"de": "Das Konto mit RID 500 kann nicht gesperrt werden und ist allgemein bekannt. Es sollte nur als "
                  "Notfallkonto dienen.",
            "en": "The RID 500 account cannot be locked out and is well known; keep it for emergencies only."},
      fix={"de": "Persönliche Admin-Konten verwenden, das Passwort des Administrators sicher verwahren (Tresor).",
           "en": "Use personal admin accounts; vault the Administrator password."},
      columns=["account", "last_logon", "pwd_last_set"])
def _builtin_admin(ctx: Ctx):
    a = next((u for u in ctx.users if u.get("rid") == 500), None)
    if a and a.get("enabled") and a.get("last_logon") and (ctx.age(a["last_logon"]) or 999) < 35:
        return Hit([acc(a)])
    return None


def _acl_findings(ctx: Ctx, sd: dict | None, check_dcsync: bool):
    if not sd:
        return None
    safe = ctx.safe_sids()
    out: dict[str, set[str]] = {}
    for ace in sd.get("aces", []):
        if not ace.get("allow") or ace.get("flags", 0) & 0x08:  # INHERIT_ONLY
            continue
        sid = ace.get("sid")
        if not sid or sid in safe:
            continue
        rights = ace_grants_control(ace)
        if check_dcsync:
            ot = ace.get("object_type")
            m = ace.get("mask", 0)
            if (m & ADS_RIGHT_DS_CONTROL_ACCESS and (ot is None or ot == GUID_DS_REPL_GET_CHANGES_ALL)) or \
                    m & ADS_RIGHT_GENERIC_ALL:
                rights = rights + ["DCSync"]
        if rights:
            out.setdefault(sid, set()).update(rights)
    return out


@rule(id="P-DCSync", category="privileged", severity="critical", points=30,
      title={"de": "Replikationsrechte (DCSync) für Nicht-Standard-Konten", "en": "Replication rights (DCSync) for non-default principals"},
      desc={"de": "Mit „Replicating Directory Changes All“ lassen sich alle Passwort-Hashes der Domäne auslesen – "
                  "inklusive krbtgt. Diese Rechte sollten nur Domänencontroller besitzen. Ausnahme: das Konto von "
                  "Entra ID Connect (MSOL_…) benötigt sie, muss dann aber wie ein Tier-0-Konto geschützt werden.",
            "en": "'Replicating Directory Changes All' allows dumping every password hash including krbtgt. Only DCs "
                  "should hold it (Entra ID Connect's MSOL_ account is an exception and must be treated as Tier 0)."},
      fix={"de": "Rechte für nicht benötigte Konten auf dem Domänenobjekt entfernen (Eigenschaften > Sicherheit > "
                 "Erweitert).",
           "en": "Remove the rights from the domain object for principals that do not need them."},
      code="(Get-Acl \"AD:$((Get-ADDomain).DistinguishedName)\").Access |\n  Where-Object ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'",
      columns=["principal", "rights", "detail"],
      refs=[("MITRE ATT&CK T1003.006", f"{ATT}/T1003/006/")])
def _dcsync(ctx: Ctx):
    res = _acl_findings(ctx, (ctx.m.get("acl") or {}).get("domain_root"), True)
    if res is None:
        raise NotApplicable("na_acl")
    items, real = [], False
    for sid, rights in res.items():
        if "DCSync" not in rights:
            continue
        name = ctx.name(sid)
        is_sync = name.upper().startswith("MSOL_") or name.upper().startswith("AAD_")
        real = real or not is_sync
        items.append({"principal": name, "rights": "DCSync", "detail": "@v_entra_connect" if is_sync else ""})
    if not items:
        return None
    return Hit(items, points=30 if real else 5, severity="critical" if real else "low")


@rule(id="P-DomainRootACL", category="privileged", severity="critical", points=30,
      title={"de": "Gefährliche Schreibrechte auf dem Domänenobjekt", "en": "Dangerous write permissions on the domain object"},
      desc={"de": "Wer auf dem Domänenobjekt Vollzugriff, WriteDacl oder WriteOwner hat, kann sich selbst DCSync-Rechte "
                  "geben. Bekanntes Beispiel: „Exchange Windows Permissions“ aus älteren Exchange-Installationen.",
            "en": "GenericAll, WriteDacl or WriteOwner on the domain object allows granting yourself DCSync rights."},
      fix={"de": "Berechtigung entfernen. Bei Exchange: aktuelles CU installieren und /PrepareAD erneut ausführen bzw. "
                 "das Split-Permissions-Modell nutzen.",
           "en": "Remove the permission. For Exchange: apply the latest CU and re-run /PrepareAD."},
      columns=["principal", "rights"])
def _domain_root_acl(ctx: Ctx):
    res = _acl_findings(ctx, (ctx.m.get("acl") or {}).get("domain_root"), False)
    if res is None:
        raise NotApplicable("na_acl")
    # anyone already reported under DCSync (PRV-10) is not scored a second time here
    sync = {s for s, r in (_acl_findings(ctx, (ctx.m.get("acl") or {}).get("domain_root"), True) or {}).items()
            if "DCSync" in r}
    items = [{"principal": ctx.name(s), "rights": ", ".join(sorted(r))} for s, r in res.items() if s not in sync]
    return Hit(items) if items else None


@rule(id="P-AdminSDHolder", category="privileged", severity="critical", points=30,
      title={"de": "Manipulierte Berechtigungen auf AdminSDHolder", "en": "Tampered AdminSDHolder permissions"},
      desc={"de": "Die Rechte auf AdminSDHolder werden stündlich auf alle Admin-Konten und -Gruppen kopiert. Ein "
                  "zusätzlicher Eintrag ist eine klassische Hintertür für dauerhafte Admin-Rechte.",
            "en": "AdminSDHolder permissions are copied to all admin objects every hour – a classic persistence backdoor."},
      fix={"de": "Unerwartete Einträge entfernen und prüfen, wann und von wem sie gesetzt wurden (Ereignis 5136).",
           "en": "Remove unexpected entries and investigate (event 5136)."},
      columns=["principal", "rights"],
      refs=[("MITRE ATT&CK T1098", f"{ATT}/T1098/")])
def _adminsdholder(ctx: Ctx):
    res = _acl_findings(ctx, (ctx.m.get("acl") or {}).get("adminsdholder"), False)
    if res is None:
        raise NotApplicable("na_acl")
    items = [{"principal": ctx.name(s), "rights": ", ".join(sorted(r))} for s, r in res.items()]
    return Hit(items) if items else None


@rule(id="P-DnsAdmins", category="privileged", severity="medium", points=5,
      title={"de": "Mitglieder in DnsAdmins", "en": "Members in DnsAdmins"},
      desc={"de": "Mitglieder von DnsAdmins können auf DCs mit DNS-Rolle eine beliebige DLL in den DNS-Dienst (SYSTEM) "
                  "laden lassen.",
            "en": "DnsAdmins members can make the DNS service on DCs load an arbitrary DLL as SYSTEM."},
      fix={"de": "Gruppe leer halten und DNS-Verwaltung über delegierte Zonenrechte lösen.",
           "en": "Keep the group empty and delegate zone permissions instead."},
      columns=["account", "last_logon"], platforms=("windows",))
def _dnsadmins(ctx: Ctx):
    g = ctx.group_by_name("DnsAdmins")
    m = ctx.members(g)
    return Hit([acc(a) for a in m]) if m else None


@rule(id="P-UnconstrainedDelegation", category="privileged", severity="high", points=20,
      title={"de": "Uneingeschränkte Kerberos-Delegierung", "en": "Unconstrained Kerberos delegation"},
      desc={"de": "Ein System mit uneingeschränkter Delegierung speichert die TGTs aller Benutzer, die sich verbinden. "
                  "Wird es kompromittiert, lassen sich – etwa per erzwungener Authentifizierung eines DCs – "
                  "Domänen-Admin-Rechte erlangen.",
            "en": "Systems with unconstrained delegation store the TGTs of every connecting user; compromise leads to domain takeover."},
      fix={"de": "Auf eingeschränkte (constrained) oder ressourcenbasierte Delegierung umstellen.",
           "en": "Switch to constrained or resource-based delegation."},
      code="Get-ADComputer -Filter 'TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516'",
      columns=["account", "type", "os"],
      refs=[("MITRE ATT&CK T1558", f"{ATT}/T1558/")])
def _unconstrained(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("enabled") and a["uac"] & UAC_TRUSTED_FOR_DELEGATION
            and not (a.get("is_dc") or a.get("is_rodc"))]
    return Hit([{"account": a["sam"], "type": "@" + a["_kind"], "os": a.get("os", "")} for a in hits]) if hits else None


@rule(id="P-ConstrainedDelegation", category="privileged", severity="high", points=15,
      title={"de": "Riskante eingeschränkte Delegierung", "en": "Risky constrained delegation"},
      desc={"de": "Delegierung an Dienste auf Domänencontrollern (z. B. cifs/ldap) oder mit Protokollübergang erlaubt "
                  "es, sich gegenüber diesen Diensten als beliebiger Benutzer – auch als Admin – auszugeben.",
            "en": "Delegation to DC services or with protocol transition allows impersonating any user, including admins."},
      fix={"de": "Delegierungsziele auf Domänencontrollern entfernen. Protokollübergang nur, wo zwingend nötig.",
           "en": "Remove delegation targets on DCs; use protocol transition only where required."},
      columns=["account", "detail", "value"])
def _constrained(ctx: Ctx):
    items, crit = [], False
    for a in ctx.accounts:
        if not a.get("enabled") or a.get("is_dc"):
            continue
        targets = a.get("delegate_to") or []
        # service/host[:port][/service name] – e.g. ldap/dc01.firma.local/firma.local
        to_dc = [t for t in targets if len(t.split("/")) > 1 and t.split("/")[1].split(":", 1)[0].lower() in ctx.dc_names]
        pt = bool(a["uac"] & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
        if to_dc:
            crit = True
            items.append({"account": a["sam"], "detail": "→ DC" + (" + Protocol Transition" if pt else ""),
                          "value": ", ".join(to_dc)})
        elif pt and targets:
            items.append({"account": a["sam"], "detail": "Protocol Transition", "value": ", ".join(targets[:3])})
    if not items:
        return None
    return Hit(items, points=25 if crit else 5, severity="critical" if crit else "medium")


@rule(id="P-RBCD", category="privileged", severity="high", points=20,
      title={"de": "Ressourcenbasierte Delegierung auf kritischen Objekten",
             "en": "Resource-based delegation on critical objects"},
      desc={"de": "Ist msDS-AllowedToActOnBehalfOfOtherIdentity auf einem DC oder krbtgt gesetzt, kann das berechtigte "
                  "Konto Tickets als beliebiger Benutzer für diesen DC erhalten. Auf anderen Servern ist RBCD legitim, "
                  "sollte aber bekannt sein.",
            "en": "RBCD on a DC or krbtgt lets the allowed account impersonate any user to that DC."},
      fix={"de": "Attribut auf DCs/krbtgt leeren. Auf übrigen Systemen prüfen, ob die Konfiguration gewollt ist.",
           "en": "Clear the attribute on DCs/krbtgt; review it elsewhere."},
      code="Set-ADComputer <DC> -PrincipalsAllowedToDelegateToAccount $null",
      columns=["account", "detail"])
def _rbcd(ctx: Ctx):
    items, crit = [], False
    for a in ctx.accounts:
        if a.get("rbcd"):
            critical = a.get("is_dc") or a.get("rid") == 502
            crit = crit or critical
            items.append({"account": a["sam"], "detail": "@v_dc_krbtgt" if critical else "@v_server"})
    if not items:
        return None
    return Hit(items, points=25 if crit else 2, severity="critical" if crit else "info")


@rule(id="P-ProtectedUsersEmpty", category="privileged", severity="low", points=5,
      title={"de": "Gruppe „Protected Users“ wird nicht genutzt", "en": "'Protected Users' group not used"},
      desc={"de": "Mitglieder von Protected Users nutzen kein NTLM, keine schwachen Kerberos-Verfahren und keine "
                  "Delegierung; Anmeldedaten werden nicht zwischengespeichert. Ideal für Admin-Konten.",
            "en": "Protected Users members cannot use NTLM, weak Kerberos or delegation – ideal for admins."},
      fix={"de": "Admin-Konten schrittweise aufnehmen (nicht Dienstkonten oder Computerkonten).",
           "en": "Add admin accounts step by step (not service or computer accounts)."},
      code="Add-ADGroupMember 'Protected Users' -Members adm.mueller",
      columns=["detail"])
def _protected_users(ctx: Ctx):
    g = ctx.group(525)
    if not g:
        raise NotApplicable("na_no_group")
    return None if ctx.members(g) else Hit([{"detail": "0"}])


@rule(id="P-PreWin2000", category="privileged", severity="medium", points=10,
      title={"de": "„Prä-Windows 2000 kompatibler Zugriff“ zu weit gefasst",
             "en": "'Pre-Windows 2000 Compatible Access' too broad"},
      desc={"de": "Enthält die Gruppe „Jeder“, „Anonymous“ oder „Authentifizierte Benutzer“, können sehr viele "
                  "Konten (im schlimmsten Fall anonym) Benutzer- und Gruppendaten auslesen.",
            "en": "If the group contains Everyone, Anonymous or Authenticated Users, broad (even anonymous) read access is granted."},
      fix={"de": "Mitglieder entfernen; Authentifizierte Benutzer nur behalten, wenn Altsysteme es nachweislich brauchen.",
           "en": "Remove members; keep Authenticated Users only if legacy systems require it."},
      code="Remove-ADGroupMember 'Pre-Windows 2000 Compatible Access' -Members 'S-1-5-11'",
      columns=["principal"])
def _prewin2000(ctx: Ctx):
    g = ctx.group(554)
    if not g:
        raise NotApplicable("na_no_group")
    fsps = ctx.foreign_members(g)
    bad = [s for s in fsps if s in ("S-1-1-0", "S-1-5-7", "S-1-5-11")]
    if not bad:
        return None
    anon = any(s in ("S-1-1-0", "S-1-5-7") for s in bad)
    return Hit([{"principal": ctx.name(s)} for s in bad], points=15 if anon else 2,
               severity="high" if anon else "low")


# --- AD CS ------------------------------------------------------------------
AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0"}


def _lowpriv_enroll(ctx: Ctx, t: dict) -> list[str]:
    low = ctx.low_priv_sids()
    out = []
    for ace in (t.get("sd") or {}).get("aces", []):
        if not ace.get("allow") or ace.get("sid") not in low:
            continue
        m, ot = ace.get("mask", 0), ace.get("object_type")
        if m & ADS_RIGHT_GENERIC_ALL or (m & ADS_RIGHT_DS_CONTROL_ACCESS and ot in (None, GUID_CERT_ENROLL, GUID_CERT_AUTOENROLL)):
            out.append(ctx.name(ace["sid"]))
    return sorted(set(out))


@rule(id="P-ADCS-ESC1", category="privileged", severity="critical", points=30,
      title={"de": "Zertifikatvorlage erlaubt freie Wahl des Antragstellers (ESC1)",
             "en": "Certificate template allows arbitrary subject (ESC1)"},
      desc={"de": "Normale Benutzer dürfen ein Anmeldezertifikat beantragen und den Namen selbst angeben – z. B. den eines "
                  "Domänen-Admins. Damit ist eine sofortige Rechteausweitung möglich.",
            "en": "Low-privileged users can request an authentication certificate for any name, e.g. a domain admin."},
      fix={"de": "„Informationen werden in der Anforderung angegeben“ deaktivieren oder Genehmigung durch Zertifikats-"
                 "verwaltung erzwingen; Registrierungsrechte auf notwendige Gruppen beschränken.",
           "en": "Disable 'Supply in the request' or require manager approval; restrict enrollment rights."},
      columns=["template", "principal", "value"],
      refs=[("SpecterOps: Certified Pre-Owned", "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf")])
def _esc1(ctx: Ctx):
    items = []
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        if not t.get("published") or not (t.get("name_flag", 0) & 0x1):
            continue
        if t.get("enroll_flag", 0) & 0x2 or t.get("ra_signature", 0) > 0:
            continue
        ekus = set(t.get("ekus") or [])
        if ekus and not (ekus & AUTH_EKUS):
            continue
        who = _lowpriv_enroll(ctx, t)
        if who:
            items.append({"template": t["display"], "principal": ", ".join(who), "value": ", ".join(sorted(ekus)) or "@v_all"})
    return Hit(items) if items else None


@rule(id="P-ADCS-ESC4", category="privileged", severity="critical", points=25,
      title={"de": "Normale Benutzer dürfen Zertifikatvorlagen ändern (ESC4)",
             "en": "Low-privileged users can modify certificate templates (ESC4)"},
      desc={"de": "Mit Schreibrechten auf eine Vorlage lässt sich diese in eine ESC1-Vorlage umbauen.",
            "en": "Write access to a template allows turning it into an ESC1 template."},
      fix={"de": "Schreibrechte für Domänen-Benutzer/Authentifizierte Benutzer entfernen.",
           "en": "Remove write permissions for broad groups."},
      columns=["template", "principal", "rights"])
def _esc4(ctx: Ctx):
    items = []
    low = ctx.low_priv_sids()
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        for ace in (t.get("sd") or {}).get("aces", []):
            if ace.get("sid") in low:
                r = ace_grants_control(ace)
                if r:
                    items.append({"template": t["display"], "principal": ctx.name(ace["sid"]), "rights": ", ".join(r)})
    return Hit(items) if items else None


@rule(id="P-ADCS-ESC2", category="privileged", severity="high", points=15,
      title={"de": "Zertifikatvorlage für beliebige Zwecke (ESC2)", "en": "Any-purpose certificate template (ESC2)"},
      desc={"de": "Vorlagen ohne Verwendungszweck oder mit „Beliebiger Zweck“ lassen sich u. a. als Registrierungs-"
                  "Agent missbrauchen und so Zertifikate für andere Benutzer ausstellen.",
            "en": "Templates with no EKU or Any Purpose can be abused e.g. as enrollment agent."},
      fix={"de": "Konkrete Verwendungszwecke festlegen und Registrierungsrechte einschränken.",
           "en": "Define specific EKUs and restrict enrollment rights."},
      columns=["template", "principal"])
def _esc2(ctx: Ctx):
    items = []
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        if not t.get("published") or t.get("enroll_flag", 0) & 0x2 or t.get("ra_signature", 0) > 0:
            continue
        ekus = set(t.get("ekus") or [])
        if t.get("name_flag", 0) & 0x1:
            continue  # already ESC1
        if ekus and "2.5.29.37.0" not in ekus:
            continue
        who = _lowpriv_enroll(ctx, t)
        if who:
            items.append({"template": t["display"], "principal": ", ".join(who)})
    return Hit(items) if items else None


# ===========================================================================
# TRUSTS
# ===========================================================================
TRUST_DIR: dict[int | None, str] = {0: "@dir_0", 1: "@dir_1", 2: "@dir_2", 3: "@dir_3"}


def trust_item(t: dict, **extra):
    d = {"trust": t["name"], "direction": TRUST_DIR.get(t.get("direction"), str(t.get("direction"))),
         "changed": fmt_date(t.get("changed"))}
    d.update(extra)
    return d


@rule(id="T-SIDFiltering", category="trusts", severity="high", points=20,
      title={"de": "SID-Filterung auf Vertrauensstellung deaktiviert", "en": "SID filtering disabled on trust"},
      desc={"de": "Ohne SID-Filterung kann ein Administrator der vertrauten Domäne über manipulierten SID-Verlauf "
                  "Admin-Rechte in Ihrer Domäne erlangen.",
            "en": "Without SID filtering an admin in the trusted domain can gain admin rights here via forged SID history."},
      fix={"de": "SID-Filterung (Quarantäne) aktivieren, sofern keine Migration mit SID-Verlauf mehr läuft.",
           "en": "Enable SID filtering (quarantine) unless a SID-history migration is ongoing."},
      code="netdom trust firma.local /domain:partner-gmbh.example /quarantine:yes",
      columns=["trust", "direction", "detail"],
      refs=[("Microsoft: SID filtering", f"{MS}/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280")])
def _sid_filtering(ctx: Ctx):
    items = []
    for t in ctx.m.get("trusts", []):
        a = t.get("attributes", 0)
        if not (t.get("direction", 0) & 2) or a & 0x20:  # only where we trust; not within the forest
            continue
        if t.get("type") == 3:            # Kerberos realm (MIT): no SIDs, SID filtering irrelevant
            continue
        if a & 0x8:
            if a & 0x40:
                items.append(trust_item(t, detail="@v_forest_sidhistory"))
        elif not (a & 0x4):
            items.append(trust_item(t, detail="@v_external_noquarantine"))
    return Hit(items) if items else None


@rule(id="T-TGTDelegation", category="trusts", severity="high", points=15,
      title={"de": "TGT-Delegierung über Vertrauensstellung erlaubt", "en": "TGT delegation across trust enabled"},
      desc={"de": "Systeme mit uneingeschränkter Delegierung in der anderen Gesamtstruktur können TGTs Ihrer Benutzer "
                  "erhalten.",
            "en": "Unconstrained-delegation systems in the other forest can receive your users' TGTs."},
      fix={"de": "TGT-Delegierung auf der Vertrauensstellung deaktivieren.", "en": "Disable TGT delegation on the trust."},
      code="netdom trust firma.local /domain:<andere> /EnableTGTDelegation:No",
      columns=["trust", "direction"])
def _tgt_deleg(ctx: Ctx):
    items = [trust_item(t) for t in ctx.m.get("trusts", []) if t.get("attributes", 0) & 0x800]
    return Hit(items) if items else None


@rule(id="T-Inactive", category="trusts", severity="medium", points=10,
      title={"de": "Inaktive oder defekte Vertrauensstellung", "en": "Inactive or broken trust"},
      desc={"de": "Das Vertrauenspasswort wird alle 30 Tage erneuert. Eine länger unveränderte Vertrauensstellung "
                  "wird vermutlich nicht mehr genutzt oder ist defekt – bleibt aber ein potenzieller Zugangsweg.",
            "en": "Trust passwords rotate every 30 days. A trust unchanged for longer is likely unused or broken."},
      fix={"de": "Prüfen, ob die Vertrauensstellung noch benötigt wird; andernfalls entfernen.",
           "en": "Check if the trust is still needed, otherwise remove it."},
      code="Test-ComputerSecureChannel; netdom trust firma.local /domain:<andere> /verify",
      columns=["trust", "direction", "changed"])
def _trust_inactive(ctx: Ctx):
    items = [trust_item(t) for t in ctx.m.get("trusts", [])
             if not (t.get("attributes", 0) & 0x20) and t.get("type") != 3   # MIT realms do not rotate passwords
             and (ctx.age(t.get("changed")) or 0) > 45]
    return Hit(items) if items else None


@rule(id="T-Downlevel", category="trusts", severity="medium", points=10,
      title={"de": "Vertrauensstellung zu NT4/Downlevel-Domäne", "en": "Trust to NT4/downlevel domain"},
      desc={"de": "Downlevel-Vertrauensstellungen nutzen nur NTLM und unterstützen keine modernen Schutzmechanismen.",
            "en": "Downlevel trusts use NTLM only and lack modern protections."},
      fix={"de": "Vertrauensstellung entfernen oder Gegenseite modernisieren.", "en": "Remove or modernise."},
      columns=["trust", "direction"])
def _downlevel(ctx: Ctx):
    items = [trust_item(t) for t in ctx.m.get("trusts", []) if t.get("type") == 1]
    return Hit(items) if items else None


@rule(id="T-NoAES", category="trusts", severity="low", points=2,
      title={"de": "Vertrauensstellung ohne AES", "en": "Trust without AES"},
      desc={"de": "Ohne AES werden Kerberos-Tickets über die Vertrauensstellung mit RC4 verschlüsselt.",
            "en": "Without AES, inter-realm tickets use RC4."},
      fix={"de": "AES auf der Vertrauensstellung aktivieren (Eigenschaften > „Die andere Domäne unterstützt Kerberos-AES“).",
           "en": "Enable AES on the trust."},
      code="ksetup /setenctypeattr <andere-domäne> AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96",
      columns=["trust", "direction"])
def _trust_aes(ctx: Ctx):
    items = [trust_item(t) for t in ctx.m.get("trusts", [])
             if not (t.get("attributes", 0) & 0x20) and t.get("type") == 2 and not ((t.get("enc_types") or 0) & 0x18)]
    return Hit(items) if items else None


# ===========================================================================
# ANOMALIES
# ===========================================================================

def pol(ctx: Ctx) -> dict:
    return ctx.domain.get("policy") or {}


@rule(id="A-MinPwdLength", category="anomalies", severity="high", points=10,
      title={"de": "Zu kurze Mindest-Passwortlänge", "en": "Minimum password length too short"},
      desc={"de": "Kurze Passwörter lassen sich per Brute Force oder Spraying schnell erraten. Das BSI empfiehlt bei "
                  "komplexen Passwörtern mindestens 8–12 Zeichen, besser lange Passphrasen.",
            "en": "Short passwords are quickly guessed. Use at least 12 characters, ideally passphrases."},
      fix={"de": "In der Default Domain Policy die Mindestlänge auf mindestens 12 (Admins per PSO 15+) setzen.",
           "en": "Set the minimum length to at least 12 (15+ for admins via PSO)."},
      code="Set-ADDefaultDomainPasswordPolicy -Identity firma.local -MinPasswordLength 12",
      columns=["value", "recommended"],
      refs=[("BSI IT-Grundschutz ORP.4", "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html")])
def _min_len(ctx: Ctx):
    n = pol(ctx).get("min_length", 0) or 0
    if n >= 12:
        return None
    return Hit([{"value": str(n), "recommended": "≥ 12"}], points=10 if n < 8 else 2,
               severity="high" if n < 8 else "low")


@rule(id="A-NoLockout", category="anomalies", severity="medium", points=10,
      title={"de": "Keine Kontosperrung bei Fehlversuchen", "en": "No account lockout"},
      desc={"de": "Ohne Sperrschwelle können Angreifer unbegrenzt Passwörter durchprobieren.",
            "en": "Without a lockout threshold attackers can guess passwords indefinitely."},
      fix={"de": "Sperrschwelle z. B. 10 Fehlversuche, Dauer 15 Minuten.", "en": "E.g. threshold 10, duration 15 min."},
      code="Set-ADDefaultDomainPasswordPolicy -Identity firma.local -LockoutThreshold 10 `\n  -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00",
      columns=["value", "recommended"])
def _lockout(ctx: Ctx):
    n = pol(ctx).get("lockout_threshold", 0) or 0
    if n == 0:
        return Hit([{"value": "0", "recommended": "5–10"}])
    if n > 20:
        return Hit([{"value": str(n), "recommended": "5–10"}], points=2, severity="low")
    return None


@rule(id="A-NoComplexity", category="anomalies", severity="medium", points=5,
      title={"de": "Komplexitätsanforderungen deaktiviert", "en": "Complexity requirements disabled"},
      desc={"de": "Ohne Komplexität und ohne große Mindestlänge sind triviale Passwörter wie „sommer2026“ erlaubt.",
            "en": "Without complexity and a long minimum length trivial passwords are allowed."},
      fix={"de": "Komplexität aktivieren oder Mindestlänge ≥ 14 für Passphrasen festlegen.",
           "en": "Enable complexity or require ≥ 14 characters."},
      columns=["value"])
def _complexity(ctx: Ctx):
    p = pol(ctx)
    if p.get("complexity") or (p.get("min_length") or 0) >= 14:
        return None
    return Hit([{"value": "@v_off"}])


@rule(id="A-ReversiblePolicy", category="anomalies", severity="critical", points=20,
      title={"de": "Umkehrbare Verschlüsselung in der Passwortrichtlinie", "en": "Reversible encryption in password policy"},
      desc={"de": "Die Domänenrichtlinie speichert alle Passwörter in entschlüsselbarer Form.",
            "en": "The domain policy stores all passwords in decryptable form."},
      fix={"de": "Einstellung deaktivieren und Passwortwechsel für alle Konten erzwingen.",
           "en": "Disable it and force password changes."},
      columns=["value"])
def _rev_policy(ctx: Ctx):
    return Hit([{"value": "@v_on"}]) if pol(ctx).get("reversible") else None


@rule(id="A-WeakPSO", category="anomalies", severity="medium", points=5,
      title={"de": "Schwache Fine-Grained Password Policy (PSO)", "en": "Weak fine-grained password policy (PSO)"},
      desc={"de": "Eine PSO überschreibt die Domänenrichtlinie für die zugewiesenen Konten. Diese PSOs sind schwächer als "
                  "empfohlen.",
            "en": "These PSOs override the domain policy with weaker settings."},
      fix={"de": "PSO anpassen oder entfernen.", "en": "Adjust or remove the PSO."},
      columns=["value", "detail"])
def _pso(ctx: Ctx):
    if not ctx.m.get("psos") and unprivileged(ctx):
        raise NotApplicable("na_restricted")  # PSOs are only readable by admins
    items = []
    for p in ctx.m.get("psos", []):
        if (p.get("min_length") or 0) < 8 or p.get("reversible") or not p.get("lockout_threshold"):
            items.append({"value": p.get("name"),
                          "detail": f"min={p.get('min_length')}, lockout={p.get('lockout_threshold')}, reversible={p.get('reversible')}"})
    return Hit(items) if items else None


@rule(id="A-Krbtgt", category="anomalies", severity="medium", points=10,
      title={"de": "krbtgt-Passwort lange nicht geändert", "en": "krbtgt password not changed for a long time"},
      desc={"de": "Mit dem Hash von krbtgt lassen sich „Golden Tickets“ erstellen – gültig, bis das Passwort zweimal "
                  "geändert wurde. Ein seltener Wechsel verlängert das Zeitfenster nach einer Kompromittierung.",
            "en": "The krbtgt hash enables Golden Tickets until the password has been changed twice."},
      fix={"de": "Passwort zweimal ändern – mit mindestens 10 Stunden (max. Ticketlebensdauer) Abstand. Microsofts "
                 "New-KrbtgtKeys.ps1 unterstützt dabei; danach halbjährlich wiederholen.",
           "en": "Reset it twice, at least 10 hours apart (e.g. with New-KrbtgtKeys.ps1); repeat every six months."},
      code="# Microsoft-Skript New-KrbtgtKeys.ps1 (GitHub: microsoft/New-KrbtgtKeys.ps1)\n.\\New-KrbtgtKeys.ps1",
      columns=["account", "pwd_last_set", "days"],
      refs=[("MITRE ATT&CK T1558.001", f"{ATT}/T1558/001/")])
def _krbtgt(ctx: Ctx):
    ks = [u for u in ctx.users if u.get("rid") == 502 or u.get("sam", "").lower().startswith("krbtgt_")]
    items, worst = [], 0
    for k in ks:
        age = ctx.age(k.get("pwd_last_set"))
        if age is None or age <= ctx.cfg.krbtgt_max_days:
            continue
        worst = max(worst, age)
        items.append({"account": k["sam"], "pwd_last_set": fmt_date(k.get("pwd_last_set")), "days": str(age)})
    if not items:
        return None
    return Hit(items, points=20 if worst > 3 * 365 else 10, severity="high" if worst > 3 * 365 else "medium")


@rule(id="A-GuestEnabled", category="anomalies", severity="high", points=15,
      title={"de": "Gastkonto aktiviert", "en": "Guest account enabled"},
      desc={"de": "Das Gastkonto erlaubt Zugriff ohne individuelles Passwort und ist allgemein bekannt.",
            "en": "The guest account allows access without an individual password."},
      fix={"de": "Gastkonto deaktivieren.", "en": "Disable the guest account."},
      code="Disable-ADAccount -Identity Guest",
      columns=["account"])
def _guest(ctx: Ctx):
    g = next((u for u in ctx.users if u.get("rid") == 501), None)
    return Hit([{"account": g["sam"]}]) if g and g.get("enabled") else None


@rule(id="A-MachineAccountQuota", category="anomalies", severity="medium", points=10,
      title={"de": "Normale Benutzer dürfen Computer zur Domäne hinzufügen", "en": "Users can join computers to the domain"},
      desc={"de": "Standardmäßig darf jeder Benutzer 10 Computerkonten anlegen. Angreifer nutzen das für Angriffe "
                  "wie RBCD-Missbrauch, noPac oder Relay-Ketten.",
            "en": "By default every user may create 10 computer accounts, which is abused in RBCD, noPac or relay attacks."},
      fix={"de": "ms-DS-MachineAccountQuota auf 0 setzen und das Hinzufügen an eine Gruppe delegieren.",
           "en": "Set ms-DS-MachineAccountQuota to 0 and delegate domain joins."},
      code="Set-ADDomain -Identity firma.local -Replace @{'ms-DS-MachineAccountQuota'='0'}",
      columns=["value", "recommended"])
def _maq(ctx: Ctx):
    v = ctx.domain.get("maq")
    if v is None or v == 0:
        return None
    return Hit([{"value": str(v), "recommended": "0"}])


@rule(id="A-RecycleBin", category="anomalies", severity="low", points=5,
      title={"de": "AD-Papierkorb nicht aktiviert", "en": "AD Recycle Bin not enabled"},
      desc={"de": "Ohne Papierkorb lassen sich versehentlich oder böswillig gelöschte Objekte nur aufwendig aus der "
                  "Sicherung wiederherstellen.",
            "en": "Without the recycle bin deleted objects can only be restored from backup."},
      fix={"de": "Papierkorb aktivieren (nicht umkehrbar, Gesamtstruktur ≥ 2008 R2).",
           "en": "Enable the recycle bin (irreversible, forest level ≥ 2008 R2)."},
      code="Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target firma.local",
      columns=["value"], platforms=("windows",))
def _recycle(ctx: Ctx):
    v = (ctx.m.get("config") or {}).get("recycle_bin")
    if v is None:
        raise NotApplicable("na_unknown")
    return None if v else Hit([{"value": "@v_off"}])


LEVELS = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016", 10: "2025"}


@rule(id="A-FunctionalLevel", category="anomalies", severity="medium", points=10,
      title={"de": "Veraltete Domänen-/Gesamtstrukturfunktionsebene", "en": "Outdated domain/forest functional level"},
      desc={"de": "Moderne Schutzfunktionen (z. B. Protected Users mit vollem Umfang, Kerberos-Armoring, PAM) setzen eine "
                  "aktuelle Funktionsebene voraus. Alte Ebenen deuten zudem auf alte DCs hin.",
            "en": "Modern protections require a current functional level; old levels hint at old DCs."},
      fix={"de": "Alte DCs ablösen und Funktionsebene anheben (Windows: mind. 2016; Samba: höchste unterstützte Ebene, "
                 "z. B. per „samba-tool domain level raise“).",
           "en": "Retire old DCs and raise the level (Windows ≥ 2016; Samba: highest supported)."},
      code="Set-ADDomainMode -Identity firma.local -DomainMode Windows2016Domain\nSet-ADForestMode -Identity firma.local -ForestMode Windows2016Forest",
      columns=["detail", "value", "recommended"])
def _level(ctx: Ctx):
    items, worst = [], 99
    target = 4 if ctx.domain_type == "samba" else 7
    for label, v in (("@v_domain", ctx.domain.get("domain_level")), ("@v_forest", ctx.domain.get("forest_level"))):
        if v is None:
            continue
        if v < target:
            worst = min(worst, v)
            items.append({"detail": label, "value": LEVELS.get(v, str(v)), "recommended": LEVELS.get(target)})
    if not items:
        return None
    if worst < 4:
        return Hit(items, points=15, severity="high")
    if worst < 6 or ctx.domain_type == "samba":
        return Hit(items, points=10)
    return Hit(items, points=2, severity="low")


@rule(id="A-DC-OS", category="anomalies", severity="critical", points=25,
      title={"de": "Domänencontroller mit veraltetem Betriebssystem", "en": "Domain controllers with outdated OS"},
      desc={"de": "Ein DC ohne Sicherheitsupdates gefährdet die gesamte Domäne – eine Lücke dort bedeutet Vollzugriff.",
            "en": "A DC without security updates endangers the whole domain."},
      fix={"de": "Neuen DC mit aktuellem Server-Betriebssystem hinzufügen, FSMO-Rollen übertragen, alten DC herabstufen.",
           "en": "Add a new DC, transfer FSMO roles and demote the old one."},
      columns=["account", "os"])
def _dc_os(ctx: Ctx):
    items, crit = [], False
    for dc in ctx.dcs:
        cls = classify_os(dc.get("os"), dc.get("os_version"), ctx.now)
        if cls == "obsolete":
            crit = True
            items.append({"account": dc["sam"], "os": dc.get("os")})
        elif cls == "expiring":
            items.append({"account": dc["sam"], "os": dc.get("os")})
    if not items:
        return None
    return Hit(items, points=25 if crit else 5, severity="critical" if crit else "low")


@rule(id="A-SingleDC", category="anomalies", severity="medium", points=10,
      title={"de": "Nur ein Domänencontroller", "en": "Only one domain controller"},
      desc={"de": "Fällt der einzige DC aus oder wird beschädigt, steht die Anmeldung im ganzen Netz still.",
            "en": "If the only DC fails, authentication stops everywhere."},
      fix={"de": "Mindestens einen zweiten DC (möglichst an einem anderen Standort/Host) betreiben.",
           "en": "Run at least a second DC on different hardware."},
      columns=["value"])
def _single_dc(ctx: Ctx):
    rw = [d for d in ctx.dcs if not d.get("is_rodc") and d.get("enabled")]
    return Hit([{"value": str(len(rw))}]) if len(rw) == 1 else None


@rule(id="A-DCInactive", category="anomalies", severity="medium", points=10,
      title={"de": "Domänencontroller ohne aktuelle Anmeldung", "en": "Domain controller without recent logon"},
      desc={"de": "Ein DC-Konto ohne Aktivität seit über 45 Tagen gehört meist zu einem nicht sauber entfernten DC. "
                  "Das stört Replikation und Anmeldung.",
            "en": "A DC account inactive for 45+ days usually belongs to a DC that was not removed cleanly."},
      fix={"de": "Prüfen und ggf. Metadatenbereinigung durchführen (ntdsutil metadata cleanup).",
           "en": "Investigate and perform metadata cleanup if needed."},
      columns=["account", "last_logon"])
def _dc_inactive(ctx: Ctx):
    hits = [d for d in ctx.dcs if d.get("enabled") and ctx.inactive(d, 45)]
    return Hit([acc(d) for d in hits]) if hits else None


@rule(id="A-DCNotInOU", category="anomalies", severity="medium", points=5,
      title={"de": "Domänencontroller außerhalb der OU „Domain Controllers“", "en": "DC outside 'Domain Controllers' OU"},
      desc={"de": "DCs außerhalb dieser OU erhalten die Default Domain Controllers Policy nicht und haben daher oft "
                  "abweichende Sicherheitseinstellungen.",
            "en": "DCs outside this OU miss the Default Domain Controllers Policy."},
      fix={"de": "DC-Konto in die OU „Domain Controllers“ verschieben.", "en": "Move the DC to the Domain Controllers OU."},
      columns=["account", "dn"])
def _dc_ou(ctx: Ctx):
    hits = [d for d in ctx.dcs if ",ou=domain controllers," not in d["dn"].lower()]
    return Hit([{"account": d["sam"], "dn": d["dn"]} for d in hits]) if hits else None


@rule(id="A-GPPPassword", category="anomalies", severity="critical", points=30,
      title={"de": "Passwörter in Gruppenrichtlinien-Einstellungen (GPP)", "en": "Passwords in Group Policy Preferences (GPP)"},
      desc={"de": "Das Feld „cpassword“ ist mit einem öffentlich bekannten Schlüssel verschlüsselt. Jeder "
                  "Domänenbenutzer kann SYSVOL lesen und das Passwort entschlüsseln.",
            "en": "'cpassword' is encrypted with a publicly known key; any domain user can read and decrypt it."},
      fix={"de": "Einstellung aus der GPO entfernen, die XML-Datei löschen und das betroffene Passwort sofort ändern.",
           "en": "Remove the preference, delete the XML file and change the password immediately."},
      columns=["gpo", "file", "account"],
      refs=[("Microsoft MS14-025", f"{MS}/security-updates/securitybulletins/2014/ms14-025"),
            ("MITRE ATT&CK T1552.006", f"{ATT}/T1552/006/")])
def _gpp(ctx: Ctx):
    sv = need_sysvol(ctx)
    hits = sv.get("gpp_passwords") or []
    return Hit([{"gpo": h["gpo"], "file": h["file"], "account": h.get("accounts", "")} for h in hits]) if hits else None


@rule(id="A-LDAPSigning", category="anomalies", severity="medium", points=10,
      title={"de": "LDAP-Signierung auf DCs nicht erzwungen", "en": "LDAP signing not enforced on DCs"},
      desc={"de": "Ohne erzwungene Signierung sind NTLM-Relay-Angriffe auf LDAP möglich – etwa um Rechte zu ändern oder "
                  "Computerkonten anzulegen. (Erst Windows Server 2025 erzwingt dies standardmäßig.)",
            "en": "Without enforced signing NTLM relay attacks against LDAP are possible."},
      fix={"de": "In der Default Domain Controllers Policy „Domänencontroller: Signaturanforderungen für LDAP-Server“ "
                 "auf „Signatur erforderlich“ setzen. Vorher Ereignis 2889 auf unsignierte Clients prüfen.",
           "en": "Set 'Domain controller: LDAP server signing requirements' to 'Require signing' (check event 2889 first)."},
      columns=["value", "recommended"], platforms=("windows",),
      refs=[("Microsoft: LDAP signing", f"{MS}/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server")])
def _ldap_signing(ctx: Ctx):
    v = effective_dc_registry(ctx, r"NTDS\Parameters\LDAPServerIntegrity")
    if v == "2":
        return None
    return Hit([{"value": v if v is not None else "@v_not_configured", "recommended": "@v_required_2"}])


@rule(id="A-NTLMv1", category="anomalies", severity="high", points=15,
      title={"de": "NTLMv1/LM auf Domänencontrollern zugelassen", "en": "NTLMv1/LM allowed on domain controllers"},
      desc={"de": "NTLMv1-Antworten lassen sich in Minuten knacken und auf den NT-Hash zurückführen. "
                  "LmCompatibilityLevel sollte 5 sein („Nur NTLMv2-Antworten senden, LM & NTLM verweigern“). "
                  "Seit dem Windows-Update vom Oktober 2026 blockiert Windows NTLMv1-abgeleitete Anmeldungen für "
                  "Single Sign-on standardmäßig (BlockNtlmSSO) – Geräte, die noch NTLMv1 brauchen (z. B. WLAN/VPN mit "
                  "PEAP-MSCHAPv2), fallen dann ohnehin aus; die DC-Einstellung sollte dem folgen.",
            "en": "NTLMv1 responses can be cracked within minutes. LmCompatibilityLevel should be 5. Since the October "
                  "2026 update Windows blocks NTLMv1-derived SSO credentials by default (BlockNtlmSSO); the DC setting "
                  "should follow."},
      fix={"de": "„Netzwerksicherheit: LAN Manager-Authentifizierungsebene“ auf Stufe 5 setzen; vorher NTLMv1-Nutzung "
                 "über Ereignis 4624 (Paketname NTLM V1) prüfen. BlockNtlmSSO=0 nur als befristete Ausnahme nutzen.",
           "en": "Set LAN Manager authentication level to 5 after auditing NTLMv1 usage (event 4624). Use "
                 "BlockNtlmSSO=0 only as a temporary exception."},
      columns=["value", "recommended"], platforms=("windows",))
def _ntlmv1(ctx: Ctx):
    v = effective_dc_registry(ctx, r"Control\Lsa\LmCompatibilityLevel")
    # A DC only refuses NTLMv1 from level 5; below that (including the default 3) it accepts NTLMv1, below 3 even LM
    if v is None:
        return Hit([{"value": "@v_not_configured_3", "recommended": "5"}], points=8, severity="medium")
    try:
        n = int(v)
    except ValueError:
        return None
    if n >= 5:
        return None
    if n < 3:
        return Hit([{"value": v, "recommended": "5"}])
    return Hit([{"value": v, "recommended": "5"}], points=8, severity="medium")


@rule(id="A-SMBSigning", category="anomalies", severity="high", points=10,
      title={"de": "SMB-Signierung auf DCs deaktiviert", "en": "SMB signing disabled on DCs"},
      desc={"de": "Ohne SMB-Signierung sind Relay-Angriffe auf die Domänencontroller möglich.",
            "en": "Without SMB signing, relay attacks against DCs are possible."},
      fix={"de": "„Microsoft-Netzwerk (Server): Kommunikation digital signieren (immer)“ aktivieren.",
           "en": "Enable 'Microsoft network server: Digitally sign communications (always)'."},
      columns=["value", "recommended"], platforms=("windows",))
def _smb_signing(ctx: Ctx):
    v = effective_dc_registry(ctx, r"LanManServer\Parameters\RequireSecuritySignature")
    return Hit([{"value": v, "recommended": "1"}]) if v == "0" else None


@rule(id="A-AnonymousAccess", category="anomalies", severity="high", points=15,
      title={"de": "Anonymer LDAP-Zugriff erlaubt (dSHeuristics)", "en": "Anonymous LDAP access allowed (dSHeuristics)"},
      desc={"de": "Über dSHeuristics wurde anonymer Lesezugriff auf das Verzeichnis freigeschaltet.",
            "en": "dSHeuristics enables anonymous read access to the directory."},
      fix={"de": "Das 7. Zeichen von dSHeuristics wieder auf 0 setzen.", "en": "Reset the 7th character of dSHeuristics to 0."},
      columns=["value"], platforms=("windows",))
def _anon(ctx: Ctx):
    v = (ctx.m.get("config") or {}).get("dsheuristics") or ""
    return Hit([{"value": v}]) if len(v) >= 7 and v[6] == "2" else None


# Extended catalogue
from . import rules2  # noqa: E402,F401
from .ruleids import LEGACY_IDS  # noqa: E402

# Assign SAMAUDIT's own stable rule IDs (STL-01 …); the internal name is kept as legacy_id
for _r in RULES:
    _r.legacy_id = _r.id
    _r.id = LEGACY_IDS[_r.id]
RULE_ALIASES = {old: new for old, new in LEGACY_IDS.items()}


def canonical_id(rule_id: str) -> str:
    return RULE_ALIASES.get(rule_id, rule_id)
