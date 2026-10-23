# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Prüfkatalog Teil 3 (ab v1.9): Neuerungen 2025/2026 – Kerberos-RC4-Abschaltung, schwache
Zertifikatszuordnungen, ESC17, delegierte MSAs (BadSuccessor) und UPN/SPN-Missbrauch."""
from __future__ import annotations

import unicodedata

from .adutil import ADS_RIGHT_GENERIC_ALL
from .analysis import Ctx
from .rules import AUTH_EKUS, Hit, NotApplicable, _lowpriv_enroll, acc, rule
from .rules2 import ADS_RIGHT_DS_CREATE_CHILD, _cfg, as_num, gpo_values

MS = "https://learn.microsoft.com"
KB = "https://support.microsoft.com/kb"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ENC_RC4 = 0x4
ENC_AES = 0x18


# ===========================================================================
# VERALTETE OBJEKTE
# ===========================================================================

@rule(id="S-KerberosRC4", category="stale", severity="medium", points=8,
      title={"de": "Konten, die noch Kerberos-RC4 brauchen", "en": "Accounts still depending on Kerberos RC4"},
      desc={"de": "Seit den Updates vom April 2026 stellen Domänencontroller Tickets standardmäßig nur noch mit AES aus, "
                  "ab Juli 2026 ohne Rückweg (CVE-2026-20833). Betroffen sind Dienstkonten, deren Passwort so alt ist, "
                  "dass sie gar keine AES-Schlüssel besitzen (Passwort älter als die erste Windows-Server-2008-Härtung "
                  "der Domäne), sowie Konten, die per msDS-SupportedEncryptionTypes auf RC4 festgelegt sind. Solche "
                  "Dienste fallen aus – und RC4-Tickets lassen sich beim Kerberoasting besonders schnell knacken.",
            "en": "Since the April 2026 updates DCs issue AES-only tickets by default, without rollback from July 2026 "
                  "(CVE-2026-20833). Service accounts whose password predates AES keys, and accounts pinned to RC4 via "
                  "msDS-SupportedEncryptionTypes, will break – and RC4 tickets are easy to crack (Kerberoasting)."},
      fix={"de": "Passwort der Konten ohne AES-Schlüssel neu setzen (erzeugt AES-Schlüssel) und AES erlauben; auf RC4 "
                 "festgelegte Konten auf AES umstellen. Vorher im Systemprotokoll der DCs auf KDCSVC-Ereignisse 201–209 "
                 "achten. Wo RC4 vorübergehend unvermeidbar ist: gezielt 0x24 am Konto setzen, nicht domänenweit.",
           "en": "Reset the password of accounts without AES keys and allow AES; move RC4-pinned accounts to AES. Watch "
                 "KDCSVC events 201–209 on the DCs. If RC4 is unavoidable, set 0x24 on that account only."},
      code="Set-ADAccountPassword <Konto> -Reset   # erzeugt AES-Schlüssel\n"
           "Set-ADUser <Konto> -KerberosEncryptionType AES128,AES256\n"
           "Get-WinEvent -LogName System -FilterXPath \"*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-"
           "Distribution-Center'] and (EventID>=201 and EventID<=209)]]\"",
      columns=["account", "detail", "pwd_last_set"], platforms=("windows",),
      refs=[("Microsoft KB5073381 (CVE-2026-20833)", f"{KB}/5073381")])
def _rc4(ctx: Ctx):
    items = []
    rodc_group = ctx.group(521)          # entsteht mit der ersten 2008er-Schemaerweiterung → ab dann AES-Schlüssel
    aes_since = (rodc_group or {}).get("created")
    for a in ctx.accounts:
        if not a.get("enabled") and a.get("rid") != 502:
            continue
        enc = a.get("enc_types")
        if enc is not None and enc & ENC_RC4 and not enc & ENC_AES:
            items.append(acc(a, detail=f"@v_rc4_only|{hex(enc)}"))
            continue
        service = a.get("_kind") == "user" and not a.get("is_gmsa") and (a.get("spns") or a.get("rid") == 502)
        pls = a.get("pwd_last_set")
        if service and aes_since and pls and pls < aes_since:
            items.append(acc(a, detail="@v_no_aes_keys"))
    try:
        vals = gpo_values(ctx, ctx.gpo_guids("dc"), r"Services\Kdc\DefaultDomainSupportedEncTypes")
    except NotApplicable:
        vals = []
    for g, v in vals:
        n = as_num(v)
        if n is not None and n & ENC_RC4:
            items.append({"account": "KDC: DefaultDomainSupportedEncTypes", "detail": f"{hex(n)} ({ctx.gpo_name(g)})",
                          "pwd_last_set": ""})
    return Hit(items) if items else None


def _mapping_kind(v: str) -> str | None:
    """Schwache explizite Zuordnung in altSecurityIdentities? (KB5014754)"""
    s = v.strip().lower()
    if not s.startswith("x509:"):
        return None
    if "<sr>" in s or "<ski>" in s or "<sha1-pukey>" in s:
        return None                       # stark: Aussteller+Seriennummer, SKI, Schlüssel-Hash
    if "<rfc822>" in s:
        return "X509RFC822"
    if "<i>" in s and "<s>" in s:
        return "X509IssuerSubject"
    if "<s>" in s:
        return "X509SubjectOnly"
    return None


@rule(id="S-WeakCertMapping", category="stale", severity="medium", points=8,
      title={"de": "Schwache Zertifikatszuordnung (altSecurityIdentities)",
             "en": "Weak certificate mapping (altSecurityIdentities)"},
      desc={"de": "Diese Konten sind über Antragsteller, Aussteller+Antragsteller oder E-Mail-Adresse einem Zertifikat "
                  "zugeordnet. Solche Angaben lassen sich in einem selbst beantragten Zertifikat nachbilden – "
                  "Anmeldung als das Konto. Seit September 2025 erzwingen DCs die starke Zuordnung vollständig; "
                  "Anmeldungen mit diesen Zuordnungen schlagen dann fehl oder sind – auf ungepatchten DCs – angreifbar.",
            "en": "These accounts are mapped to certificates by subject, issuer+subject or e-mail. Such values can be "
                  "reproduced in a self-requested certificate. Since September 2025 DCs fully enforce strong mapping."},
      fix={"de": "Auf starke Zuordnung umstellen: X509:<I>Aussteller<SR>Seriennummer, <SKI> oder <SHA1-PUKEY>; "
                 "alternativ Zertifikate mit SID-Erweiterung neu ausstellen.",
           "en": "Use strong mappings (<I>…<SR>, <SKI>, <SHA1-PUKEY>) or reissue certificates with the SID extension."},
      code="Set-ADUser <Konto> -Replace @{altSecurityIdentities='X509:<I>DC=local,DC=firma,CN=FIRMA-CA<SR>1200000000AC11000000002B'}",
      columns=["account", "type", "value"],
      refs=[("Microsoft KB5014754", f"{KB}/5014754")])
def _weak_mapping(ctx: Ctx):
    items, admin = [], False
    for a in ctx.accounts:
        if not a.get("enabled"):
            continue
        for v in a.get("alt_sec_ids") or []:
            kind = _mapping_kind(v)
            if kind:
                items.append({"account": a["sam"], "type": kind, "value": v if len(v) <= 90 else v[:87] + "…"})
                admin = admin or ctx.is_priv(a)
    if not items:
        return None
    return Hit(items, severity="high", points=15) if admin else Hit(items)


# ===========================================================================
# PRIVILEGIERTE KONTEN
# ===========================================================================

@rule(id="P-ADCS-ESC17", category="privileged", severity="high", points=15,
      title={"de": "Serverzertifikat mit frei wählbarem Namen (ESC17)",
             "en": "Server certificate with arbitrary name (ESC17)"},
      desc={"de": "Normale Benutzer oder Computer dürfen ein Serverzertifikat (Serverauthentifizierung) für einen "
                  "beliebigen Namen beantragen. Damit lassen sich vertrauenswürdige HTTPS-Server vortäuschen – etwa der "
                  "WSUS-Server: Clients installieren dann untergeschobene „Updates“ mit SYSTEM-Rechten. Vorgestellt "
                  "auf der TROOPERS 2026; die ESC1-Prüfung erfasst das nicht, da keine Clientauthentifizierung nötig ist.",
            "en": "Low-privileged principals can request a server authentication certificate for any name, e.g. to "
                  "impersonate the HTTPS WSUS server and push malicious updates (TROOPERS 2026)."},
      fix={"de": "„Informationen werden in der Anforderung angegeben“ nur für eng begrenzte Gruppen erlauben oder "
                 "Genehmigung durch die Zertifikatsverwaltung erzwingen; Registrierungsrechte einschränken. "
                 "Allein den Verwendungszweck einzuschränken reicht nicht.",
           "en": "Restrict 'Supply in the request' and enrollment rights or require manager approval."},
      columns=["template", "principal", "detail"],
      refs=[("TROOPERS26: ESC17", "https://troopers.de/downloads/troopers26/TR26_ESC17_WDATRC.pdf")])
def _esc17(ctx: Ctx):
    try:
        wsus_https = [v for _, v in gpo_values(ctx, ctx.gpo_guids("all"), r"WindowsUpdate\WUServer")
                      if str(v).lower().startswith("https://")]
    except NotApplicable:
        wsus_https = []
    items = []
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        if not t.get("published") or not (t.get("name_flag", 0) & 0x1):
            continue
        if t.get("enroll_flag", 0) & 0x2 or t.get("ra_signature", 0) > 0:
            continue
        ekus = set(t.get("ekus") or [])
        if SERVER_AUTH not in ekus or ekus & AUTH_EKUS:
            continue                      # mit Clientauthentifizierung bereits ESC1
        who = _lowpriv_enroll(ctx, t)
        if who:
            items.append({"template": t["display"], "principal": ", ".join(who),
                          "detail": "@v_wsus_https" if wsus_https else "@v_server_auth"})
    if not items:
        return None
    return Hit(items) if wsus_https else Hit(items, severity="medium", points=8)


@rule(id="P-dMSA", category="privileged", severity="high", points=15,
      title={"de": "Delegierte Dienstkonten (dMSA) missbrauchbar", "en": "Delegated managed service accounts (dMSA) abusable"},
      desc={"de": "Mit Windows Server 2025 kamen delegierte Dienstkonten (dMSA). Wer in einer OU dMSAs anlegen darf, "
                  "konnte darüber die Rechte jedes Kontos übernehmen („BadSuccessor“). Der Patch vom August 2025 "
                  "(CVE-2025-53779) erschwert das; mit Schreibrechten auf das Zielkonto lassen sich dessen Schlüssel "
                  "aber weiterhin abgreifen. Bestehende dMSAs, die auf privilegierte Konten verweisen, sind besonders "
                  "kritisch.",
            "en": "With Windows Server 2025, anyone who may create dMSAs in an OU could take over any account "
                  "(BadSuccessor). The August 2025 patch (CVE-2025-53779) limits this, but keys can still be obtained "
                  "with write access to the target. dMSAs linked to privileged accounts are critical."},
      fix={"de": "DCs mit Windows Server 2025 aktuell halten; das Recht „Untergeordnete Objekte erstellen“ (alle Klassen "
                 "oder msDS-DelegatedManagedServiceAccount) auf OUs nur Tier-0-Administratoren geben; unerwartete "
                 "dMSA-Verknüpfungen (msDS-ManagedAccountPrecededByLink) entfernen und Änderungen daran überwachen.",
           "en": "Patch Windows Server 2025 DCs; grant 'Create child objects' on OUs to Tier 0 only; remove unexpected "
                 "dMSA links (msDS-ManagedAccountPrecededByLink) and audit changes to them."},
      code="Get-ADServiceAccount -Filter * -Properties msDS-ManagedAccountPrecededByLink |\n"
           "  Where-Object 'msDS-ManagedAccountPrecededByLink' | Select Name, msDS-ManagedAccountPrecededByLink",
      columns=["principal", "dn", "detail"], platforms=("windows",),
      refs=[("Akamai: BadSuccessor", "https://www.akamai.com/blog/security-research/2025/aug/badsuccessor-is-dead-analyzing-badsuccessor-patch"),
            ("CVE-2025-53779", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779")])
def _dmsa(ctx: Ctx):
    d = _cfg(ctx).get("dmsa")
    if d is None:
        raise NotApplicable("na_unknown")
    if not d.get("schema"):
        return None
    if not any("2025" in (c.get("os") or "") for c in ctx.computers if c.get("is_dc") or c.get("is_rodc")):
        return None                       # ohne DC mit Windows Server 2025 gibt es keinen dMSA-Mechanismus
    excluded = ctx.safe_sids() | {pg["group"].get("sid") for pg in ctx.priv_groups if pg.get("admin")}
    guid = (d.get("guid") or "").lower()
    found: dict[str, list[str]] = {}
    for c in d.get("containers", []):
        for ace in (c.get("sd") or {}).get("aces", []):
            sid = ace.get("sid")
            if not ace.get("allow") or ace.get("flags", 0) & 0x08 or not sid or sid in excluded:
                continue
            if ace.get("inherited_object_type"):
                continue                  # gilt nur für bestimmte untergeordnete Klassen
            m, ot = ace.get("mask", 0), (ace.get("object_type") or "").lower()
            if m & ADS_RIGHT_GENERIC_ALL or (m & ADS_RIGHT_DS_CREATE_CHILD and ot in ("", guid)):
                found.setdefault(sid, []).append(c["dn"])
    items = []
    for sid, dns in found.items():
        dns = sorted(set(dns), key=len)
        items.append({"principal": ctx.name(sid), "dn": dns[0], "detail": f"@v_dmsa_create|{len(dns)}"})
    critical = False
    for a in d.get("accounts", []):
        for tdn in a.get("preceded_by") or []:
            target = ctx.by_dn.get(tdn.lower())
            if target is None or not target.get("enabled"):
                continue
            priv = ctx.is_priv(target) or target.get("rid") in (500, 502)
            critical = critical or priv
            items.append({"principal": a["sam"], "dn": tdn, "detail": "@v_dmsa_link_priv" if priv else "@v_dmsa_link"})
    if not items:
        return None
    return Hit(items, severity="critical", points=25) if critical else Hit(items)


# ===========================================================================
# ANOMALIEN
# ===========================================================================

def _invisible(ch: str) -> bool:
    cat = unicodedata.category(ch)
    return cat in ("Cf", "Cc", "Co", "Cn", "Zl", "Zp") or (cat == "Zs" and ch != " ")


def _show(s: str) -> str:
    return "".join(f"<U+{ord(ch):04X}>" if _invisible(ch) else ch for ch in s)


def _norm(s: str) -> str:
    return unicodedata.normalize("NFKC", "".join(ch for ch in s if not _invisible(ch))).casefold()


@rule(id="A-UPNSPNUniqueness", category="anomalies", severity="high", points=15,
      title={"de": "Manipulierbare Anmeldenamen (UPN/SPN)", "en": "Manipulable logon names (UPN/SPN)"},
      desc={"de": "Prüft auf Spuren und Voraussetzungen der 2026 veröffentlichten Angriffe „KerberLoss“ "
                  "(CVE-2026-25177) und „ResetNightmare“ (CVE-2026-27912): unsichtbare Unicode-Zeichen in UPNs oder "
                  "SPNs (umgehen die Eindeutigkeitsprüfung, ermöglichen SPN-Übernahme und NTLM-Rückfall), UPNs, die dem "
                  "Anmeldenamen eines anderen Kontos entsprechen (Passwort-Reset fremder Konten bis zur Domänenübernahme), "
                  "doppelte Namen sowie eine per dSHeuristics abgeschaltete Eindeutigkeitsprüfung.",
            "en": "Looks for traces and preconditions of 'KerberLoss' (CVE-2026-25177) and 'ResetNightmare' "
                  "(CVE-2026-27912): invisible Unicode characters in UPNs/SPNs, UPNs equal to another account's logon "
                  "name, duplicate names and uniqueness checks disabled via dSHeuristics."},
      fix={"de": "Alle DCs mit den Updates ab April 2026 versorgen; betroffene UPNs/SPNs bereinigen; Eindeutigkeits"
                 "prüfung wieder aktivieren (21. Zeichen von dSHeuristics auf 0); Schreibrechte auf "
                 "servicePrincipalName/userPrincipalName für Nicht-Administratoren entfernen.",
           "en": "Patch all DCs (April 2026 or later), clean up the affected UPNs/SPNs, re-enable uniqueness checks "
                 "(21st character of dSHeuristics = 0) and remove SPN/UPN write rights from non-admins."},
      code="setspn -X -F            # doppelte SPNs in der Gesamtstruktur\n"
           "Set-ADUser <Konto> -UserPrincipalName '<name>@<domäne>'",
      columns=["account", "detail", "value"],
      refs=[("Semperis: KerberLoss & ResetNightmare",
             "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"),
            ("Microsoft KB5008382", f"{KB}/5008382")])
def _uniqueness(ctx: Ctx):
    items, serious = [], False
    dsh = _cfg(ctx).get("dsheuristics") or ""
    if len(dsh) >= 21 and dsh[20] in "123":
        items.append({"account": "dSHeuristics", "detail": f"@v_uniq_off_{dsh[20]}", "value": dsh})
    sams = {(a.get("sam") or "").lower(): a for a in ctx.accounts if a.get("sam")}
    seen: dict[tuple[str, str], tuple[set[str], str]] = {}
    for a in ctx.accounts:
        names = [("UPN", a["upn"])] if a.get("upn") else []
        names += [("SPN", s) for s in a.get("spns") or []]
        for kind, v in names:
            if any(_invisible(ch) for ch in v):
                items.append({"account": a["sam"], "detail": f"@v_invisible|{kind}", "value": _show(v)})
                serious = True
            seen.setdefault((kind, _norm(v)), (set(), v))[0].add(a["sam"])
        upn = (a.get("upn") or "").lower()
        if not upn:
            continue
        other = sams.get(upn)
        if other is None and "@" in upn:
            o = sams.get(upn.split("@", 1)[0])
            if o is not None and (ctx.is_priv(o) or o.get("rid") in (500, 502)):
                other = o
        if other is not None and other is not a:
            items.append({"account": a["sam"], "detail": f"@v_upn_is_sam|{other['sam']}", "value": a["upn"]})
            serious = True
    for (kind, _), (owners, v) in seen.items():
        if len(owners) > 1:
            items.append({"account": ", ".join(sorted(owners)), "detail": f"@v_duplicate|{kind}", "value": _show(v)})
            serious = True
    if not items:
        return None
    return Hit(items) if serious else Hit(items, severity="medium", points=8)
