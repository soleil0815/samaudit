# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Prüfkatalog Teil 4 (ab v2.1): ESC13, Golden gMSA/dMSA, gMSA-Kennwortleser, Certighost (CVE-2026-54121)
und Gruppenrichtlinien, die den Anmeldeschutz lockern."""
from __future__ import annotations

from .adutil import ADS_RIGHT_GENERIC_ALL
from .analysis import Ctx
from .rules import AUTH_EKUS, Hit, NotApplicable, _lowpriv_enroll, rule
from .rules2 import _cfg, as_num, gpo_values

MS = "https://learn.microsoft.com"
ADS_RIGHT_DS_READ_PROP = 0x00000010
GENERIC_READ = 0x80000000
INHERIT_ONLY = 0x08
CONTAINER_INHERIT = 0x02
OBJECT_INHERIT = 0x01
UNIVERSAL_GROUP = 0x8


def _pki(ctx: Ctx) -> dict:
    return ctx.m.get("pki") or {}


# ===========================================================================
# PRIVILEGIERTE KONTEN
# ===========================================================================

@rule(id="P-ADCS-ESC13", category="privileged", severity="high", points=15,
      title={"de": "Zertifikatvorlage verleiht Gruppenrechte (ESC13)",
             "en": "Certificate template grants group rights (ESC13)"},
      desc={"de": "Die Ausstellungsrichtlinie dieser Vorlage ist mit einer AD-Gruppe verknüpft (msDS-OIDToGroupLink). "
                  "Wer sich mit einem solchen Zertifikat anmeldet, erhält die Rechte der Gruppe – ohne Mitglied zu sein "
                  "und ohne dass es in der Gruppe sichtbar wird. Dürfen normale Benutzer oder Computer das Zertifikat "
                  "beantragen, haben sie damit dauerhaft diese Gruppenrechte.",
            "en": "The template's issuance policy is linked to an AD group (msDS-OIDToGroupLink). Logging on with such a "
                  "certificate grants the group's rights without membership. If low-privileged users or computers may "
                  "enroll, they effectively hold these rights."},
      fix={"de": "Registrierungsrechte der Vorlage auf die Personen beschränken, die die Gruppenrechte wirklich "
                 "brauchen, oder die Verknüpfung entfernen; Ausstellung zusätzlich an eine Genehmigung binden.",
           "en": "Restrict enrollment to the people who really need the group rights or remove the link; require "
                 "manager approval."},
      code="Get-ADObject -SearchBase \"CN=OID,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)\" "
           "-LDAPFilter '(msDS-OIDToGroupLink=*)' -Properties msDS-OIDToGroupLink,msPKI-Cert-Template-OID",
      columns=["template", "principal", "group"], platforms=("windows",),
      refs=[("SpecterOps: ESC13", "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53")])
def _esc13(ctx: Ctx):
    links = {(o.get("oid") or "").strip(): o for o in _pki(ctx).get("oids", []) if o.get("group")}
    if not links:
        return None
    items, critical = [], False
    for t in _pki(ctx).get("templates", []):
        if not t.get("published") or t.get("enroll_flag", 0) & 0x2 or t.get("ra_signature", 0) > 0:
            continue
        ekus = set(t.get("ekus") or [])
        if ekus and not ekus & AUTH_EKUS:
            continue                          # ohne Anmeldezweck keine Kerberos-Anmeldung
        groups = [links[p] for p in t.get("policies") or [] if p in links]
        if not groups:
            continue
        who = _lowpriv_enroll(ctx, t)
        if not who:
            continue
        for o in groups:
            g = ctx.by_dn.get((o["group"] or "").lower())
            priv = bool(g) and (g["dn"].lower() in ctx.priv_map or
                                any(pg["group"]["dn"].lower() == g["dn"].lower() for pg in ctx.priv_groups))
            critical = critical or priv
            items.append({"template": t["display"], "principal": ", ".join(who),
                          "group": (g or {}).get("sam") or o["group"]})
    if not items:
        return None
    return Hit(items, severity="critical", points=25) if critical else Hit(items)


def _reads(ace: dict, attr_guid: str | None) -> bool:
    m, ot = ace.get("mask", 0), (ace.get("object_type") or "").lower()
    if m & ADS_RIGHT_GENERIC_ALL or m & GENERIC_READ:
        return True
    return bool(m & ADS_RIGHT_DS_READ_PROP) and (not ot or (attr_guid and ot == attr_guid.lower()))


@rule(id="P-KDSRootKey", category="privileged", severity="critical", points=25,
      title={"de": "Hauptschlüssel der verwalteten Dienstkonten lesbar (Golden gMSA/dMSA)",
             "en": "Managed service account root key readable (Golden gMSA/dMSA)"},
      desc={"de": "Aus dem KDS-Stammschlüssel berechnen Domänencontroller die Kennwörter aller gMSA und dMSA. Wer ihn "
                  "lesen kann, kann jedes dieser Kennwörter jederzeit offline ausrechnen – auch künftige. Der Schlüssel "
                  "lässt sich nicht erneuern; standardmäßig dürfen ihn nur Domänen-/Organisations-Admins und DCs lesen.",
            "en": "Domain controllers derive the passwords of all gMSAs and dMSAs from the KDS root key. Whoever can "
                  "read it can compute every such password offline, forever. The key cannot be rotated; by default "
                  "only Domain/Enterprise Admins and DCs may read it."},
      fix={"de": "Die zusätzlichen Leserechte sofort entfernen. Da ein gelesener Schlüssel nicht erneuert werden kann: "
                 "einen neuen KDS-Stammschlüssel anlegen, die gMSA/dMSA neu erstellen und die alten löschen. "
                 "Lesezugriffe per Überwachung (Ereignis 4662, Objekttyp msKds-ProvRootKey) melden lassen.",
           "en": "Remove the extra read rights immediately. A read key cannot be rotated: create a new KDS root key, "
                 "recreate the gMSAs/dMSAs and delete the old ones. Audit reads (event 4662, msKds-ProvRootKey)."},
      code="Get-ADObject -SearchBase \"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,"
           "$((Get-ADRootDSE).configurationNamingContext)\" -Filter * -Properties nTSecurityDescriptor |\n"
           "  ForEach-Object { $_.nTSecurityDescriptor.Access } | Format-Table IdentityReference, ActiveDirectoryRights",
      columns=["principal", "dn", "detail"], platforms=("windows",),
      refs=[("Semperis: Golden gMSA", "https://www.semperis.com/blog/golden-GMSA-attack/"),
            ("Semperis: Golden dMSA", "https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/")])
def _kds(ctx: Ctx):
    k = _cfg(ctx).get("kds")
    if k is None:
        raise NotApplicable("na_unknown")
    if not k.get("present"):
        return None                           # kein KDS-Stammschlüssel → keine gMSA/dMSA
    items = []
    if k.get("readable"):
        # SAMAUDIT läuft mit einem normalen Konto – kann es den Schlüssel lesen, können es viele
        items.append({"principal": "@v_kds_auditor", "dn": k.get("dn") or "", "detail": "@v_kds_readable"})
    safe = ctx.safe_sids()
    guid = k.get("attr_guid")
    found: dict[str, set[str]] = {}
    for ace in ((k.get("container_sd") or {}).get("aces") or []):
        if (ace.get("allow") and ace.get("sid") not in safe and ace.get("flags", 0) & (CONTAINER_INHERIT | OBJECT_INHERIT)
                and _reads(ace, guid)):
            found.setdefault(ace["sid"], set()).add(k.get("dn") or "")
    for key in k.get("keys") or []:
        for ace in ((key.get("sd") or {}).get("aces") or []):
            if ace.get("allow") and ace.get("sid") not in safe and not ace.get("flags", 0) & INHERIT_ONLY \
                    and _reads(ace, guid):
                found.setdefault(ace["sid"], set()).add(key.get("dn") or "")
    for sid, dns in found.items():
        items.append({"principal": ctx.name(sid), "dn": sorted(dns)[0], "detail": f"@v_kds_ace|{len(dns)}"})
    return Hit(items) if items else None


BROAD_RIDS = (513, 514, 515)
BROAD_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545", "S-1-5-32-546"}


@rule(id="P-GMSAReaders", category="privileged", severity="medium", points=8,
      title={"de": "gMSA-Kennwort für zu viele abrufbar", "en": "gMSA password retrievable by too many"},
      desc={"de": "Wer in msDS-GroupMSAMembership eingetragen ist, darf das aktuelle Kennwort des gruppenverwalteten "
                  "Dienstkontos abrufen und sich damit als das Dienstkonto anmelden. Stehen dort breite Gruppen wie "
                  "„Domänen-Benutzer“ oder „Domänencomputer“, kann das praktisch jeder; bei privilegierten "
                  "Dienstkonten genügt schon ein einziger normaler Berechtigter für eine Rechteausweitung.",
            "en": "Principals listed in msDS-GroupMSAMembership may retrieve the gMSA's current password and log on as "
                  "it. Broad groups such as Domain Users or Domain Computers mean practically anyone; for privileged "
                  "gMSAs a single ordinary principal is enough for privilege escalation."},
      fix={"de": "Nur die Server eintragen, auf denen der Dienst läuft (am besten über eine eigene Gruppe); privilegierte "
                 "gMSA nur von Tier-0-Servern abrufen lassen.",
           "en": "List only the servers running the service (ideally via a dedicated group); privileged gMSAs only "
                 "for Tier 0 servers."},
      code="Set-ADServiceAccount <gMSA> -PrincipalsAllowedToRetrieveManagedPassword <Gruppe-der-Server>",
      columns=["account", "principal", "detail"], platforms=("windows",),
      refs=[("Microsoft: gMSA", f"{MS}/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview")])
def _gmsa_readers(ctx: Ctx):
    broad = set(BROAD_SIDS) | {ctx.group_sid(r) for r in BROAD_RIDS} | {f"{ctx.root_sid}-{r}" for r in BROAD_RIDS}
    safe = ctx.safe_sids()
    items, high = [], False
    for a in ctx.users:
        if not a.get("is_gmsa") or not a.get("enabled") or not a.get("gmsa_readers"):
            continue
        priv = ctx.is_priv(a)
        for ace in a["gmsa_readers"].get("aces") or []:
            sid = ace.get("sid")
            if not ace.get("allow") or not sid or sid in safe:
                continue
            if sid in broad:
                items.append({"account": a["sam"], "principal": ctx.name(sid), "detail": "@v_gmsa_broad"})
                high = high or priv
            elif priv and not (ctx.by_sid.get(sid) and ctx.is_priv(ctx.by_sid[sid])):
                items.append({"account": a["sam"], "principal": ctx.name(sid), "detail": "@v_gmsa_priv"})
                high = True
    if not items:
        return None
    return Hit(items, severity="high", points=15) if high else Hit(items)


MACHINE_TEMPLATES = {"machine", "workstation", "computer"}


@rule(id="P-Certighost", category="privileged", severity="medium", points=8,
      title={"de": "Voraussetzungen für Certighost (CVE-2026-54121) erfüllt",
             "en": "Preconditions for Certighost (CVE-2026-54121) met"},
      desc={"de": "Mit „Certighost“ (Juli 2026) kann jeder Domänenbenutzer ein Zertifikat für einen Domänencontroller "
                  "erhalten und damit per DCSync alle Kennwörter auslesen – wenn Benutzer Computerkonten anlegen dürfen, "
                  "eine Unternehmens-Zertifizierungsstelle die Maschinenvorlage für Domänencomputer anbietet und die "
                  "Zertifizierungsstelle das Update vom Juli 2026 noch nicht hat. Den Patchstand der "
                  "Zertifizierungsstelle kann SAMAUDIT nicht sehen; die übrigen Voraussetzungen sind hier erfüllt.",
            "en": "With 'Certighost' (July 2026) any domain user can obtain a certificate for a domain controller and "
                  "dump all passwords via DCSync – if users may create computer accounts, an enterprise CA offers the "
                  "machine template to domain computers and the CA lacks the July 2026 update. SAMAUDIT cannot see the "
                  "CA's patch level; the other preconditions are met here."},
      fix={"de": "Das Sicherheitsupdate vom Juli 2026 auf allen Zertifizierungsstellen installieren. Zusätzlich "
                 "ms-DS-MachineAccountQuota auf 0 setzen; als Übergang kann das Flag EDITF_ENABLECHASECLIENTDC "
                 "entfernt werden (vorher testen).",
           "en": "Install the July 2026 security update on all CAs. Also set ms-DS-MachineAccountQuota to 0; as a "
                 "stopgap remove the EDITF_ENABLECHASECLIENTDC flag (test first)."},
      code="certutil -setreg policy\\EditFlags -EDITF_ENABLECHASECLIENTDC   # auf der CA, danach CertSvc neu starten\n"
           "Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}",
      columns=["ca", "template", "detail"], platforms=("windows",),
      refs=[("CVE-2026-54121", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54121"),
            ("The Hacker News: Certighost", "https://thehackernews.com/2026/07/certighost-exploit-lets-low-privileged.html")])
def _certighost(ctx: Ctx):
    maq = (ctx.m.get("domain") or {}).get("maq")
    if maq is not None and maq <= 0:
        return None
    templates = {t["name"].lower(): t for t in _pki(ctx).get("templates", []) if t.get("name")}
    items = []
    for ca in _pki(ctx).get("cas", []):
        for name in ca.get("templates") or []:
            t = templates.get(name.lower())
            if not t or name.lower() not in MACHINE_TEMPLATES:
                continue
            if any(s == ctx.group_sid(515) for s in _enroll_sids(t)):
                items.append({"ca": ca.get("name") or "", "template": t.get("display") or name,
                              "detail": f"@v_certighost|{maq if maq is not None else 10}"})
    return Hit(items) if items else None


def _enroll_sids(t: dict) -> list[str]:
    from .rules import GUID_CERT_AUTOENROLL, GUID_CERT_ENROLL
    from .adutil import ADS_RIGHT_DS_CONTROL_ACCESS
    out = []
    for ace in (t.get("sd") or {}).get("aces", []):
        m, ot = ace.get("mask", 0), ace.get("object_type")
        if ace.get("allow") and (m & ADS_RIGHT_GENERIC_ALL or
                                 (m & ADS_RIGHT_DS_CONTROL_ACCESS and ot in (None, GUID_CERT_ENROLL, GUID_CERT_AUTOENROLL))):
            out.append(ace.get("sid"))
    return out


# ===========================================================================
# ANOMALIEN
# ===========================================================================

LOOSENING = [
    # (Registry-Wert, schwacher Wert, Kennung des Details)
    (r"Control\Lsa\LimitBlankPasswordUse", 0, "v_gpo_blank_pw"),
    (r"Control\Lsa\RestrictAnonymousSAM", 0, "v_gpo_anon_sam"),
    (r"Control\Lsa\EveryoneIncludesAnonymous", 1, "v_gpo_everyone_anon"),
    (r"Services\LanManServer\Parameters\RestrictNullSessAccess", 0, "v_gpo_null_sess"),
]


@rule(id="A-GPOAnonymous", category="anomalies", severity="medium", points=10,
      title={"de": "Gruppenrichtlinie lockert Anmeldeschutz (leere Kennwörter, anonymer Zugriff)",
             "en": "Group Policy weakens logon protection (blank passwords, anonymous access)"},
      desc={"de": "Eine aktiv verknüpfte Gruppenrichtlinie schaltet Schutzmechanismen ab, die Windows standardmäßig "
                  "aktiviert hat: Konten mit leerem Kennwort dürfen sich übers Netz anmelden, oder anonyme Benutzer "
                  "dürfen Konten und Freigaben auflisten bzw. werden wie „Jeder“ behandelt. Das erleichtert das "
                  "Ausspähen der Domäne und Anmeldungen ohne Kennwort.",
            "en": "An actively linked GPO disables protections that Windows enables by default: accounts with blank "
                  "passwords may log on over the network, or anonymous users may enumerate accounts and shares or are "
                  "treated like Everyone."},
      fix={"de": "In der genannten GPO unter Sicherheitsoptionen „Konten: Lokale Kontenverwendung von leeren Kennwörtern "
                 "auf Konsolenanmeldung beschränken“ aktivieren, „Netzwerkzugriff: Anonyme Aufzählung von SAM-Konten "
                 "nicht erlauben“ aktivieren, „Die Verwendung von ‚Jeder‘-Berechtigungen für anonyme Benutzer "
                 "ermöglichen“ und den anonymen Zugriff auf Named Pipes und Freigaben deaktivieren – oder die "
                 "Einstellung aus der GPO entfernen (Standard ist sicher).",
           "en": "Enable 'Limit local account use of blank passwords to console logon only' and 'Do not allow "
                 "anonymous enumeration of SAM accounts', disable 'Let Everyone permissions apply to anonymous users' "
                 "and anonymous access to named pipes/shares – or remove the setting (the default is secure)."},
      columns=["gpo", "detail", "value"],
      refs=[("PingCastle: A-LimitBlankPasswordUse / A-AnonymousAuthorizedGPO", "https://www.pingcastle.com/documentation/"),
            ("Microsoft: Network access security options",
             f"{MS}/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/"
             "network-access-do-not-allow-anonymous-enumeration-of-sam-accounts")])
def _gpo_anonymous(ctx: Ctx):
    guids = ctx.gpo_guids("all")
    items = []
    for key, weak, detail in LOOSENING:
        for g, v in gpo_values(ctx, guids, key):
            if as_num(v) == weak:
                items.append({"gpo": ctx.gpo_name(g), "detail": f"@{detail}", "value": f"{key.rsplit(chr(92), 1)[1]}={v}"})
    if not items:
        return None
    blank_on_dc = False
    try:
        dc = set(ctx.gpo_guids("dc"))
        blank_on_dc = any(as_num(v) == 0 for g, v in gpo_values(ctx, list(dc), LOOSENING[0][0]))
    except NotApplicable:
        pass
    return Hit(items, severity="high", points=15) if blank_on_dc else Hit(items)
