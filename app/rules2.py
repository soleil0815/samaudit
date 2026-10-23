# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Erweiterter Prüfkatalog (Teil 2): DNS, PKI, Gruppenrichtlinien, Überwachung,
Sicherung, RODC, Berechtigungen auf kritischen Objekten u. v. m."""
from __future__ import annotations

from .adutil import (
    UAC_DONT_EXPIRE_PASSWORD, ace_grants_control, classify_os, fmt_date, now_utc, sid_domain,
)
from .analysis import Ctx
from .rules import (ATT, MS, Hit, NotApplicable, _lowpriv_enroll, acc, admin_item, enabled_computers, need_sysvol, rule,
                    unprivileged)

ADS_RIGHT_DS_CREATE_CHILD = 0x1


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def _cfg(ctx: Ctx) -> dict:
    return ctx.m.get("config") or {}


def gpo_values(ctx: Ctx, guids: list[str], key: str) -> list[tuple[str, object]]:
    """Werte eines Registry-Schlüssels aus GptTmpl.inf (Registry Values) und Registry.pol der GPOs."""
    sv = need_sysvol(ctx)
    key = key.lower().lstrip("\\")
    out = []
    for g in guids:
        sec = (sv.get("secedit", {}).get(g) or {}).get("Registry Values") or {}
        for k, v in sec.items():
            kk = k.lower()
            if kk.endswith(key) and (kk == key or kk.endswith("\\" + key)):
                out.append((g, v.split(",", 1)[1].strip().strip('"') if "," in v else v))
        pol = sv.get("regpol", {}).get(g) or {}
        for scope in ("machine", "user"):
            for k, v in (pol.get(scope) or {}).items():
                if k == key or k.endswith("\\" + key):
                    out.append((g, v))
    return out


def last_value(ctx: Ctx, guids: list[str], key: str):
    vals = gpo_values(ctx, guids, key)
    return vals[-1][1] if vals else None


def as_num(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def acl_hits(ctx: Ctx, sd: dict | None, extra_safe: set[str] = frozenset()) -> dict[str, set]:
    if not sd:
        return {}
    safe = ctx.safe_sids() | set(extra_safe)
    out: dict[str, set] = {}
    for ace in sd.get("aces", []):
        if not ace.get("allow") or ace.get("flags", 0) & 0x08:
            continue
        sid = ace.get("sid")
        if not sid or sid in safe:
            continue
        r = ace_grants_control(ace)
        if r:
            out.setdefault(sid, set()).update(r)
    return out


# ===========================================================================
# VERALTETE OBJEKTE
# ===========================================================================

@rule(id="S-MachinePwdNotRotated", category="stale", severity="medium", points=5,
      title={"de": "Maschinenkennwort wird nicht erneuert", "en": "Machine account password not rotated"},
      desc={"de": "Diese Computer melden sich regelmäßig an, haben ihr Maschinenkennwort aber seit über 90 Tagen nicht "
                  "geändert (Standard: alle 30 Tage). Meist ist die automatische Änderung per Richtlinie abgeschaltet – "
                  "ein einmal erbeuteter Maschinen-Hash bleibt dann dauerhaft gültig.",
            "en": "These computers are active but have not changed their machine password for more than 90 days."},
      fix={"de": "Richtlinie „Domänenmitglied: Änderungen von Computerkontenkennwörtern deaktivieren“ auf „Deaktiviert“ "
                 "setzen bzw. „Maximales Kennwortalter“ auf 30 Tage.",
           "en": "Re-enable automatic machine password changes (max. 30 days)."},
      code="Test-ComputerSecureChannel -Repair   # auf dem betroffenen Rechner\nReset-ComputerMachinePassword",
      columns=["account", "os", "pwd_last_set", "last_logon"])
def _machine_pwd(ctx: Ctx):
    hits = []
    for c in enabled_computers(ctx, include_dc=True):
        if classify_os(c.get("os")) in ("samba", "other", "unknown") or ctx.inactive(c, 45):
            continue
        if (ctx.age(c.get("pwd_last_set")) or 0) > 90:
            hits.append(c)
    return Hit([acc(c, os=c.get("os")) for c in hits]) if hits else None


@rule(id="S-DesEncryptionType", category="stale", severity="medium", points=5,
      title={"de": "DES als Kerberos-Verschlüsselung erlaubt", "en": "DES allowed as Kerberos encryption type"},
      desc={"de": "Im Attribut msDS-SupportedEncryptionTypes ist DES freigegeben. DES-Schlüssel lassen sich in kurzer Zeit "
                  "brechen; seit Windows Server 2008 R2 ist DES standardmäßig deaktiviert.",
            "en": "msDS-SupportedEncryptionTypes allows DES, which can be broken quickly."},
      fix={"de": "Nur AES zulassen (Wert 0x18 bzw. 24) und Passwort neu setzen.",
           "en": "Allow AES only (0x18) and reset the password."},
      code="Set-ADUser <Konto> -KerberosEncryptionType AES128,AES256\nSet-ADComputer <Computer> -KerberosEncryptionType AES128,AES256",
      columns=["account", "type", "value"])
def _des_enc(ctx: Ctx):
    hits = [a for a in ctx.accounts if a.get("enabled") and (a.get("enc_types") or 0) & 0x3]
    return Hit([{"account": a["sam"], "type": "@" + a["_kind"], "value": hex(a["enc_types"])} for a in hits]) if hits else None


@rule(id="S-Duplicates", category="stale", severity="low", points=5,
      title={"de": "Doppelte Objekte (Replikationskonflikte)", "en": "Duplicate objects (replication conflicts)"},
      desc={"de": "Objekte mit „CNF:“ im Namen oder $DUPLICATE-Konten entstehen bei Replikationskonflikten. Sie können "
                  "Rechte erben oder Anmeldungen fehlleiten und deuten auf Replikationsprobleme hin.",
            "en": "Objects with 'CNF:' or $DUPLICATE accounts result from replication conflicts."},
      fix={"de": "Konfliktobjekte prüfen, das richtige Objekt behalten und die Duplikate löschen.",
           "en": "Review the conflict objects, keep the correct one and delete duplicates."},
      code="Get-ADObject -LDAPFilter '(cn=*CNF:*)' -IncludeDeletedObjects:$false",
      columns=["dn"])
def _duplicates(ctx: Ctx):
    d = _cfg(ctx).get("duplicates")
    if d is None:
        raise NotApplicable("na_unknown")
    return Hit([{"dn": x} for x in d]) if d else None


@rule(id="S-NoSubnets", category="stale", severity="low", points=2,
      title={"de": "Keine AD-Subnetze definiert", "en": "No AD subnets defined"},
      desc={"de": "Ohne Subnetz-Zuordnung wissen Clients nicht, welcher Standort und damit welcher DC zuständig ist. "
                  "Anmeldungen laufen dann ggf. über langsame oder unsichere Verbindungen.",
            "en": "Without subnets clients cannot find their site and nearest DC."},
      fix={"de": "In „Active Directory-Standorte und -Dienste“ alle IP-Netze als Subnetze anlegen und Standorten zuordnen.",
           "en": "Define all IP networks as subnets and assign them to sites."},
      code="New-ADReplicationSubnet -Name '192.168.10.0/24' -Site 'Default-First-Site-Name'",
      columns=["value"])
def _subnets(ctx: Ctx):
    n = _cfg(ctx).get("subnets")
    if n is None:
        raise NotApplicable("na_unknown")
    return Hit([{"value": "0"}]) if n == 0 else None


# ===========================================================================
# PRIVILEGIERTE KONTEN
# ===========================================================================

@rule(id="P-BroadGroupInAdmins", category="privileged", severity="critical", points=30,
      title={"de": "Allgemeine Gruppen in privilegierten Gruppen", "en": "Broad groups nested in privileged groups"},
      desc={"de": "„Jeder“, „Authentifizierte Benutzer“, „Domänen-Benutzer“ oder „Domänencomputer“ sind (auch verschachtelt) "
                  "Mitglied einer Admin- oder Operator-Gruppe. Damit hat praktisch jedes Konto erhöhte Rechte.",
            "en": "Everyone, Authenticated Users, Domain Users or Domain Computers are (nested) members of a privileged group."},
      fix={"de": "Die allgemeine Gruppe sofort aus der privilegierten Gruppe entfernen.",
           "en": "Remove the broad group from the privileged group immediately."},
      columns=["group", "principal"])
def _broad_in_admins(ctx: Ctx):
    low = ctx.low_priv_sids()
    items = []
    for pg in ctx.priv_groups:
        for sid in ctx.nested_principals(pg["group"]):
            if sid in low:
                items.append({"group": pg["group"].get("sam"), "principal": ctx.name(sid)})
    return Hit(items) if items else None


@rule(id="P-AdminPwdNeverExpires", category="privileged", severity="medium", points=5,
      title={"de": "Admin-Konten mit „Passwort läuft nie ab“", "en": "Admin accounts with 'password never expires'"},
      desc={"de": "Bei privilegierten Konten sollte ein kompromittiertes Passwort nicht unbegrenzt gültig bleiben.",
            "en": "A compromised admin password should not stay valid forever."},
      fix={"de": "Flag entfernen; für Admins lange Passphrasen mit regelmäßigem Wechsel oder Smartcard/FIDO2 nutzen.",
           "en": "Remove the flag; use passphrases with rotation or smartcard/FIDO2."},
      code="Set-ADUser <Admin> -PasswordNeverExpires $false",
      columns=["account", "group", "pwd_last_set"])
def _admin_never_expires(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("enabled") and u["uac"] & UAC_DONT_EXPIRE_PASSWORD
            and u.get("rid") not in (500,)]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-DisabledInAdmins", category="privileged", severity="low", points=2,
      title={"de": "Deaktivierte Konten in Admin-Gruppen", "en": "Disabled accounts in admin groups"},
      desc={"de": "Deaktivierte Konten in privilegierten Gruppen werden beim Reaktivieren sofort wieder Admin – oft unbemerkt.",
            "en": "Disabled accounts in privileged groups become admins again when re-enabled."},
      fix={"de": "Konten aus den privilegierten Gruppen entfernen.", "en": "Remove them from privileged groups."},
      columns=["account", "group", "last_logon"])
def _disabled_admins(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if not u.get("enabled") and u.get("rid") not in (501, 502)]
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-OtherPrivGroups", category="privileged", severity="low", points=5,
      title={"de": "Mitglieder in weiteren kritischen Gruppen", "en": "Members in other critical groups"},
      desc={"de": "Schlüsseladministratoren können Shadow Credentials auf beliebigen Konten setzen; Mitglieder von "
                  "„Richtlinien-Ersteller-Besitzer“ können GPOs anlegen und bearbeiten.",
            "en": "Key Admins can set shadow credentials on any account; Group Policy Creator Owners can create and edit GPOs."},
      fix={"de": "Gruppen leer halten und Rechte nur bei Bedarf vergeben.", "en": "Keep these groups empty."},
      columns=["account", "group"])
def _other_priv(ctx: Ctx):
    items = []
    for rid in (526, 527, 520):
        g = ctx.group(rid)
        for a in ctx.members(g):
            if rid == 520 and a.get("rid") == 500:
                continue
            items.append({"account": a["sam"], "group": g.get("sam")})
    return Hit(items) if items else None


@rule(id="P-ShadowCredentials", category="privileged", severity="medium", points=10,
      title={"de": "Schlüsselanmeldeinformationen auf Admin-Konten (Shadow Credentials)",
             "en": "Key credentials on admin accounts (shadow credentials)"},
      desc={"de": "msDS-KeyCredentialLink ist auf privilegierten Konten gesetzt. Das ist bei Windows Hello for Business "
                  "normal, kann aber auch eine Hintertür sein, mit der sich ein Angreifer ohne Passwort als Admin anmeldet.",
            "en": "msDS-KeyCredentialLink is set on privileged accounts – legitimate for WHfB, but also a known backdoor."},
      fix={"de": "Prüfen, ob die Einträge zu bekannten Geräten (Windows Hello) gehören; unbekannte Einträge löschen.",
           "en": "Verify the entries belong to known devices; remove unknown ones."},
      code="Get-ADUser <Admin> -Properties msDS-KeyCredentialLink | Select-Object -Expand msDS-KeyCredentialLink",
      columns=["account", "group"],
      refs=[("MITRE ATT&CK T1556", f"{ATT}/T1556/")])
def _shadow(ctx: Ctx):
    hits = [u for u in ctx.privileged_users if u.get("key_cred")]
    if not hits and unprivileged(ctx) and not any(a.get("key_cred") for a in ctx.accounts):
        raise NotApplicable("na_restricted")
    return Hit([admin_item(ctx, u) for u in hits]) if hits else None


@rule(id="P-DCOwner", category="privileged", severity="high", points=20,
      title={"de": "Domänencontroller-Objekt gehört keinem Administrator", "en": "Domain controller object not owned by admins"},
      desc={"de": "Der Besitzer eines Objekts kann dessen Berechtigungen ändern. Gehört ein DC-Computerobjekt einem normalen "
                  "Konto (z. B. dem, das den Server hochgestuft hat), kann dieses Konto die Domäne übernehmen.",
            "en": "The owner can change permissions. A DC owned by a regular account allows domain takeover."},
      fix={"de": "Besitzer auf „Domänen-Admins“ setzen.", "en": "Set the owner to Domain Admins."},
      code="$dc = Get-ADComputer DC01\n$acl = Get-Acl \"AD:$($dc.DistinguishedName)\"\n$acl.SetOwner([Security.Principal.NTAccount]'FIRMA\\Domain Admins')\nSet-Acl \"AD:$($dc.DistinguishedName)\" $acl",
      columns=["account", "principal"])
def _dc_owner(ctx: Ctx):
    safe = ctx.safe_sids()
    seen_any = False
    items = []
    for dc in ctx.dcs:
        o = dc.get("owner")
        if o is None:
            continue
        seen_any = True
        if o not in safe:
            items.append({"account": dc["sam"], "principal": ctx.name(o)})
    if not seen_any:
        raise NotApplicable("na_acl")
    return Hit(items) if items else None


@rule(id="P-DCOUACL", category="privileged", severity="critical", points=25,
      title={"de": "Schreibrechte auf der OU „Domain Controllers“", "en": "Write permissions on the 'Domain Controllers' OU"},
      desc={"de": "Wer die OU der Domänencontroller verändern darf, kann dort GPOs verknüpfen oder Rechte auf die DC-Objekte "
                  "vererben – und so die Domäne übernehmen.",
            "en": "Write access to the DC OU allows linking GPOs or inheriting rights to DC objects."},
      fix={"de": "Unerwartete Einträge aus der ACL der OU entfernen.", "en": "Remove unexpected ACL entries."},
      columns=["principal", "rights"])
def _dc_ou_acl(ctx: Ctx):
    sd = (ctx.m.get("acl") or {}).get("dc_ou")
    if not sd:
        raise NotApplicable("na_acl")
    res = acl_hits(ctx, sd)
    return Hit([{"principal": ctx.name(s), "rights": ", ".join(sorted(r))} for s, r in res.items()]) if res else None


@rule(id="P-GPOWrite", category="privileged", severity="critical", points=25,
      title={"de": "Nicht-Administratoren dürfen kritische GPOs ändern", "en": "Non-admins can modify critical GPOs"},
      desc={"de": "GPOs auf Domäne oder DC-OU wirken auf alle Rechner bzw. alle DCs. Wer sie ändern darf, kann dort Skripte, "
                  "Dienste oder lokale Admins verteilen und erhält so die Kontrolle über die Domäne.",
            "en": "GPOs linked to the domain or DC OU apply to all machines/DCs; editing them means domain takeover."},
      fix={"de": "In der Gruppenrichtlinienverwaltung unter „Delegierung“ die Bearbeitungsrechte entfernen.",
           "en": "Remove edit rights under the GPO's Delegation tab."},
      columns=["gpo", "detail", "principal", "rights"],
      refs=[("MITRE ATT&CK T1484.001", f"{ATT}/T1484/001/")])
def _gpo_write(ctx: Ctx):
    crit_guids = set(ctx.gpo_guids("dc"))
    all_guids = set(ctx.gpo_guids("all"))
    items, crit = [], False
    have_sd = False
    for g in ctx.m.get("gpos", []):
        if g.get("sd") is None:
            continue
        have_sd = True
        guid = g["guid"].upper()
        if guid not in all_guids:
            continue
        for sid, r in acl_hits(ctx, g["sd"], {ctx.group_sid(520)}).items():
            is_crit = guid in crit_guids
            crit = crit or is_crit
            items.append({"gpo": g["name"], "detail": "@v_scope_dc" if is_crit else "@v_scope_ou",
                          "principal": ctx.name(sid), "rights": ", ".join(sorted(r))})
    if not have_sd:
        raise NotApplicable("na_acl")
    if not items:
        return None
    return Hit(items, points=25 if crit else 10, severity="critical" if crit else "medium")


@rule(id="P-RODC", category="privileged", severity="high", points=20,
      title={"de": "Riskante Kennwortreplikation auf RODCs", "en": "Risky password replication on RODCs"},
      desc={"de": "Ein schreibgeschützter DC (RODC) darf Passwörter nur für unkritische Konten zwischenspeichern. Stehen "
                  "Admin- oder allgemeine Gruppen in der Zulassungsliste oder wurden Admin-Passwörter bereits repliziert, "
                  "führt der Diebstahl des RODC zur Übernahme der Domäne.",
            "en": "RODCs must only cache passwords of non-critical accounts."},
      fix={"de": "Zulassungsliste auf Standortbenutzer beschränken, „Denied RODC Password Replication Group“ in der "
                 "Verweigerungsliste belassen und betroffene Admin-Passwörter ändern.",
           "en": "Restrict the allowed list, keep the denied group, reset exposed admin passwords."},
      columns=["account", "detail", "value"])
def _rodc(ctx: Ctx):
    rodcs = [d for d in ctx.dcs if d.get("is_rodc")]
    if not rodcs:
        return None
    items = []
    bad_groups = {ctx.group_sid(r) for r in (512, 519, 518, 544, 513, 515)} | ctx.low_priv_sids()
    denied = ctx.group_sid(572)
    for r in rodcs:
        for gdn in r.get("reveal_on_demand", []):
            o = ctx.by_dn.get(gdn.lower())
            if o and (o.get("sid") in bad_groups or (o["_kind"] != "group" and ctx.is_priv(o))):
                items.append({"account": r["sam"], "detail": "RevealOnDemand", "value": o.get("sam")})
        never = {ctx.by_dn.get(x.lower(), {}).get("sid") for x in r.get("never_reveal", [])}
        if denied not in never and ctx.by_sid.get(denied):
            items.append({"account": r["sam"], "detail": "NeverReveal", "value": "@v_denied_missing"})
        for udn in r.get("revealed", []):
            o = ctx.by_dn.get(udn.lower())
            if o and ctx.is_priv(o):
                items.append({"account": r["sam"], "detail": "Revealed", "value": o.get("sam")})
    if not items and unprivileged(ctx) and not any(r.get("revealed") for r in rodcs):
        raise NotApplicable("na_restricted")  # msDS-RevealedUsers ist nur für Admins lesbar
    return Hit(items) if items else None


@rule(id="P-AzureSSO", category="privileged", severity="medium", points=5,
      title={"de": "Schlüssel für Entra ID Seamless SSO nicht erneuert", "en": "Entra ID Seamless SSO key not rolled over"},
      desc={"de": "Mit dem Kerberos-Schlüssel des Kontos AZUREADSSOACC$ lassen sich Anmeldetickets für Microsoft Entra ID "
                  "fälschen. Microsoft empfiehlt, ihn mindestens alle 30 Tage zu erneuern.",
            "en": "The AZUREADSSOACC$ key allows forging Entra ID sign-in tickets; roll it over every 30 days."},
      fix={"de": "Schlüssel mit dem Entra-Connect-Modul erneuern (Update-AzureADSSOForest).",
           "en": "Roll over the key with Update-AzureADSSOForest."},
      code="Import-Module .\\AzureADSSO.psd1\nNew-AzureADSSOAuthenticationContext\nUpdate-AzureADSSOForest -OnPremCredentials (Get-Credential)",
      columns=["account", "pwd_last_set"],
      refs=[("Microsoft: Seamless SSO", f"{MS}/entra/identity/hybrid/connect/how-to-connect-sso-faq")])
def _azure_sso(ctx: Ctx):
    a = next((c for c in ctx.computers if c.get("sam", "").upper() == "AZUREADSSOACC$"), None)
    if not a or (ctx.age(a.get("pwd_last_set")) or 0) <= 40:
        return None
    return Hit([acc(a)])


@rule(id="P-ADCS-ESC3", category="privileged", severity="high", points=15,
      title={"de": "Registrierungs-Agent-Vorlage für normale Benutzer (ESC3)", "en": "Enrollment agent template for regular users (ESC3)"},
      desc={"de": "Mit einem Registrierungs-Agent-Zertifikat kann man Zertifikate im Namen anderer Benutzer beantragen – "
                  "auch für Administratoren.",
            "en": "An enrollment agent certificate allows requesting certificates on behalf of other users."},
      fix={"de": "Registrierungsrechte auf wenige Personen beschränken und Agent-Einschränkungen auf der CA konfigurieren.",
           "en": "Restrict enrollment and configure enrollment agent restrictions on the CA."},
      columns=["template", "principal"])
def _esc3(ctx: Ctx):
    items = []
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        if not t.get("published") or t.get("enroll_flag", 0) & 0x2 or t.get("ra_signature", 0) > 0:
            continue
        if "1.3.6.1.4.1.311.20.2.1" in (t.get("ekus") or []):
            who = _lowpriv_enroll(ctx, t)
            if who:
                items.append({"template": t["display"], "principal": ", ".join(who)})
    return Hit(items) if items else None


@rule(id="P-ADCS-ESC9-15", category="privileged", severity="high", points=15,
      title={"de": "Schwache Zertifikatvorlagen (ESC9 / ESC15)", "en": "Weak certificate templates (ESC9 / ESC15)"},
      desc={"de": "Vorlagen ohne Sicherheitserweiterung (CT_FLAG_NO_SECURITY_EXTENSION) oder Schema-Version-1-Vorlagen mit "
                  "frei wählbarem Antragsteller lassen sich – je nach Patchstand – für Anmeldungen als andere Benutzer missbrauchen.",
            "en": "Templates without the security extension or schema v1 templates with supplied subject can be abused."},
      fix={"de": "Flag entfernen bzw. Vorlage duplizieren (neue Schema-Version), CAs aktuell halten (CVE-2024-49019).",
           "en": "Remove the flag or duplicate the template; keep CAs patched (CVE-2024-49019)."},
      columns=["template", "detail", "principal"])
def _esc9(ctx: Ctx):
    from .rules import AUTH_EKUS
    items = []
    for t in (ctx.m.get("pki") or {}).get("templates", []):
        if not t.get("published"):
            continue
        who = _lowpriv_enroll(ctx, t)
        if not who:
            continue
        ekus = set(t.get("ekus") or [])
        auth = not ekus or bool(ekus & AUTH_EKUS)
        if t.get("enroll_flag", 0) & 0x80000 and auth:
            items.append({"template": t["display"], "detail": "ESC9", "principal": ", ".join(who)})
        if t.get("schema_version") == 1 and t.get("name_flag", 0) & 0x1:
            items.append({"template": t["display"], "detail": "ESC15", "principal": ", ".join(who)})
    return Hit(items) if items else None


@rule(id="P-ADCS-ESC5", category="privileged", severity="critical", points=25,
      title={"de": "Schreibrechte auf PKI-Objekten (ESC5)", "en": "Write permissions on PKI objects (ESC5)"},
      desc={"de": "Wer Zertifizierungsstellen-Objekte, NTAuth oder den Vorlagen-Container ändern darf, kann eigene CAs "
                  "einschleusen oder Vorlagen manipulieren.",
            "en": "Write access to CA objects, NTAuth or the template container allows injecting CAs or tampering templates."},
      fix={"de": "Rechte auf Organisations-Admins und Systemkonten beschränken.", "en": "Restrict to Enterprise Admins."},
      columns=["dn", "principal", "rights"])
def _esc5(ctx: Ctx):
    pki = ctx.m.get("pki") or {}
    objs = list(pki.get("objects", [])) + [{"dn": c.get("dn") or c.get("name"), "sd": c.get("sd")} for c in pki.get("cas", [])]
    if not any(o.get("sd") for o in objs):
        if not objs:
            return None
        raise NotApplicable("na_acl")
    items = []
    for o in objs:
        for sid, r in acl_hits(ctx, o.get("sd"), {ctx.group_sid(517)}).items():
            items.append({"dn": o["dn"], "principal": ctx.name(sid), "rights": ", ".join(sorted(r))})
    return Hit(items) if items else None


@rule(id="P-ADCS-ESC8", category="privileged", severity="high", points=15,
      title={"de": "Zertifikatsregistrierung über HTTP (ESC8)", "en": "Certificate enrollment over HTTP (ESC8)"},
      desc={"de": "Registrierungsdienste über unverschlüsseltes HTTP erlauben NTLM-Relay: Ein Angreifer erzwingt die "
                  "Anmeldung eines DCs und lässt sich dafür ein Zertifikat ausstellen.",
            "en": "HTTP enrollment endpoints allow NTLM relay to obtain a DC certificate."},
      fix={"de": "Nur HTTPS mit Extended Protection for Authentication (EPA) anbieten, NTLM auf IIS deaktivieren.",
           "en": "Use HTTPS with Extended Protection, disable NTLM on IIS."},
      columns=["value", "detail"],
      refs=[("Microsoft KB5005413", "https://support.microsoft.com/kb/5005413")])
def _esc8(ctx: Ctx):
    items = []
    for ca in (ctx.m.get("pki") or {}).get("cas", []):
        for line in ca.get("enroll_servers", []):
            for part in line.split("\n"):
                if part.strip().lower().startswith("http://"):
                    items.append({"value": part.strip(), "detail": ca.get("name")})
    return Hit(items) if items else None


@rule(id="A-CAWeakCrypto", category="anomalies", severity="medium", points=10,
      title={"de": "Schwache oder ablaufende CA-Zertifikate", "en": "Weak or expiring CA certificates"},
      desc={"de": "CA-Zertifikate mit SHA-1/MD5-Signatur oder RSA-Schlüsseln unter 2048 Bit gelten als unsicher; "
                  "ablaufende CA-Zertifikate legen Anmeldungen per Zertifikat lahm.",
            "en": "CA certificates with SHA-1/MD5 or RSA < 2048 bit are weak; expiring ones break authentication."},
      fix={"de": "CA-Schlüssel erneuern (SHA-256, RSA ≥ 3072) und rechtzeitig vor Ablauf verlängern.",
           "en": "Renew CA keys (SHA-256, RSA ≥ 3072) before expiry."},
      columns=["detail", "value", "recommended"])
def _ca_crypto(ctx: Ctx):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    pki = ctx.m.get("pki") or {}
    certs = []
    for c in pki.get("cas", []):
        certs += c.get("certs", [])
    for o in pki.get("objects", []):
        certs += o.get("certs", [])
    seen, items, worst = set(), [], 0
    for der in certs:
        if der in seen:
            continue
        seen.add(der)
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001
            continue
        name = cert.subject.rfc4514_string()[:80]
        algo = (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?").lower()
        if algo in ("md5", "sha1"):
            items.append({"detail": name, "value": algo.upper(), "recommended": "SHA-256"}); worst = max(worst, 2)
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
            items.append({"detail": name, "value": f"RSA {key.key_size}", "recommended": "RSA ≥ 3072"}); worst = 3
        try:
            na = cert.not_valid_after_utc
        except AttributeError:
            na = cert.not_valid_after.replace(tzinfo=now_utc().tzinfo)
        days = (na - now_utc()).days
        if days < 0:
            items.append({"detail": name, "value": fmt_date(na), "recommended": "@v_renew_expired"}); worst = 3
        elif days < 180:
            items.append({"detail": name, "value": fmt_date(na), "recommended": "@v_renew_soon"}); worst = max(worst, 1)
    if not items:
        return None
    pts, sev = {1: (2, "low"), 2: (10, "medium"), 3: (15, "high")}[worst]
    return Hit(items, points=pts, severity=sev)


# ===========================================================================
# VERTRAUENSSTELLUNGEN
# ===========================================================================

@rule(id="T-ForeignAdmins", category="trusts", severity="high", points=15,
      title={"de": "Konten fremder Domänen in privilegierten Gruppen", "en": "Foreign domain principals in privileged groups"},
      desc={"de": "Ein Konto aus einer vertrauten Domäne ist Mitglied einer Admin- oder Operator-Gruppe. Damit hängt die "
                  "Sicherheit Ihrer Domäne an der Sicherheit der fremden Domäne.",
            "en": "A principal from a trusted domain is a member of a privileged group."},
      fix={"de": "Fremde Konten aus privilegierten Gruppen entfernen und lokale Admin-Konten verwenden.",
           "en": "Remove foreign principals and use local admin accounts."},
      columns=["group", "principal"])
def _foreign_admins(ctx: Ctx):
    items = []
    own = {ctx.domain_sid, ctx.root_sid}
    for pg in ctx.priv_groups:
        for sid in ctx.nested_principals(pg["group"]):
            dom = sid_domain(sid)
            if sid.startswith("S-1-5-21-") and dom not in own:
                items.append({"group": pg["group"].get("sam"), "principal": sid})
    return Hit(items) if items else None


@rule(id="T-NoSelectiveAuth", category="trusts", severity="low", points=2,
      title={"de": "Vertrauensstellung ohne selektive Authentifizierung", "en": "Trust without selective authentication"},
      desc={"de": "Ohne selektive Authentifizierung dürfen sich alle Benutzer der anderen Gesamtstruktur an jedem Rechner "
                  "Ihrer Domäne anmelden, sofern dort Rechte bestehen (z. B. über „Authentifizierte Benutzer“).",
            "en": "Without selective authentication every user of the other forest can authenticate to all your machines."},
      fix={"de": "Selektive Authentifizierung aktivieren und „Darf authentifizieren“ nur auf benötigten Servern vergeben.",
           "en": "Enable selective authentication and grant 'Allowed to authenticate' where needed."},
      code="netdom trust firma.local /domain:<andere> /SelectiveAUTH:Yes",
      columns=["trust", "direction"])
def _selective(ctx: Ctx):
    from .rules import trust_item
    items = [trust_item(t) for t in ctx.m.get("trusts", [])
             if t.get("direction", 0) & 2 and not (t.get("attributes", 0) & 0x20) and not (t.get("attributes", 0) & 0x10)]
    return Hit(items) if items else None


# ===========================================================================
# ANOMALIEN – Richtlinien, DNS, Sicherung
# ===========================================================================

@rule(id="A-PwdPolicyDetails", category="anomalies", severity="low", points=2,
      title={"de": "Kennwortchronik oder Mindestalter zu gering", "en": "Password history or minimum age too low"},
      desc={"de": "Mit kurzer Chronik oder Mindestalter 0 können Benutzer sofort zu ihrem alten Passwort zurückwechseln.",
            "en": "With a short history or a minimum age of 0 users can immediately reuse their old password."},
      fix={"de": "Kennwortchronik 24, minimales Kennwortalter 1 Tag.", "en": "History 24, minimum age 1 day."},
      code="Set-ADDefaultDomainPasswordPolicy -Identity firma.local -PasswordHistoryCount 24 -MinPasswordAge 1.00:00:00",
      columns=["detail", "value", "recommended"])
def _pwd_details(ctx: Ctx):
    p = ctx.domain.get("policy") or {}
    items = []
    if (p.get("history") or 0) < 24:
        items.append({"detail": "@v_history", "value": str(p.get("history")), "recommended": "24"})
    if (p.get("min_age_days") or 0) < 1:
        items.append({"detail": "@v_min_age", "value": str(round(p.get("min_age_days") or 0)), "recommended": "1"})
    return Hit(items) if items else None


@rule(id="A-DNSInsecureUpdate", category="anomalies", severity="high", points=15,
      title={"de": "DNS-Zonen erlauben unsichere dynamische Updates", "en": "DNS zones allow insecure dynamic updates"},
      desc={"de": "Bei „Nicht sichere und sichere“ Updates kann jeder ohne Anmeldung DNS-Einträge anlegen oder überschreiben "
                  "– etwa den Namen eines Servers auf den eigenen Rechner umbiegen.",
            "en": "Nonsecure updates allow anyone to create or overwrite DNS records without authentication."},
      fix={"de": "In der DNS-Konsole für die Zone „Nur sichere“ dynamische Updates einstellen.",
           "en": "Set dynamic updates to 'Secure only'."},
      code="Set-DnsServerPrimaryZone -Name firma.local -DynamicUpdate Secure",
      columns=["value"])
def _dns_update(ctx: Ctx):
    zones = _cfg(ctx).get("dns_zones")
    if zones is None:
        raise NotApplicable("na_unknown")
    hits = [z for z in zones if z.get("allow_update") == 1]
    return Hit([{"value": z["name"]} for z in hits]) if hits else None


@rule(id="A-DNSZoneCreateChild", category="anomalies", severity="low", points=2,
      title={"de": "Jeder Benutzer darf DNS-Einträge anlegen (ADIDNS)", "en": "Any user can create DNS records (ADIDNS)"},
      desc={"de": "Standardmäßig dürfen authentifizierte Benutzer neue Einträge in AD-integrierten Zonen anlegen. "
                  "Angreifer registrieren so z. B. „wpad“ oder einen Platzhalter-Eintrag und fangen Verbindungen ab.",
            "en": "By default authenticated users may create records in AD-integrated zones (e.g. wpad, wildcard)."},
      fix={"de": "Recht „Alle untergeordneten Objekte erstellen“ für Authentifizierte Benutzer entfernen und Einträge über "
                 "DHCP bzw. Admins anlegen lassen; zusätzlich statische Einträge für „wpad“ und „*“ setzen.",
           "en": "Remove 'Create all child objects' for Authenticated Users; add static wpad and wildcard records."},
      columns=["value", "principal"])
def _dns_create(ctx: Ctx):
    zones = _cfg(ctx).get("dns_zones")
    if zones is None:
        raise NotApplicable("na_unknown")
    low = ctx.low_priv_sids()
    items = []
    for z in zones:
        for ace in (z.get("sd") or {}).get("aces", []):
            if ace.get("allow") and ace.get("sid") in low and ace.get("mask", 0) & ADS_RIGHT_DS_CREATE_CHILD:
                items.append({"value": z["name"], "principal": ctx.name(ace["sid"])})
                break
    return Hit(items) if items else None


@rule(id="A-Backup", category="anomalies", severity="high", points=15,
      title={"de": "Keine aktuelle Sicherung des Active Directory", "en": "No recent Active Directory backup"},
      desc={"de": "Laut Replikations-Metadaten wurde die Domäne lange oder nie gesichert. Ohne Sicherung ist nach einem "
                  "Ransomware-Angriff oder Fehler keine Wiederherstellung möglich.",
            "en": "According to replication metadata the domain has not been backed up recently."},
      fix={"de": "Täglich eine Systemstatus-Sicherung mindestens eines DCs erstellen und die Wiederherstellung testen.",
           "en": "Back up the system state of at least one DC daily and test restores."},
      code="wbadmin start systemstatebackup -backupTarget:E: -quiet",
      columns=["value", "days"])
def _backup(ctx: Ctx):
    lb = _cfg(ctx).get("last_backup")
    if lb is None:
        raise NotApplicable("na_unknown")
    if lb == "never":
        return Hit([{"value": "@v_never", "days": "–"}])
    days = ctx.age(lb) or 0
    if days <= 7:
        return None
    return Hit([{"value": fmt_date(lb), "days": str(days)}], points=15 if days > 30 else 10,
               severity="high" if days > 30 else "medium")


@rule(id="A-Tombstone", category="anomalies", severity="low", points=2,
      title={"de": "Tombstone-Lebensdauer zu kurz", "en": "Tombstone lifetime too short"},
      desc={"de": "Die Tombstone-Lebensdauer bestimmt, wie alt eine Sicherung höchstens sein darf. Unter 180 Tagen wird "
                  "die Wiederherstellung aus älteren Sicherungen unmöglich.",
            "en": "The tombstone lifetime limits the maximum backup age; below 180 days restores become hard."},
      fix={"de": "tombstoneLifetime auf 180 setzen.", "en": "Set tombstoneLifetime to 180."},
      columns=["value", "recommended"])
def _tombstone(ctx: Ctx):
    v = _cfg(ctx).get("tombstone_lifetime")
    if v is None or v >= 180:
        return None
    return Hit([{"value": str(v), "recommended": "180"}])


@rule(id="A-SysvolFRS", category="anomalies", severity="medium", points=10,
      title={"de": "SYSVOL wird noch über FRS repliziert", "en": "SYSVOL still replicated with FRS"},
      desc={"de": "FRS ist veraltet, fehleranfällig und wird von neuen Windows-Server-Versionen nicht mehr unterstützt.",
            "en": "FRS is deprecated and unsupported by current Windows Server versions."},
      fix={"de": "Migration auf DFSR mit dfsrmig durchführen.", "en": "Migrate to DFSR using dfsrmig."},
      code="dfsrmig /setglobalstate 1   # dann 2 und 3, jeweils mit dfsrmig /getmigrationstate prüfen",
      columns=["value"], platforms=("windows",))
def _frs(ctx: Ctx):
    v = _cfg(ctx).get("sysvol_repl")
    if v is None:
        return None
    return Hit([{"value": "FRS"}]) if v == "frs" else None


@rule(id="A-DSHeuristicsSDProp", category="anomalies", severity="medium", points=10,
      title={"de": "Operator-Gruppen vom AdminSDHolder-Schutz ausgenommen", "en": "Operator groups excluded from AdminSDHolder"},
      desc={"de": "Über dSHeuristics wurden Operator-Gruppen vom Schutz durch AdminSDHolder ausgenommen. Deren "
                  "Berechtigungen können dadurch unbemerkt aufgeweicht werden.",
            "en": "dSHeuristics excludes operator groups from AdminSDHolder protection."},
      fix={"de": "Das 16. Zeichen von dSHeuristics auf 0 zurücksetzen.", "en": "Reset the 16th character of dSHeuristics to 0."},
      columns=["value"], platforms=("windows",))
def _dsh_sdprop(ctx: Ctx):
    v = _cfg(ctx).get("dsheuristics") or ""
    return Hit([{"value": v}]) if len(v) >= 16 and v[15] not in ("0", "") else None


# ===========================================================================
# ANOMALIEN – Gruppenrichtlinien auf DCs und in der Domäne
# ===========================================================================

def _gpo_list(ctx: Ctx, vals) -> str:
    return ", ".join(sorted({ctx.gpo_name(g) for g, _ in vals}))


@rule(id="A-DCSpooler", category="anomalies", severity="medium", points=10,
      title={"de": "Druckwarteschlange auf DCs nicht deaktiviert", "en": "Print spooler not disabled on DCs"},
      desc={"de": "Über den Druckspooler eines DCs lässt sich dessen Anmeldung an beliebige Systeme erzwingen "
                  "(PrinterBug/PrintNightmare) – in Kombination mit Delegierung oder Relay die Domänenübernahme.",
            "en": "The DC print spooler enables coerced authentication (PrinterBug) and PrintNightmare."},
      fix={"de": "In einer GPO für die OU „Domain Controllers“ den Dienst „Druckwarteschlange“ auf „Deaktiviert“ setzen.",
           "en": "Disable the Print Spooler service via a GPO on the DC OU."},
      code="Stop-Service Spooler; Set-Service Spooler -StartupType Disabled   # je DC",
      columns=["value"], platforms=("windows",),
      refs=[("Microsoft: DC print spooler", f"{MS}/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server")])
def _spooler(ctx: Ctx):
    sv = need_sysvol(ctx)
    state = None
    for g in ctx.gpo_guids("dc"):
        sect = (sv.get("secedit", {}).get(g) or {}).get("Service General Setting") or {}
        for k, v in sect.items():
            if k.strip('"').lower() == "spooler":
                state = v.split(",", 1)[0].strip()
    return None if state == "4" else Hit([{"value": "@v_not_configured" if state is None else state}])


@rule(id="A-DCAuditPolicy", category="anomalies", severity="medium", points=10,
      title={"de": "Überwachungsrichtlinie auf DCs unvollständig", "en": "Audit policy on DCs incomplete"},
      desc={"de": "Ohne Überwachung von Anmeldungen, Kerberos, Konten- und Gruppenänderungen bleiben Angriffe in den "
                  "Ereignisprotokollen unsichtbar und lassen sich später nicht nachvollziehen.",
            "en": "Without auditing of logons, Kerberos, account and group changes attacks remain invisible."},
      fix={"de": "In einer GPO für die DC-OU die erweiterte Überwachungsrichtlinie für die fehlenden Unterkategorien "
                 "(Erfolg und Fehler) aktivieren.",
           "en": "Enable advanced audit policy for the missing subcategories (success and failure)."},
      code="auditpol /get /category:*   # Ist-Zustand auf einem DC",
      columns=["detail"], platforms=("windows",),
      refs=[("Microsoft: Audit policy recommendations", f"{MS}/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations")])
def _audit(ctx: Ctx):
    sv = need_sysvol(ctx)
    adv: dict = {}
    legacy: dict = {}
    for g in ctx.gpo_guids("dc"):
        adv.update(sv.get("audit", {}).get(g) or {})
        legacy.update((sv.get("secedit", {}).get(g) or {}).get("Event Audit") or {})
    need = {
        "Credential Validation": ("0cce923f-69ae-11d9-bed3-505054503030", "AuditAccountLogon"),
        "Kerberos Authentication Service": ("0cce9242-69ae-11d9-bed3-505054503030", "AuditAccountLogon"),
        "Kerberos Service Ticket Operations": ("0cce9240-69ae-11d9-bed3-505054503030", "AuditAccountLogon"),
        "User Account Management": ("0cce9235-69ae-11d9-bed3-505054503030", "AuditAccountManage"),
        "Security Group Management": ("0cce9237-69ae-11d9-bed3-505054503030", "AuditAccountManage"),
        "Computer Account Management": ("0cce9236-69ae-11d9-bed3-505054503030", "AuditAccountManage"),
        "Directory Service Changes": ("0cce923c-69ae-11d9-bed3-505054503030", "AuditDSAccess"),
        "Logon": ("0cce9215-69ae-11d9-bed3-505054503030", "AuditLogonEvents"),
        "Audit Policy Change": ("0cce922f-69ae-11d9-bed3-505054503030", "AuditPolicyChange"),
        "Sensitive Privilege Use": ("0cce9228-69ae-11d9-bed3-505054503030", "AuditPrivilegeUse"),
    }
    missing = []
    for name, (guid, leg) in need.items():
        v = adv.get(guid)
        if v is None:
            v = adv.get(f"audit {name}".lower())
        if v is None and not adv:
            v = as_num(legacy.get(leg))
        if not v:
            missing.append(name)
    if not missing:
        return None
    if len(missing) == len(need):
        return Hit([{"detail": "@v_not_configured"}])
    return Hit([{"detail": m} for m in missing], points=5, severity="low")


@rule(id="A-DCPrivileges", category="anomalies", severity="critical", points=20,
      title={"de": "Gefährliche Benutzerrechte auf DCs", "en": "Dangerous user rights on DCs"},
      desc={"de": "Über die Benutzerrechtezuweisung der DC-Richtlinien haben Nicht-Administratoren Rechte wie "
                  "„Programme debuggen“, „Sichern/Wiederherstellen“, „Treiber laden“ oder lokale Anmeldung an DCs. "
                  "Jedes dieser Rechte reicht zur Übernahme eines DCs.",
            "en": "Non-admins hold rights like debug, backup/restore, load driver or logon on DCs."},
      fix={"de": "Rechte in der Default Domain Controllers Policy (Benutzerrechtezuweisung) auf Administratoren beschränken.",
           "en": "Restrict these rights to administrators in the DC policy."},
      columns=["privilege", "principal", "gpo"], platforms=("windows",))
def _dc_privs(ctx: Ctx):
    sv = need_sysvol(ctx)
    danger = {"SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
              "SeLoadDriverPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege",
              "SeEnableDelegationPrivilege", "SeSecurityPrivilege", "SeSystemEnvironmentPrivilege",
              "SeManageVolumePrivilege", "SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight", "SeImpersonatePrivilege"}
    effective: dict[str, tuple[str, list[str]]] = {}
    for g in ctx.gpo_guids("dc"):
        for k, v in ((sv.get("secedit", {}).get(g) or {}).get("Privilege Rights") or {}).items():
            if k in danger:
                effective[k] = (g, [x.strip().lstrip("*") for x in v.split(",") if x.strip()])
    ok = ctx.safe_sids() | {"S-1-5-19", "S-1-5-20", "S-1-5-6", "S-1-5-32-551", "S-1-5-32-549", "S-1-5-32-548",
                            "S-1-5-32-550", "S-1-5-17", "S-1-5-32-568"}
    items = []
    for priv, (g, principals) in effective.items():
        for p in principals:
            if p.upper().startswith("S-1-5-80-") or p.upper().startswith("S-1-5-83-"):
                continue
            if p.upper().startswith("S-1-"):
                if p.upper() in ok:
                    continue
                name = ctx.name(p.upper())
            else:
                low = p.lower()
                if any(x in low for x in ("administrators", "administratoren", "domain admins", "domänen-admins",
                                          "enterprise admins", "organisations-admins", "system", "local service",
                                          "network service", "lokaler dienst", "netzwerkdienst", "nt service\\",
                                          "service", "dienst", "backup operators", "sicherungs-operatoren",
                                          "server operators", "server-operatoren", "account operators",
                                          "konten-operatoren", "print operators", "druck-operatoren",
                                          "enterprise domain controllers")):
                    continue
                name = p
            items.append({"privilege": priv, "principal": name, "gpo": ctx.gpo_name(g)})
    return Hit(items) if items else None


@rule(id="A-LDAPChannelBinding", category="anomalies", severity="medium", points=5,
      title={"de": "LDAP-Kanalbindung auf DCs nicht erzwungen", "en": "LDAP channel binding not enforced on DCs"},
      desc={"de": "Kanalbindung schützt LDAPS vor NTLM-Relay. Ohne „Immer“ können weitergeleitete Anmeldungen über LDAPS "
                  "missbraucht werden.",
            "en": "Channel binding protects LDAPS against NTLM relay."},
      fix={"de": "„Domänencontroller: Anforderungen an das LDAP-Server-Kanalbindungstoken“ auf „Immer“ setzen "
                 "(vorher Ereignis 3039 prüfen).",
           "en": "Set 'LDAP server channel binding token requirements' to 'Always' (check event 3039 first)."},
      columns=["value", "recommended"], platforms=("windows",))
def _channel_binding(ctx: Ctx):
    v = last_value(ctx, ctx.gpo_guids("dc"), r"NTDS\Parameters\LdapEnforceChannelBinding")
    if as_num(v) == 2:
        return None
    return Hit([{"value": "@v_not_configured" if v is None else str(v), "recommended": "2"}])


@rule(id="A-LMHash", category="anomalies", severity="high", points=15,
      title={"de": "LM-Hashes werden gespeichert", "en": "LM hashes are stored"},
      desc={"de": "Eine Richtlinie erlaubt das Speichern von LAN-Manager-Hashes. Diese lassen sich in Sekunden knacken.",
            "en": "A policy allows storing LAN Manager hashes, which are cracked in seconds."},
      fix={"de": "„Netzwerksicherheit: Keine LAN Manager-Hashwerte … speichern“ aktivieren und Passwörter ändern.",
           "en": "Enable 'Do not store LAN Manager hash value' and reset passwords."},
      columns=["value", "gpo"], platforms=("windows",))
def _lmhash(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("all"), r"Control\Lsa\NoLMHash") if as_num(v) == 0]
    return Hit([{"value": "0", "gpo": _gpo_list(ctx, vals)}]) if vals else None


@rule(id="A-ZeroLogon", category="anomalies", severity="critical", points=25,
      title={"de": "Unsichere Netlogon-Verbindungen erlaubt (ZeroLogon)", "en": "Vulnerable Netlogon connections allowed (ZeroLogon)"},
      desc={"de": "Eine Richtlinie lässt anfällige Netlogon-Verbindungen zu oder schaltet den vollständigen Schutz ab. "
                  "Damit ist CVE-2020-1472 (ZeroLogon) ausnutzbar – die Übernahme eines DCs ohne Passwort.",
            "en": "A policy allows vulnerable Netlogon connections (CVE-2020-1472)."},
      fix={"de": "„Domänencontroller: Anfällige Netlogon-Verbindungen für sicheren Kanal zulassen“ entfernen und "
                 "FullSecureChannelProtection nicht auf 0 setzen.",
           "en": "Remove the vulnerable channel allow list and keep FullSecureChannelProtection enabled."},
      columns=["detail", "gpo"], platforms=("windows",),
      refs=[("Microsoft KB4557222", "https://support.microsoft.com/kb/4557222")])
def _zerologon(ctx: Ctx):
    items = []
    al = gpo_values(ctx, ctx.gpo_guids("dc"), r"Netlogon\Parameters\VulnerableChannelAllowList")
    if al:
        items.append({"detail": "VulnerableChannelAllowList", "gpo": _gpo_list(ctx, al)})
    fs = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("dc"), r"Netlogon\Parameters\FullSecureChannelProtection")
          if as_num(v) == 0]
    if fs:
        items.append({"detail": "FullSecureChannelProtection=0", "gpo": _gpo_list(ctx, fs)})
    return Hit(items) if items else None


@rule(id="A-RefusePwdChange", category="anomalies", severity="medium", points=5,
      title={"de": "DCs verweigern Änderungen von Computerkennwörtern", "en": "DCs refuse machine password changes"},
      desc={"de": "Mit „RefusePasswordChange“ behalten Computerkonten ihr Passwort dauerhaft – gestohlene Maschinen-Hashes "
                  "bleiben gültig.",
            "en": "With RefusePasswordChange computer passwords never rotate."},
      fix={"de": "„Domänencontroller: Änderungen von Computerkontenkennwörtern ablehnen“ deaktivieren.",
           "en": "Disable 'Refuse machine account password changes'."},
      columns=["gpo"], platforms=("windows",))
def _refuse(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("dc"), r"Netlogon\Parameters\RefusePasswordChange")
            if as_num(v) == 1]
    return Hit([{"gpo": _gpo_list(ctx, vals)}]) if vals else None


@rule(id="A-KerberosEncDC", category="anomalies", severity="medium", points=10,
      title={"de": "Schwache Kerberos-Verschlüsselung per Richtlinie erlaubt", "en": "Weak Kerberos encryption allowed by policy"},
      desc={"de": "Die Richtlinie „Für Kerberos zulässige Verschlüsselungstypen“ erlaubt DES oder RC4. RC4-Tickets "
                  "erleichtern Kerberoasting erheblich; Microsoft schaltet RC4 schrittweise ab.",
            "en": "The policy allows DES or RC4 for Kerberos."},
      fix={"de": "Nur AES128/AES256 (und ggf. zukünftige Verfahren) zulassen; vorher Ereignisse 4768/4769 auf RC4 prüfen.",
           "en": "Allow AES only after checking events 4768/4769 for RC4 usage."},
      columns=["value", "detail", "gpo"], platforms=("windows",))
def _krb_enc(ctx: Ctx):
    vals = gpo_values(ctx, ctx.gpo_guids("dc"), r"Kerberos\Parameters\SupportedEncryptionTypes")
    if not vals:
        return None
    g, v = vals[-1]
    n = as_num(v)
    if n is None:
        return None
    if n & 0x3:
        return Hit([{"value": hex(n), "detail": "DES", "gpo": ctx.gpo_name(g)}], points=15, severity="high")
    if n & 0x4:
        return Hit([{"value": hex(n), "detail": "RC4", "gpo": ctx.gpo_name(g)}], points=2, severity="low")
    return None


@rule(id="A-SMBClientSigning", category="anomalies", severity="low", points=2,
      title={"de": "SMB-Client-Signierung auf DCs deaktiviert", "en": "SMB client signing disabled on DCs"},
      desc={"de": "Verbindungen, die ein DC selbst aufbaut (z. B. zu SYSVOL anderer DCs), sind ohne Signierung manipulierbar.",
            "en": "SMB connections made by DCs can be tampered with."},
      fix={"de": "„Microsoft-Netzwerk (Client): Kommunikation digital signieren (immer)“ aktivieren.",
           "en": "Enable 'Microsoft network client: Digitally sign communications (always)'."},
      columns=["gpo"], platforms=("windows",))
def _smb_client(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("dc"), r"LanmanWorkstation\Parameters\RequireSecuritySignature")
            if as_num(v) == 0]
    return Hit([{"gpo": _gpo_list(ctx, vals)}]) if vals else None


@rule(id="A-WDigest", category="anomalies", severity="critical", points=20,
      title={"de": "WDigest speichert Klartext-Passwörter", "en": "WDigest stores cleartext passwords"},
      desc={"de": "Eine Richtlinie setzt UseLogonCredential=1. Dann liegen Passwörter angemeldeter Benutzer im Klartext im "
                  "Speicher und lassen sich mit Standardwerkzeugen auslesen.",
            "en": "UseLogonCredential=1 keeps cleartext passwords in memory."},
      fix={"de": "Wert auf 0 setzen oder Einstellung entfernen.", "en": "Set the value to 0 or remove it."},
      columns=["gpo"], platforms=("windows",))
def _wdigest(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("all"), r"SecurityProviders\WDigest\UseLogonCredential")
            if as_num(v) == 1]
    return Hit([{"gpo": _gpo_list(ctx, vals)}]) if vals else None


@rule(id="A-AlwaysInstallElevated", category="anomalies", severity="high", points=15,
      title={"de": "„Immer mit erhöhten Rechten installieren“ aktiviert", "en": "'Always install elevated' enabled"},
      desc={"de": "Jeder Benutzer kann damit beliebige MSI-Pakete mit SYSTEM-Rechten installieren – eine sofortige "
                  "Rechteausweitung auf allen betroffenen Rechnern.",
            "en": "Any user can install MSI packages as SYSTEM – instant privilege escalation."},
      fix={"de": "Einstellung in allen GPOs deaktivieren; Software über Verteilungswerkzeuge ausrollen.",
           "en": "Disable the setting; deploy software via management tools."},
      columns=["gpo"], platforms=("windows",),
      refs=[("MITRE ATT&CK T1548", f"{ATT}/T1548/")])
def _aie(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("all"), r"Windows\Installer\AlwaysInstallElevated")
            if as_num(v) == 1]
    return Hit([{"gpo": _gpo_list(ctx, vals)}]) if vals else None


@rule(id="A-WSUSHttp", category="anomalies", severity="high", points=15,
      title={"de": "WSUS über unverschlüsseltes HTTP", "en": "WSUS over unencrypted HTTP"},
      desc={"de": "Updates werden per HTTP bezogen. Ein Angreifer im Netz kann gefälschte „Updates“ einspielen und Code mit "
                  "SYSTEM-Rechten auf allen Clients ausführen.",
            "en": "Updates are fetched over HTTP; an attacker can inject fake updates."},
      fix={"de": "WSUS auf HTTPS (Port 8531) umstellen und die GPO-Adresse anpassen.", "en": "Switch WSUS to HTTPS (8531)."},
      columns=["value", "gpo"], platforms=("windows",))
def _wsus(ctx: Ctx):
    vals = [(g, v) for g, v in gpo_values(ctx, ctx.gpo_guids("all"), r"WindowsUpdate\WUServer")
            if str(v).lower().startswith("http://")]
    return Hit([{"value": str(v), "gpo": ctx.gpo_name(g)} for g, v in vals]) if vals else None


@rule(id="A-LLMNR", category="anomalies", severity="medium", points=5,
      title={"de": "LLMNR nicht per Richtlinie deaktiviert", "en": "LLMNR not disabled by policy"},
      desc={"de": "Über LLMNR (und NetBIOS) beantworten Angreifer fehlgeschlagene Namensauflösungen und fangen so "
                  "Anmeldedaten ab (Responder).",
            "en": "Attackers answer failed name resolutions via LLMNR and capture credentials."},
      fix={"de": "GPO „DNS-Client: Multicastnamensauflösung deaktivieren“ = Aktiviert; NetBIOS über DHCP deaktivieren.",
           "en": "Enable 'Turn off multicast name resolution'; disable NetBIOS via DHCP."},
      columns=["value"], platforms=("windows",),
      refs=[("MITRE ATT&CK T1557.001", f"{ATT}/T1557/001/")])
def _llmnr(ctx: Ctx):
    vals = gpo_values(ctx, ctx.gpo_guids("all"), r"Windows NT\DNSClient\EnableMulticast")
    return None if any(as_num(v) == 0 for _, v in vals) else Hit([{"value": "@v_not_configured"}])


@rule(id="A-PSLogging", category="anomalies", severity="low", points=2,
      title={"de": "PowerShell-Skriptblockprotokollierung nicht aktiv", "en": "PowerShell script block logging not enabled"},
      desc={"de": "Ohne Skriptblockprotokollierung sind Angriffe mit PowerShell kaum nachvollziehbar.",
            "en": "Without script block logging PowerShell attacks are hard to trace."},
      fix={"de": "GPO „PowerShell-Skriptblockprotokollierung aktivieren“ setzen und Protokolle zentral sammeln.",
           "en": "Enable 'Turn on PowerShell Script Block Logging' and collect logs centrally."},
      columns=["value"], platforms=("windows",))
def _pslog(ctx: Ctx):
    vals = gpo_values(ctx, ctx.gpo_guids("all"), r"PowerShell\ScriptBlockLogging\EnableScriptBlockLogging")
    return None if any(as_num(v) == 1 for _, v in vals) else Hit([{"value": "@v_not_configured"}])


@rule(id="A-LSAProtection", category="anomalies", severity="low", points=2,
      title={"de": "LSA-Schutz (RunAsPPL) nicht per Richtlinie aktiviert", "en": "LSA protection (RunAsPPL) not enforced"},
      desc={"de": "Der LSA-Schutz erschwert das Auslesen von Anmeldedaten aus dem Speicher (z. B. mit Mimikatz).",
            "en": "LSA protection makes dumping credentials from memory harder."},
      fix={"de": "RunAsPPL per GPO auf 1 (bzw. 2 ohne UEFI-Sperre) setzen, vorher Kompatibilität von LSA-Plugins prüfen.",
           "en": "Set RunAsPPL to 1 via GPO after checking LSA plug-in compatibility."},
      columns=["value"], platforms=("windows",))
def _ppl(ctx: Ctx):
    vals = gpo_values(ctx, ctx.gpo_guids("all"), r"Control\Lsa\RunAsPPL")
    return None if any((as_num(v) or 0) >= 1 for _, v in vals) else Hit([{"value": "@v_not_configured"}])


@rule(id="A-ScriptPasswords", category="anomalies", severity="high", points=15,
      title={"de": "Mögliche Passwörter in Anmeldeskripten", "en": "Possible passwords in logon scripts"},
      desc={"de": "In Skripten auf NETLOGON/SYSVOL stehen Zeilen, die nach Zugangsdaten aussehen. Diese Freigaben sind für "
                  "jeden Domänenbenutzer lesbar.",
            "en": "Scripts on NETLOGON/SYSVOL contain lines that look like credentials; these shares are readable by all users."},
      fix={"de": "Fundstellen prüfen, Zugangsdaten aus den Skripten entfernen und betroffene Passwörter ändern.",
           "en": "Review, remove the credentials and change the affected passwords."},
      columns=["file", "line", "kind"],
      refs=[("MITRE ATT&CK T1552.001", f"{ATT}/T1552/001/")])
def _scripts(ctx: Ctx):
    sv = need_sysvol(ctx)
    hits = sv.get("script_secrets") or []
    return Hit([{"file": h["file"], "line": str(h["line"]), "kind": h["kind"]} for h in hits]) if hits else None
