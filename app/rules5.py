# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Rule catalogue part 5 (since v2.4): Credential Guard via Group Policy, Samba release series past their end of
life and computer accounts whose DNS host name does not match their logon name (Certifried leftovers)."""
from __future__ import annotations

import re
from datetime import date

from .analysis import Ctx
from .rules import Hit, NotApplicable, rule
from .rules2 import as_num, gpo_values

MS = "https://learn.microsoft.com"


# ===========================================================================
# ANOMALIES
# ===========================================================================

CG_LSA_KEYS = (r"Microsoft\Windows\DeviceGuard\LsaCfgFlags",      # ADMX "Turn On Virtualization Based Security"
               r"CurrentControlSet\Control\Lsa\LsaCfgFlags")       # set directly (GPP / security template)
CG_VBS_KEY = r"Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity"


@rule(id="A-CredentialGuard", category="anomalies", severity="info", points=1,
      title={"de": "Credential Guard nicht per Gruppenrichtlinie aktiviert",
             "en": "Credential Guard not enabled via Group Policy"},
      desc={"de": "Credential Guard schützt Anmeldedaten im Speicher (NTLM-Hashes, Kerberos-Tickets) durch "
                  "virtualisierungsbasierte Sicherheit (VBS) – Werkzeuge wie Mimikatz kommen dann nicht mehr an sie heran. "
                  "Geprüft wird nur, ob eine verknüpfte Gruppenrichtlinie Credential Guard einschaltet oder ausdrücklich "
                  "abschaltet. Auf Windows 11 ab 22H2 (Enterprise/Education) und Windows Server 2025 ist Credential Guard "
                  "auf geeigneter Hardware ohnehin standardmäßig aktiv; außerdem kann es über Intune/MDM gesetzt sein. "
                  "Beides ist per LDAP/SYSVOL nicht sichtbar – deshalb nur ein Hinweis. Eine Richtlinie, die es "
                  "ausdrücklich abschaltet, wird stärker gewichtet.",
            "en": "Credential Guard protects credentials in memory (NTLM hashes, Kerberos tickets) with "
                  "virtualization-based security (VBS), so tools like Mimikatz can no longer reach them. Only checks "
                  "whether a linked GPO enables or explicitly disables Credential Guard. On Windows 11 22H2+ "
                  "(Enterprise/Education) and Windows Server 2025 it is on by default on capable hardware, and it can "
                  "also be set via Intune/MDM – neither is visible via LDAP/SYSVOL, hence only a hint. A GPO that "
                  "explicitly disables it is weighted higher."},
      fix={"de": "Gruppenrichtlinie für Arbeitsplätze und Server (nicht für Domänencontroller – dort bringt Credential "
                 "Guard keinen Schutz für die AD-Datenbank): Computerkonfiguration → Administrative Vorlagen → System → "
                 "Device Guard → „Virtualisierungsbasierte Sicherheit aktivieren“ = Aktiviert, Plattform „Sicherer "
                 "Start“, „Credential Guard-Konfiguration“ = „Mit UEFI-Sperre aktiviert“ (oder ohne Sperre, solange "
                 "noch getestet wird). Vorher prüfen, ob Anwendungen NTLMv1, MS-CHAPv2 (z. B. WLAN/VPN mit PEAP) oder "
                 "Kerberos-DES/uneingeschränkte Delegierung brauchen – das funktioniert danach nicht mehr.",
           "en": "GPO for workstations and servers (not domain controllers – there it does not protect the AD "
                 "database): Computer Configuration → Administrative Templates → System → Device Guard → 'Turn On "
                 "Virtualization Based Security' = Enabled, platform 'Secure Boot', 'Credential Guard Configuration' = "
                 "'Enabled with UEFI lock' (or without lock while testing). First check whether applications need "
                 "NTLMv1, MS-CHAPv2 (e.g. Wi-Fi/VPN with PEAP) or Kerberos DES/unconstrained delegation – these stop "
                 "working."},
      code="# auf einem Client prüfen (2 = Credential Guard läuft)\n"
           "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard)"
           ".SecurityServicesRunning",
      columns=["gpo", "detail", "value"], platforms=("windows",),
      refs=[("Microsoft: Configure Credential Guard",
             f"{MS}/windows/security/identity-protection/credential-guard/configure"),
            ("Microsoft: Credential Guard considerations",
             f"{MS}/windows/security/identity-protection/credential-guard/considerations-known-issues")])
def _credential_guard(ctx: Ctx):
    enabled, off, unreadable = False, [], None
    for g in ctx.gpo_guids("all"):
        try:
            lsa = [(k, v) for k in CG_LSA_KEYS for _, v in gpo_values(ctx, [g], k)]
            vbs = gpo_values(ctx, [g], CG_VBS_KEY)
        except NotApplicable as e:          # e.g. GPO with security filtering – still evaluate the others
            unreadable = e
            continue
        for _k, v in lsa:
            n = as_num(v)
            if n in (1, 2):
                enabled = True
            elif n == 0:
                off.append({"gpo": ctx.gpo_name(g), "detail": "@v_cg_off", "value": f"LsaCfgFlags={v}"})
        for _, v in vbs:
            if as_num(v) == 0:
                off.append({"gpo": ctx.gpo_name(g), "detail": "@v_vbs_off",
                            "value": f"EnableVirtualizationBasedSecurity={v}"})
    if off:
        return Hit(off, severity="low", points=3)
    if enabled:
        return None
    if unreadable is not None:
        raise unreadable
    return Hit([{"gpo": "–", "detail": "@v_not_configured", "value": "LsaCfgFlags"}], note="@n_cg_default")


# End of life per Samba release series (wiki.samba.org "Samba Release Planning", endoflife.date/samba).
# Series older than 4.15 have long been unsupported; newer series are only added once their end date is fixed.
SAMBA_EOL = {
    15: date(2023, 3, 8), 16: date(2023, 9, 4), 17: date(2024, 3, 27), 18: date(2024, 9, 2),
    19: date(2025, 3, 6), 20: date(2025, 9, 12), 21: date(2026, 3, 31), 22: date(2026, 9, 30),
}
SAMBA_OLDEST_LISTED = min(SAMBA_EOL)
_SAMBA_VER = re.compile(r"(?<![\d.])4\.(\d{1,2})\.(\d{1,3})(?![\d])")


def samba_version(text: str | None) -> tuple[int, str] | None:
    """'Samba Team (https://www.samba.org) 4.15.13-Synology' → (15, '4.15.13-Synology')."""
    m = _SAMBA_VER.search(text or "")
    if not m:
        return None
    tail = re.match(r"[\w.+~-]*", (text or "")[m.end():])
    return int(m.group(1)), m.group(0) + (tail.group(0) if tail else "")


@rule(id="A-SambaEOL", category="anomalies", severity="info", points=0,
      title={"de": "Samba-Reihe der Domänencontroller vom Samba-Team nicht mehr gepflegt",
             "en": "Samba series of the domain controllers no longer maintained by the Samba team"},
      desc={"de": "Das Samba-Team pflegt jeweils nur die drei jüngsten Versionsreihen; ältere bekommen von dort keine "
                  "Sicherheitskorrekturen mehr. Viele Hersteller (z. B. Synology, Ubuntu, Red Hat, Debian) übernehmen "
                  "wichtige Korrekturen aber selbst in ihre ältere Reihe – entscheidend ist also, ob der Hersteller "
                  "Ihres Systems noch Updates liefert. Deshalb nur ein Hinweis ohne Punkte. Die Version stammt aus dem "
                  "rootDSE (vendorVersion) bzw. dem Computerkonto des DCs.",
            "en": "The Samba team only maintains the three most recent release series; older ones no longer receive "
                  "security fixes from upstream. Many vendors (e.g. Synology, Ubuntu, Red Hat, Debian) backport "
                  "important fixes into their older series, so what matters is whether your system's vendor still "
                  "ships updates – hence only a hint without points. The version comes from the rootDSE "
                  "(vendorVersion) or the DC's computer account."},
      fix={"de": "Beim Hersteller prüfen, ob die eingesetzte Samba-Version noch Sicherheitsupdates bekommt, und alle "
                 "Updates einspielen. Mittelfristig auf eine aktuelle, vom Samba-Team gepflegte Reihe wechseln "
                 "(bei Appliances: Firmware-/Paketupdate des Herstellers).",
           "en": "Ask the vendor whether the Samba version in use still receives security updates and install all "
                 "updates. In the medium term move to a current series maintained by the Samba team (appliances: "
                 "vendor firmware/package update)."},
      code="samba -V\nsamba-tool domain level show",
      columns=["host", "value", "detail"], platforms=("samba",),
      refs=[("Samba Release Planning", "https://wiki.samba.org/index.php/Samba_Release_Planning"),
            ("endoflife.date: Samba", "https://endoflife.date/samba")])
def _samba_eol(ctx: Ctx):
    found: dict[str, tuple[int, str]] = {}
    for dc in ctx.computers:
        if not (dc.get("is_dc") or dc.get("is_rodc")):
            continue
        v = samba_version(dc.get("os_version")) or samba_version(dc.get("os"))
        if v:
            found[(dc.get("sam") or "").rstrip("$") or dc.get("dns") or "?"] = v
    meta = ctx.m.get("meta") or {}
    v = samba_version(meta.get("vendor"))
    if v and not found:
        host = (meta.get("dc_host") or "rootDSE").split(".", 1)[0]
        found[host.upper() if host != "rootDSE" else host] = v
    if not found:
        raise NotApplicable("na_samba_version")
    today = ctx.now.date()
    items = []
    for host, (series, full) in sorted(found.items()):
        if series < SAMBA_OLDEST_LISTED:
            items.append({"host": host, "value": full, "detail": "@v_samba_eol_old"})
        elif series in SAMBA_EOL and SAMBA_EOL[series] <= today:
            items.append({"host": host, "value": full, "detail": f"@v_samba_eol|{SAMBA_EOL[series].isoformat()}"})
    return Hit(items) if items else None


@rule(id="A-DnsHostnameMismatch", category="anomalies", severity="low", points=3,
      title={"de": "DNS-Name passt nicht zum Computerkonto (Certifried-Spur)",
             "en": "DNS host name does not match the computer account (Certifried trace)"},
      desc={"de": "Der dNSHostName eines Computerkontos beginnt normalerweise mit seinem Anmeldenamen (ohne „$“, auf 15 "
                  "Zeichen gekürzt). Weicht er ab, wurde er nachträglich geändert. Beim Angriff „Certifried“ "
                  "(CVE-2022-26923) setzen Angreifer den dNSHostName eines selbst angelegten Computers auf den Namen "
                  "eines Domänencontrollers und lassen sich ein Zertifikat für den DC ausstellen. Trägt ein normales "
                  "Computerkonto den DNS-Namen eines DCs, ist das ein ernstes Warnsignal. Andere Abweichungen sind oft "
                  "harmlos (Umbenennungen, Fremdsysteme), sollten aber geklärt werden.",
            "en": "A computer account's dNSHostName normally starts with its logon name (without '$', truncated to 15 "
                  "characters). A mismatch means it was changed later. In the 'Certifried' attack (CVE-2022-26923) "
                  "attackers set the dNSHostName of a computer they created to a domain controller's name and obtain a "
                  "certificate for the DC. A normal computer carrying a DC's DNS name is a serious red flag; other "
                  "mismatches are often harmless (renames, third-party systems) but should be explained."},
      fix={"de": "Abweichende Konten klären und korrigieren bzw. löschen. Trägt ein Konto den Namen eines DCs: als "
                 "Sicherheitsvorfall behandeln (Ersteller/Besitzer des Kontos ermitteln, ausgestellte Zertifikate "
                 "der CA prüfen und widerrufen). ms-DS-MachineAccountQuota auf 0 setzen.",
           "en": "Review and fix or delete the mismatching accounts. If an account carries a DC's name: treat it as a "
                 "security incident (find the account's creator/owner, review and revoke certificates issued by the "
                 "CA). Set ms-DS-MachineAccountQuota to 0."},
      code="Get-ADComputer -Filter * -Properties dNSHostName | Where-Object {\n"
           "  $_.dNSHostName -and ($_.dNSHostName.Split('.')[0] -ne $_.Name) } | Select Name, dNSHostName",
      columns=["account", "dns", "detail"],
      refs=[("Microsoft: CVE-2022-26923", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"),
            ("Oliver Lyak: Certifried", "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4")])
def _dns_mismatch(ctx: Ctx):
    dc_dns = {(c.get("dns") or "").lower(): c for c in ctx.computers
              if (c.get("is_dc") or c.get("is_rodc")) and c.get("dns")}
    items, critical = [], False
    for c in ctx.computers:
        dns, sam = (c.get("dns") or "").strip().lower(), (c.get("sam") or "").lower()
        if not dns or not sam.endswith("$") or c.get("is_dc") or c.get("is_rodc"):
            continue
        name = sam[:-1]
        label = dns.split(".", 1)[0]
        if dns in dc_dns and dc_dns[dns] is not c:
            items.append({"account": c["sam"], "dns": c.get("dns"), "detail": "@v_dns_is_dc"})
            critical = True
        elif label[:15] != name[:15]:
            items.append({"account": c["sam"], "dns": c.get("dns"), "detail": "@v_dns_mismatch"})
    if not items:
        return None
    return Hit(items, severity="critical", points=25) if critical else Hit(items)
