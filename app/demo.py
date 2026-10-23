# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Demo-Daten: eine fiktive Domäne mit typischen Schwachstellen.
Wird nur verwendet, wenn DEMO_MODE=true gesetzt ist."""
from __future__ import annotations

import random
from datetime import timedelta

from .adutil import (
    ADS_RIGHT_DS_CONTROL_ACCESS, ADS_RIGHT_GENERIC_ALL, ADS_RIGHT_WRITE_DAC, GUID_CERT_ENROLL,
    GUID_DS_REPL_GET_CHANGES, GUID_DS_REPL_GET_CHANGES_ALL, UAC_ACCOUNTDISABLE, UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH, UAC_ENCRYPTED_TEXT_PWD_ALLOWED, UAC_NORMAL_ACCOUNT, UAC_PASSWD_NOTREQD,
    UAC_SERVER_TRUST_ACCOUNT, UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
    UAC_USE_DES_KEY_ONLY, UAC_WORKSTATION_TRUST_ACCOUNT, now_utc,
)

DOM_SID = "S-1-5-21-1004336348-1177238915-682003330"
DMSA_GUID = "0feb936f-47b3-49f2-9386-1dedc2c23765"
DN = "DC=firma,DC=local"
FQDN = "firma.local"

FIRST = ["Anna", "Ben", "Clara", "David", "Emma", "Felix", "Greta", "Hannah", "Jonas", "Klara", "Lukas", "Marie",
         "Noah", "Olivia", "Paul", "Lena", "Tim", "Sophie", "Jan", "Laura", "Max", "Mia", "Leon", "Julia", "Finn",
         "Lea", "Tom", "Nina", "Erik", "Sara"]
LAST = ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz", "Hoffmann",
        "Koch", "Richter", "Klein", "Wolf", "Schröder", "Neumann", "Schwarz", "Braun", "Zimmermann", "Krüger",
        "Hartmann", "Lange", "Werner", "Krause", "Lehmann", "Köhler", "Maier", "Huber", "Kaiser", "Fuchs"]


def build() -> dict:
    rnd = random.Random(4711)
    now = now_utc()
    ago = lambda days: now - timedelta(days=days)  # noqa: E731
    rid_counter = [2000]

    def next_rid():
        rid_counter[0] += 1
        return rid_counter[0]

    users: list[dict] = []
    computers: list[dict] = []

    def user(sam, ou="OU=Mitarbeiter", rid=None, uac=UAC_NORMAL_ACCOUNT, last=5, pwd=60, created=900,
             spns=None, pgid=513, admin_count=0, **kw):
        rid = rid or next_rid()
        u = {
            "dn": f"CN={sam},{ou},{DN}" if ou else f"CN={sam},CN=Users,{DN}", "sam": sam,
            "sid": f"{DOM_SID}-{rid}", "rid": rid, "uac": uac, "enabled": not (uac & UAC_ACCOUNTDISABLE),
            "last_logon": ago(last) if last is not None else None, "pwd_last_set": ago(pwd) if pwd is not None else None,
            "created": ago(created), "spns": spns or [], "primary_gid": pgid, "sid_history": [], "enc_types": None,
            "delegate_to": [], "rbcd": False, "classes": ["top", "person", "user"], "upn": f"{sam}@{FQDN}", "key_cred": False,
            "display": sam, "has_userpassword": False, "is_gmsa": False, "admin_count": admin_count,
        }
        u.update(kw)
        users.append(u)
        return u

    # --- eingebaute Konten ------------------------------------------------
    user("Administrator", ou=None, rid=500, uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD, last=2, pwd=2310,
         created=3100)
    user("Guest", ou=None, rid=501, uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE | UAC_PASSWD_NOTREQD, last=None,
         pwd=None, created=3100)
    user("krbtgt", ou=None, rid=502, uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE, last=None, pwd=2050, created=3100)

    # --- Administratoren --------------------------------------------------
    ou_adm = "OU=Admins,OU=IT"
    adm = [user(n, ou=ou_adm, last=rnd.randint(1, 20), pwd=rnd.randint(30, 300)) for n in
           ("adm.mueller", "adm.schmidt", "adm.weber", "adm.fischer", "adm.wagner")]
    adm_old = user("adm.altmann", ou=ou_adm, last=410, pwd=1500, uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD)
    svc_backup = user("svc_backup", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                      last=1, pwd=1850, spns=["MSSQLSvc/srv-backup01.firma.local:1433"])
    t_becker = user("t.becker", last=3, pwd=40)
    hilfe = user("hilfe.it", ou="OU=IT", last=12, pwd=200, pgid=512)
    svc_sql = user("svc_sql", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                   last=1, pwd=2400, spns=["MSSQLSvc/srv-sql01.firma.local:1433", "MSSQLSvc/srv-sql01.firma.local"])
    user("svc_web", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD, last=2,
         pwd=1300, spns=["HTTP/intranet.firma.local"], enc_types=0x1F)
    user("svc_sap", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD, last=1,
         pwd=700, spns=["SAP/sap-prod.firma.local"], enc_types=0x4)
    user("m.praktikant", last=3, pwd=50, spns=["HTTP/intranet.firma.local\u200b"])
    user("p.weiss", last=6, pwd=80, upn="Administrator")
    user("vertrieb.zert", last=9, pwd=120, alt_sec_ids=["X509:<RFC822>vertrieb@firma.de"])
    user("krbtgt_18842", ou=None, uac=UAC_NORMAL_ACCOUNT | UAC_ACCOUNTDISABLE, last=None, pwd=1200, created=1300)
    svc_sync = user("svc_sync", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD,
                    last=1, pwd=900)
    msol = user("MSOL_6f1c2a9e44b1", ou=None, uac=UAC_NORMAL_ACCOUNT | UAC_DONT_EXPIRE_PASSWORD, last=1, pwd=500)
    user("svc_scan", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_REQ_PREAUTH |
         UAC_DONT_EXPIRE_PASSWORD, last=30, pwd=1600)
    user("drucker.lager", uac=UAC_NORMAL_ACCOUNT | UAC_DONT_REQ_PREAUTH, last=90, pwd=700)
    user("kiosk01", uac=UAC_NORMAL_ACCOUNT | UAC_PASSWD_NOTREQD, last=4, pwd=800)
    user("legacy.app", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_ENCRYPTED_TEXT_PWD_ALLOWED,
         last=20, pwd=1000)
    user("unix.sync", ou="OU=Dienstkonten,OU=IT", uac=UAC_NORMAL_ACCOUNT | UAC_USE_DES_KEY_ONLY, last=60, pwd=1900,
         has_userpassword=True)
    user("j.migration", last=7, pwd=100, sid_history=["S-1-5-21-555111222-333444555-666777888-1150"])
    user("ex.mitarbeiter1", last=40, pwd=500, admin_count=1)
    user("ex.mitarbeiter2", last=200, pwd=600, admin_count=1)
    gmsa = user("gmsa_sql$", ou="CN=Managed Service Accounts", uac=UAC_WORKSTATION_TRUST_ACCOUNT, last=1, pwd=20,
                spns=["MSSQLSvc/srv-sql02.firma.local:1433"], pgid=515, is_gmsa=True,
                classes=["top", "computer", "msds-groupmanagedserviceaccount"])

    # --- normale Benutzer -------------------------------------------------
    seen = {u["sam"] for u in users}
    for i in range(420):
        fn, ln = rnd.choice(FIRST), rnd.choice(LAST)
        sam = f"{fn[0].lower()}.{ln.lower().replace('ü', 'ue').replace('ö', 'oe').replace('ä', 'ae')}"
        if sam in seen:
            sam += str(i)
        seen.add(sam)
        r = rnd.random()
        uac = UAC_NORMAL_ACCOUNT
        last = rnd.randint(0, 25)
        if r < 0.09:
            uac |= UAC_DONT_EXPIRE_PASSWORD
        if 0.09 <= r < 0.22:
            last = rnd.randint(200, 900)  # inaktiv
        if 0.22 <= r < 0.25:
            last = None  # nie angemeldet
        if 0.25 <= r < 0.32:
            uac |= UAC_ACCOUNTDISABLE
            last = rnd.randint(200, 1500)
        user(sam, last=last, pwd=rnd.randint(1, 400), created=rnd.randint(250, 2900), uac=uac,
             display=f"{fn} {ln}")

    # --- Computer ---------------------------------------------------------
    def comp(name, os_name, ou="OU=Clients", last=2, pwd=15, created=700, uac=UAC_WORKSTATION_TRUST_ACCOUNT,
             laps=True, pgid=515, **kw):
        rid = next_rid()
        dns = f"{name.lower()}.{FQDN}"
        c = {
            "dn": f"CN={name},{ou},{DN}", "sam": name + "$", "sid": f"{DOM_SID}-{rid}", "rid": rid, "uac": uac,
            "enabled": not (uac & UAC_ACCOUNTDISABLE), "last_logon": ago(last) if last is not None else None,
            "pwd_last_set": ago(pwd), "created": ago(created), "spns": [f"HOST/{dns}", f"HOST/{name}"],
            "primary_gid": pgid, "sid_history": [], "enc_types": 28, "delegate_to": [], "rbcd": False,
            "classes": ["top", "computer"], "dns": dns, "os": os_name, "os_version": "", "laps": laps, "key_cred": False,
            "reveal_on_demand": [], "never_reveal": [], "revealed": [], "owner": None,
            "is_dc": bool(uac & UAC_SERVER_TRUST_ACCOUNT), "is_rodc": False,
        }
        c.update(kw)
        computers.append(c)
        return c

    dc_uac = UAC_SERVER_TRUST_ACCOUNT | UAC_TRUSTED_FOR_DELEGATION
    dc01 = comp("DC01", "Windows Server 2019 Standard", ou="OU=Domain Controllers", uac=dc_uac, laps=False, pgid=516,
         last=0, pwd=10, created=2400)
    dc02 = comp("DC02", "Windows Server 2012 R2 Standard", ou="OU=Domain Controllers", uac=dc_uac, laps=False, pgid=516,
         last=1, pwd=12, created=3000)
    comp("DC03", "Windows Server 2025 Standard", ou="OU=Domain Controllers", uac=dc_uac, laps=False, pgid=516,
         last=0, pwd=8, created=120)
    comp("SRV-APP01", "Windows Server 2016 Standard", ou="OU=Server",
         uac=UAC_WORKSTATION_TRUST_ACCOUNT | UAC_TRUSTED_FOR_DELEGATION, laps=False)
    comp("SRV-WEB01", "Windows Server 2022 Standard", ou="OU=Server",
         uac=UAC_WORKSTATION_TRUST_ACCOUNT | UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
         delegate_to=["cifs/dc01.firma.local", "cifs/DC01"])
    comp("SRV-FILE01", "Windows Server 2022 Standard", ou="OU=Server", rbcd=True)
    comp("SRV-SQL01", "Windows Server 2019 Standard", ou="OU=Server")
    comp("SRV-BACKUP01", "Windows Server 2016 Standard", ou="OU=Server", laps=False)
    comp("SRV-LEGACY", "Windows Server 2008 R2 Enterprise", ou="OU=Server", laps=False, last=3)
    comp("SRV-PRINT01", "Windows Server 2016 Standard", ou="OU=Server", last=260)
    comp("NAS-ARCHIV", "Samba 4.15.13-Ubuntu", ou="OU=Server", laps=False)
    for i in range(1, 141):
        r = rnd.random()
        if r < 0.70:
            osn = "Windows 11 Pro"
        elif r < 0.93:
            osn = "Windows 10 Pro"
        elif r < 0.96:
            osn = "Windows 7 Professional"
        else:
            osn = "Windows 11 Enterprise"
        last = rnd.randint(0, 14) if rnd.random() > 0.13 else rnd.randint(190, 700)
        comp(f"PC-{i:04d}", osn, last=last, laps=rnd.random() < 0.62)
    rodc = comp("RODC-FIL01", "Windows Server 2022 Standard", ou="OU=Domain Controllers",
                uac=0x04001000 | UAC_WORKSTATION_TRUST_ACCOUNT, laps=False, pgid=521, is_rodc=True, last=1)
    comp("AZUREADSSOACC", "", ou="CN=Computers", laps=False, pwd=420, last=None, created=900)
    for c in computers[12:16]:
        c["pwd_last_set"] = ago(rnd.randint(150, 400))
        c["last_logon"] = ago(2)
    comp("PC-ALT01", "Windows XP Professional", last=1200, laps=False, uac=UAC_WORKSTATION_TRUST_ACCOUNT |
         UAC_PASSWD_NOTREQD)

    # --- Gruppen ----------------------------------------------------------
    def gdn(name, ou="CN=Users"):
        return f"CN={name},{ou},{DN}"

    it_admins = gdn("IT-Admins", "OU=Gruppen,OU=IT")
    helpdesk = gdn("Helpdesk", "OU=Gruppen,OU=IT")
    groups = [
        {"dn": gdn("Domain Admins"), "sam": "Domain Admins", "sid": f"{DOM_SID}-512", "rid": 512,
         "members": [users[0]["dn"], adm[0]["dn"], adm[1]["dn"], adm[2]["dn"], adm_old["dn"], svc_backup["dn"],
                     t_becker["dn"], it_admins]},
        {"dn": it_admins, "sam": "IT-Admins", "sid": f"{DOM_SID}-1050", "rid": 1050,
         "members": [adm[3]["dn"], adm[4]["dn"]]},
        {"dn": helpdesk, "sam": "Helpdesk", "sid": f"{DOM_SID}-1051", "rid": 1051, "members": []},
        {"dn": gdn("Enterprise Admins"), "sam": "Enterprise Admins", "sid": f"{DOM_SID}-519", "rid": 519,
         "members": [users[0]["dn"], adm[4]["dn"]]},
        {"dn": gdn("Schema Admins"), "sam": "Schema Admins", "sid": f"{DOM_SID}-518", "rid": 518,
         "members": [users[0]["dn"]]},
        {"dn": f"CN=Administrators,CN=Builtin,{DN}", "sam": "Administrators", "sid": "S-1-5-32-544", "rid": 544,
         "members": [users[0]["dn"], gdn("Domain Admins"), gdn("Enterprise Admins")]},
        {"dn": f"CN=Account Operators,CN=Builtin,{DN}", "sam": "Account Operators", "sid": "S-1-5-32-548",
         "rid": 548, "members": [users[40]["dn"]]},
        {"dn": f"CN=Server Operators,CN=Builtin,{DN}", "sam": "Server Operators", "sid": "S-1-5-32-549",
         "rid": 549, "members": []},
        {"dn": f"CN=Print Operators,CN=Builtin,{DN}", "sam": "Print Operators", "sid": "S-1-5-32-550",
         "rid": 550, "members": []},
        {"dn": f"CN=Backup Operators,CN=Builtin,{DN}", "sam": "Backup Operators", "sid": "S-1-5-32-551",
         "rid": 551, "members": [svc_backup["dn"]]},
        {"dn": f"CN=Pre-Windows 2000 Compatible Access,CN=Builtin,{DN}",
         "sam": "Pre-Windows 2000 Compatible Access", "sid": "S-1-5-32-554", "rid": 554,
         "members": [f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{DN}"]},
        {"dn": gdn("DnsAdmins"), "sam": "DnsAdmins", "sid": f"{DOM_SID}-1101", "rid": 1101,
         "members": [users[55]["dn"]]},
        {"dn": gdn("Group Policy Creator Owners"), "sam": "Group Policy Creator Owners", "sid": f"{DOM_SID}-520",
         "rid": 520, "members": [users[0]["dn"]]},
        {"dn": gdn("Protected Users"), "sam": "Protected Users", "sid": f"{DOM_SID}-525", "rid": 525,
         "members": []},
        {"dn": gdn("Key Admins"), "sam": "Key Admins", "sid": f"{DOM_SID}-526", "rid": 526, "members": []},
        {"dn": gdn("Enterprise Key Admins"), "sam": "Enterprise Key Admins", "sid": f"{DOM_SID}-527",
         "rid": 527, "members": []},
        {"dn": gdn("Domain Users"), "sam": "Domain Users", "sid": f"{DOM_SID}-513", "rid": 513, "members": []},
        {"dn": gdn("Domain Computers"), "sam": "Domain Computers", "sid": f"{DOM_SID}-515", "rid": 515,
         "members": []},
        {"dn": gdn("Domain Controllers"), "sam": "Domain Controllers", "sid": f"{DOM_SID}-516", "rid": 516,
         "members": []},
        {"dn": gdn("Exchange Windows Permissions", "OU=Microsoft Exchange Security Groups"),
         "sam": "Exchange Windows Permissions", "sid": f"{DOM_SID}-1120", "rid": 1120, "members": []},
    ]

    dc01["owner"] = f"{DOM_SID}-512"
    dc02["owner"] = users[[u["sam"] for u in users].index("j.migration")]["sid"]
    rodc["owner"] = f"{DOM_SID}-512"
    rodc["reveal_on_demand"] = [gdn("Allowed RODC Password Replication Group"), gdn("Domain Users")]
    rodc["never_reveal"] = []
    rodc["revealed"] = [adm[1]["dn"]]
    adm[4]["key_cred"] = True
    adm[2]["alt_sec_ids"] = ["X509:<I>DC=local,DC=firma,CN=FIRMA-CA<S>CN=adm.weber,OU=Admins,OU=IT,DC=firma,DC=local"]
    groups.append({"dn": gdn("Read-only Domain Controllers"), "sam": "Read-only Domain Controllers",
                   "sid": f"{DOM_SID}-521", "rid": 521, "members": [], "created": ago(2350)})
    groups.append({"dn": gdn("Denied RODC Password Replication Group"), "sam": "Denied RODC Password Replication Group",
                   "sid": f"{DOM_SID}-572", "rid": 572, "members": []})
    groups.append({"dn": gdn("Allowed RODC Password Replication Group"), "sam": "Allowed RODC Password Replication Group",
                   "sid": f"{DOM_SID}-571", "rid": 571, "members": []})
    for g in groups:
        if g["rid"] == 550:
            g["members"].append(f"CN=S-1-5-11,CN=ForeignSecurityPrincipals,{DN}")
        if g["rid"] == 551:
            g["members"].append(f"CN=S-1-5-21-9988776655-1122334455-6677889900-1104,CN=ForeignSecurityPrincipals,{DN}")
        if g["rid"] == 526:
            g["members"].append(adm[3]["dn"])

    def ace(sid, mask, obj=None):
        return {"type": 5 if obj else 0, "allow": True, "mask": mask, "sid": sid, "object_type": obj,
                "inherited_object_type": None, "inherited": False, "flags": 0}

    acl = {
        "domain_root": {"owner": f"{DOM_SID}-512", "aces": [
            ace("S-1-5-9", ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES_ALL),
            ace(f"{DOM_SID}-516", ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES_ALL),
            ace("S-1-5-32-544", ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES_ALL),
            ace(f"{DOM_SID}-519", ADS_RIGHT_GENERIC_ALL),
            ace(msol["sid"], ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES),
            ace(msol["sid"], ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES_ALL),
            ace(svc_sync["sid"], ADS_RIGHT_DS_CONTROL_ACCESS, GUID_DS_REPL_GET_CHANGES_ALL),
            ace(f"{DOM_SID}-1120", ADS_RIGHT_WRITE_DAC),
        ]},
        "adminsdholder": {"owner": f"{DOM_SID}-512", "aces": [
            ace("S-1-5-18", ADS_RIGHT_GENERIC_ALL), ace(f"{DOM_SID}-512", 0x000F01BD),
            ace(f"{DOM_SID}-1051", ADS_RIGHT_GENERIC_ALL),
        ]},
    }

    templates = [
        {"name": "User", "display": "Benutzer", "name_flag": 0x82000000, "enroll_flag": 0x29, "ra_signature": 0,
         "ekus": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.4"], "published": True,
         "sd": {"owner": f"{DOM_SID}-519", "aces": [ace(f"{DOM_SID}-513", ADS_RIGHT_DS_CONTROL_ACCESS,
                                                          GUID_CERT_ENROLL)]}},
        {"name": "WebServer-Export", "display": "Webserver (exportierbar)", "name_flag": 0x1, "enroll_flag": 0,
         "ra_signature": 0, "ekus": ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"], "published": True,
         "sd": {"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-513", ADS_RIGHT_DS_CONTROL_ACCESS,
                                                         GUID_CERT_ENROLL)]}},
        {"name": "VPN-Alt", "display": "VPN (alt)", "name_flag": 0, "enroll_flag": 0, "ra_signature": 0,
         "ekus": ["1.3.6.1.5.5.7.3.2"], "published": True,
         "sd": {"owner": f"{DOM_SID}-512", "aces": [ace("S-1-5-11", ADS_RIGHT_GENERIC_ALL)]}},
        {"name": "EnrollmentAgent-Alt", "display": "Registrierungs-Agent (alt)", "name_flag": 0, "enroll_flag": 0,
         "ra_signature": 0, "ekus": ["1.3.6.1.4.1.311.20.2.1"], "published": True, "schema_version": 2,
         "sd": {"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-513", ADS_RIGHT_DS_CONTROL_ACCESS,
                                                         GUID_CERT_ENROLL)]}},
        {"name": "Webserver-Intern", "display": "Webserver intern", "name_flag": 0x1, "enroll_flag": 0,
         "ra_signature": 0, "ekus": ["1.3.6.1.5.5.7.3.1"], "published": True, "schema_version": 2,
         "sd": {"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-515", ADS_RIGHT_DS_CONTROL_ACCESS,
                                                         GUID_CERT_ENROLL)]}},
        {"name": "SubCA", "display": "Untergeordnete Zertifizierungsstelle", "name_flag": 0x1, "enroll_flag": 0,
         "ra_signature": 0, "ekus": [], "published": False,
         "sd": {"owner": f"{DOM_SID}-519", "aces": [ace(f"{DOM_SID}-512", ADS_RIGHT_DS_CONTROL_ACCESS,
                                                          GUID_CERT_ENROLL)]}},
    ]

    gpos = [
        {"guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}", "name": "Default Domain Policy",
         "path": "", "flags": 0, "changed": ago(400)},
        {"guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}", "name": "Default Domain Controllers Policy",
         "path": "", "flags": 0, "changed": ago(800)},
        {"guid": "{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}", "name": "Laufwerkszuordnung Vertrieb",
         "path": "", "flags": 0, "changed": ago(1700)},
        {"guid": "{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}", "name": "Clients-Basis",
         "path": "", "flags": 0, "changed": ago(90)},
    ]
    gpos[0]["sd"] = {"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-1051", 0x40000000)]}
    for g in gpos[1:]:
        g["sd"] = {"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-512", 0x000F01FF)]}

    return {
        "meta": {"domain_type": "windows", "vendor": "", "unprivileged": True, "dc_host": "dc01.firma.local",
                 "warnings": [], "demo": True},
        "rootdse": {"default_nc": DN, "root_nc": DN, "domain_level": 6, "forest_level": 6, "dc_level": 6,
                    "dns_host": "dc01.firma.local"},
        "domain": {
            "dn": DN, "fqdn": FQDN, "netbios": "FIRMA", "sid": DOM_SID, "root_sid": DOM_SID, "is_root": True,
            "domain_level": 6, "forest_level": 6, "created": ago(3100), "maq": 10,
            "policy": {"min_length": 7, "history": 12, "max_age_days": 90.0, "min_age_days": 1.0,
                       "complexity": True, "reversible": False, "lockout_threshold": 0,
                       "lockout_duration_min": 30.0, "lockout_window_min": 30.0},
            "gplink": [{"guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}", "enabled": True, "enforced": False},
                       {"guid": "{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}", "enabled": True, "enforced": False}],
        },
        "users": users, "computers": computers, "groups": groups,
        "trusts": [
            {"name": "partner-gmbh.de", "flat": "PARTNER", "direction": 3, "type": 2, "attributes": 0x0,
             "sid": "S-1-5-21-9988776655-1122334455-6677889900", "created": ago(1500), "changed": ago(160),
             "enc_types": None},
            {"name": "konzern.local", "flat": "KONZERN", "direction": 2, "type": 2, "attributes": 0x8,
             "sid": "S-1-5-21-123123123-456456456-789789789", "created": ago(900), "changed": ago(12),
             "enc_types": 24},
        ],
        "acl": dict(acl, dc_ou={"owner": f"{DOM_SID}-512", "aces": [ace(f"{DOM_SID}-512", 0x000F01FF)]}),
        "config": {"dsheuristics": None, "recycle_bin": False, "schema_version": 88, "laps_legacy_schema": True,
                   "laps_windows_schema": False, "tombstone_lifetime": 180, "sites": 1, "subnets": 0,
                   "duplicates": [f"CN=s.mueller\\0ACNF:5f1c0e2a-7d9b-4f4e-bb21-0c6d9e3a2f11,OU=Mitarbeiter,{DN}"],
                   "dns_zones": [
                       {"name": "firma.local", "dn": "", "allow_update": 1,
                        "sd": {"owner": None, "aces": [ace("S-1-5-11", 0x1)]}},
                       {"name": "_msdcs.firma.local", "dn": "", "allow_update": 2, "sd": {"owner": None, "aces": []}},
                   ],
                   "last_backup": ago(52), "sysvol_repl": "dfsr",
                   "dmsa": {"schema": True, "guid": DMSA_GUID, "containers": [
                       {"dn": f"OU=Server,{DN}", "sd": {"owner": f"{DOM_SID}-512", "aces": [
                           ace(f"{DOM_SID}-1051", 0x1), ace(f"{DOM_SID}-512", 0x000F01FF)]}},
                       {"dn": f"OU=Clients,{DN}", "sd": {"owner": f"{DOM_SID}-512", "aces": [
                           ace(f"{DOM_SID}-1051", 0x1, DMSA_GUID)]}}],
                       "accounts": [{"dn": f"CN=dmsa_backup,CN=Managed Service Accounts,{DN}", "sam": "dmsa_backup$",
                                     "preceded_by": [svc_backup["dn"]], "state": 1}]}},
        "psos": [{"name": "PSO-Admins", "min_length": 14, "complexity": True, "reversible": False,
                  "lockout_threshold": 5, "applies_to": [it_admins], "precedence": 10}],
        "pki": {"cas": [{"name": "FIRMA-CA", "host": "srv-ca01.firma.local", "dn": "CN=FIRMA-CA,CN=Enrollment Services",
                         "templates": ["User", "WebServer-Export", "VPN-Alt", "EnrollmentAgent-Alt", "Webserver-Intern"],
                         "certs": [_demo_ca_cert()], "sd": None,
                         "enroll_servers": ["1\n4\n0\nhttp://srv-ca01.firma.local/FIRMA-CA_CES_Kerberos/service.svc/CES\n0"]}],
                "templates": templates, "objects": [
                    {"dn": "CN=Public Key Services,CN=Services,CN=Configuration," + DN, "certs": [],
                     "sd": {"owner": f"{DOM_SID}-519", "aces": [ace(f"{DOM_SID}-519", 0x000F01FF)]}},
                    {"dn": "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration," + DN,
                     "certs": [], "sd": {"owner": f"{DOM_SID}-519", "aces": [ace(f"{DOM_SID}-519", 0x000F01FF)]}}]},
        "gpos": gpos,
        "gpo_links": {"domain": [{"guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}", "enabled": True,
                                  "enforced": False}],
                      "dc_ou": [{"guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}", "enabled": True,
                                 "enforced": False}],
                      "all": [{"guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}", "enabled": True, "enforced": False},
                              {"guid": "{6AC1786C-016F-11D2-945F-00C04FB984F9}", "enabled": True, "enforced": False},
                              {"guid": "{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}", "enabled": True, "enforced": False},
                              {"guid": "{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}", "enabled": True, "enforced": False}]},
        "sysvol": {
            "status": "ok", "error": None, "files_scanned": 9,
            "gpp_passwords": [{"gpo": "Laufwerkszuordnung Vertrieb", "guid": "{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}",
                               "file": r"{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}\User\Preferences\Drives\Drives.xml",
                               "accounts": "FIRMA\\svc_laufwerke"}],
            "secedit": {
                "{6AC1786C-016F-11D2-945F-00C04FB984F9}": {
                  "Event Audit": {"AuditAccountLogon": "3", "AuditAccountManage": "3", "AuditLogonEvents": "3"},
                  "Privilege Rights": {"SeBackupPrivilege": f"*S-1-5-32-544,*S-1-5-32-551,*{DOM_SID}-1051",
                                       "SeDebugPrivilege": "*S-1-5-32-544"},
                  "Registry Values": {
                    r"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity": "4,1",
                    r"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel": "4,3",
                    r"MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature": "4,1",
                }},
                "{31B2F340-016D-11D2-945F-00C04FB984F9}": {"System Access": {"MinimumPasswordLength": "7"}},
            },
            "regpol": {"{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}": {"machine": {
                "software\\policies\\microsoft\\windows\\windowsupdate\\wuserver": "http://wsus.firma.local:8530",
                "software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging\\enablescriptblocklogging": 1,
            }}},
            "audit": {},
            "script_secrets": [{"file": "NETLOGON\\laufwerke_vertrieb.bat", "line": 7, "kind": "net use /user"},
                               {"file": "NETLOGON\\Inventar\\sammeln.ps1", "line": 23, "kind": "ConvertTo-SecureString"}],
        },
    }


_CA_CACHE: list = []


def _demo_ca_cert() -> bytes:
    """Fiktives CA-Zertifikat mit SHA-1-Signatur für die Demo."""
    if _CA_CACHE:
        return _CA_CACHE[0]
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FIRMA-CA"),
                      x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "firma"),
                      x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "local")])
    now = dt.datetime.now(dt.timezone.utc)
    try:
        algo = hashes.SHA1()
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - dt.timedelta(days=3000))
                .not_valid_after(now + dt.timedelta(days=120))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, algo))
    except Exception:  # noqa: BLE001 – SHA-1 evtl. gesperrt
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - dt.timedelta(days=3000))
                .not_valid_after(now + dt.timedelta(days=120))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
    _CA_CACHE.append(cert.public_bytes(serialization.Encoding.DER))
    return _CA_CACHE[0]
