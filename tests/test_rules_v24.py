# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests for the 2.4 checks (Credential Guard via GPO, Samba series past end of life, DNS host name
mismatch / Certifried) and the extended constrained delegation check (krbtgt, domain name)."""
from __future__ import annotations

import copy
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-rules-"))

from app import demo  # noqa: E402
from app.analysis import Ctx  # noqa: E402
from app.config import settings  # noqa: E402
from app.rules import RULES, NotApplicable, canonical_id  # noqa: E402
from app.rules5 import samba_version  # noqa: E402

BASE = demo.build()
DEFAULT_DOMAIN_POLICY = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
GPO = "{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}"
UAC_PT = 0x1000000


def rule(rule_id: str):
    return next(r for r in RULES if canonical_id(r.id) == rule_id)


def run(rule_id: str, model: dict):
    return rule(rule_id).check(Ctx(model, settings))


def regpol(m: dict, values: dict, guid: str = GPO) -> dict:
    m["sysvol"]["regpol"].setdefault(guid, {}).setdefault("machine", {}).update(values)
    return m


CG = "software\\policies\\microsoft\\windows\\deviceguard\\"


class Catalogue(unittest.TestCase):
    def test_three_new_checks_with_numbers(self):
        ids = {canonical_id(r.id) for r in RULES}
        for rid in ("ANM-46", "ANM-47", "ANM-48"):
            self.assertIn(rid, ids)
        self.assertEqual(len(RULES), 118)

    def test_platforms(self):
        self.assertEqual(rule("ANM-46").platforms, ("windows",))
        self.assertEqual(rule("ANM-47").platforms, ("samba",))


class CredentialGuard(unittest.TestCase):
    def test_not_configured_is_only_a_hint(self):
        hit = run("ANM-46", copy.deepcopy(BASE))
        self.assertIsNotNone(hit)
        self.assertIsNone(hit.points)              # rule default: info, 1 point
        self.assertEqual(rule("ANM-46").points, 1)
        self.assertEqual(rule("ANM-46").severity, "info")
        self.assertEqual(hit.note, "@n_cg_default")

    def test_enabled_with_uefi_lock(self):
        m = regpol(copy.deepcopy(BASE), {CG + "enablevirtualizationbasedsecurity": 1, CG + "lsacfgflags": 1})
        self.assertIsNone(run("ANM-46", m))

    def test_enabled_without_lock_via_security_template(self):
        m = copy.deepcopy(BASE)
        m["sysvol"]["secedit"][GPO]["Registry Values"][
            r"MACHINE\System\CurrentControlSet\Control\Lsa\LsaCfgFlags"] = "4,2"
        self.assertIsNone(run("ANM-46", m))

    def test_explicitly_disabled(self):
        m = regpol(copy.deepcopy(BASE), {CG + "lsacfgflags": 0})
        hit = run("ANM-46", m)
        self.assertEqual(hit.severity, "low")
        self.assertEqual(hit.items[0]["detail"], "@v_cg_off")

    def test_vbs_disabled_beats_enabled_elsewhere(self):
        m = regpol(copy.deepcopy(BASE), {CG + "lsacfgflags": 1})
        m = regpol(m, {CG + "enablevirtualizationbasedsecurity": 0}, guid=DEFAULT_DOMAIN_POLICY)
        hit = run("ANM-46", m)
        self.assertEqual(hit.items[0]["detail"], "@v_vbs_off")

    def test_unlinked_gpo_is_ignored(self):
        m = copy.deepcopy(BASE)
        guid = "{11111111-2222-3333-4444-555555555555}"
        m["gpos"].append({"guid": guid, "name": "Nicht verknüpft", "dn": f"CN={guid},CN=Policies,CN=System,{m['domain']['dn']}"})
        regpol(m, {CG + "lsacfgflags": 1}, guid=guid)
        self.assertIsNotNone(run("ANM-46", m))


class SambaEOL(unittest.TestCase):
    def model(self, os_version: str | None = None, vendor: str = "") -> dict:
        m = copy.deepcopy(BASE)
        m["meta"]["domain_type"] = "samba"
        m["meta"]["vendor"] = vendor
        for c in m["computers"]:
            if c.get("is_dc") or c.get("is_rodc"):
                c["os"], c["os_version"] = "Samba", ""
        if os_version is not None:
            dc = next(c for c in m["computers"] if c.get("is_dc"))
            dc["os_version"] = os_version
        return m

    def test_parse(self):
        self.assertEqual(samba_version("Samba Team (https://www.samba.org) 4.15.13-Synology"), (15, "4.15.13-Synology"))
        self.assertEqual(samba_version("4.23.2"), (23, "4.23.2"))
        self.assertIsNone(samba_version("Samba"))
        self.assertIsNone(samba_version("10.0 (17763)"))
        self.assertIsNone(samba_version(None))

    def test_eol_series(self):
        hit = run("ANM-47", self.model("4.15.13-Synology"))
        self.assertEqual(hit.items[0]["value"], "4.15.13-Synology")
        self.assertEqual(hit.items[0]["detail"], "@v_samba_eol|2023-03-08")
        self.assertEqual(rule("ANM-47").points, 0)

    def test_very_old_series(self):
        self.assertEqual(run("ANM-47", self.model("4.11.17")).items[0]["detail"], "@v_samba_eol_old")

    def test_maintained_series(self):
        self.assertIsNone(run("ANM-47", self.model("4.23.3")))
        self.assertIsNone(run("ANM-47", self.model("4.25.1-Debian")))

    def test_vendor_version_from_rootdse(self):
        hit = run("ANM-47", self.model(vendor="Samba Team (https://www.samba.org) 4.21.4"))
        self.assertEqual(hit.items[0]["host"], "DC01")
        self.assertIn("2026-03-31", hit.items[0]["detail"])

    def test_unknown_version_is_not_applicable(self):
        with self.assertRaises(NotApplicable):
            run("ANM-47", self.model(vendor="Samba Team (https://www.samba.org)"))

    def test_non_dc_samba_member_ignored(self):
        # NAS-ARCHIV in the demo runs Samba 4.15 but is no DC
        m = self.model("4.24.0")
        self.assertIsNone(run("ANM-47", m))


class DnsHostnameMismatch(unittest.TestCase):
    def test_demo_finds_renamed_pc(self):
        hit = run("ANM-48", copy.deepcopy(BASE))
        self.assertEqual([i["account"] for i in hit.items], ["PC-0150$"])
        self.assertIsNone(hit.severity)

    def test_clean_domain(self):
        m = copy.deepcopy(BASE)
        m["computers"] = [c for c in m["computers"] if c["sam"] != "PC-0150$"]
        self.assertIsNone(run("ANM-48", m))

    def test_dc_name_on_member_is_critical(self):
        m = copy.deepcopy(BASE)
        pc = next(c for c in m["computers"] if c["sam"] == "PC-0001$")
        pc["dns"] = "DC01.firma.local"
        hit = run("ANM-48", m)
        self.assertEqual(hit.severity, "critical")
        self.assertIn({"account": "PC-0001$", "dns": "DC01.firma.local", "detail": "@v_dns_is_dc"}, hit.items)

    def test_netbios_truncation_and_empty(self):
        m = copy.deepcopy(BASE)
        m["computers"] = [c for c in m["computers"] if c["sam"] != "PC-0150$"]
        m["computers"][20].update(sam="VERYLONGCOMPUTE$", dns="verylongcomputername.firma.local")
        m["computers"][21].update(dns="")
        m["computers"][22].update(dns=m["computers"][22]["dns"].upper())
        m["computers"][23].update(dns=m["computers"][23]["dns"].split(".")[0] + ".anderer-namensraum.example")
        self.assertIsNone(run("ANM-48", m))


class ConstrainedDelegation(unittest.TestCase):
    def model(self, targets: list[str], pt: bool = False) -> dict:
        m = copy.deepcopy(BASE)
        for a in m["users"] + m["computers"]:
            a["delegate_to"] = []
            a["uac"] &= ~UAC_PT
        svc = next(u for u in m["users"] if u.get("enabled") and not u.get("is_gmsa"))
        svc["delegate_to"] = targets
        if pt:
            svc["uac"] |= UAC_PT
        return m

    def test_krbtgt_is_critical(self):
        hit = run("PRV-15", self.model(["krbtgt/FIRMA.LOCAL"]))
        self.assertEqual(hit.severity, "critical")
        self.assertEqual(hit.items[0]["detail"], "@v_deleg_krbtgt")

    def test_domain_name_reaches_dcs(self):
        hit = run("PRV-15", self.model(["ldap/firma.local/firma.local"]))
        self.assertEqual(hit.severity, "critical")
        hit = run("PRV-15", self.model(["cifs/FIRMA"]))
        self.assertEqual(hit.severity, "critical")

    def test_member_server_without_protocol_transition(self):
        self.assertIsNone(run("PRV-15", self.model(["cifs/srv-file01.firma.local", "MSSQLSvc/srv-sql01.firma.local:1433"])))

    def test_no_delegation(self):
        self.assertIsNone(run("PRV-15", self.model([])))


if __name__ == "__main__":
    unittest.main()
