# SPDX-License-Identifier: AGPL-3.0-or-later
"""Selbsttests der Prüfungen aus 2.1 (ESC13, KDS-Stammschlüssel, gMSA-Kennwortleser, Certighost,
Gruppenrichtlinien mit gelockertem Anmeldeschutz) – mit der Demo-Domäne als Grundlage."""
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

from app import demo, ldapsrc  # noqa: E402
from app.analysis import Ctx  # noqa: E402
from app.config import settings  # noqa: E402
from app.rules import RULES, NotApplicable, canonical_id  # noqa: E402

BASE = demo.build()
SID = BASE["domain"]["sid"]
ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"


def ace(sid, mask, object_type=None, flags=0):
    return {"type": 5 if object_type else 0, "flags": flags, "inherited": False, "allow": True, "mask": mask,
            "sid": sid, "object_type": object_type, "inherited_object_type": None}


def run(rule_id: str, model: dict):
    rule = next(r for r in RULES if canonical_id(r.id) == rule_id)
    return rule.check(Ctx(model, settings))


class Catalogue(unittest.TestCase):
    def test_five_new_checks_with_numbers(self):
        ids = {canonical_id(r.id) for r in RULES}
        for rid in ("PRV-38", "PRV-39", "PRV-40", "PRV-41", "ANM-45"):
            self.assertIn(rid, ids)
        self.assertEqual(len(RULES), 115)


class ESC13(unittest.TestCase):
    def model(self, group_rid=None, enroll_sid=None, ekus=("1.3.6.1.5.5.7.3.2",)):
        m = copy.deepcopy(BASE)
        grp = next(g for g in m["groups"] if g.get("rid") == (group_rid or 512)) if group_rid else None
        dn = grp["dn"] if grp else f"CN=VPN-Nutzer,OU=Gruppen,{m['domain']['dn']}"
        m["pki"]["oids"] = [{"oid": "1.3.6.1.4.1.311.21.8.1.2.3", "name": "VPN", "group": dn}]
        m["pki"]["templates"].append({
            "name": "VPN-Zugang", "display": "VPN-Zugang", "name_flag": 0, "enroll_flag": 0, "ra_signature": 0,
            "ekus": list(ekus), "published": True, "policies": ["1.3.6.1.4.1.311.21.8.1.2.3"],
            "sd": {"owner": None, "aces": [ace(enroll_sid or f"{SID}-513", 0x100, ENROLL)]}})
        return m

    def test_link_to_ordinary_group(self):
        hit = run("PRV-38", self.model())
        self.assertIsNotNone(hit)
        self.assertEqual(hit.items[0]["template"], "VPN-Zugang")
        self.assertIsNone(hit.severity)                               # Standard: hoch

    def test_link_to_domain_admins_is_critical(self):
        hit = run("PRV-38", self.model(group_rid=512))
        self.assertEqual(hit.severity, "critical")

    def test_only_admins_may_enroll(self):
        self.assertIsNone(run("PRV-38", self.model(enroll_sid=f"{SID}-512")))

    def test_no_logon_purpose(self):
        self.assertIsNone(run("PRV-38", self.model(ekus=("1.3.6.1.5.5.7.3.4",))))   # nur E-Mail-Schutz

    def test_no_links(self):
        self.assertIsNone(run("PRV-38", copy.deepcopy(BASE)))


class KDSRootKey(unittest.TestCase):
    def model(self, **kds):
        m = copy.deepcopy(BASE)
        m["config"]["kds"].update(kds)
        return m

    def test_default_is_fine(self):
        self.assertIsNone(run("PRV-39", copy.deepcopy(BASE)))

    def test_auditor_can_read_key(self):
        hit = run("PRV-39", self.model(readable=True))
        self.assertEqual(hit.items[0]["detail"], "@v_kds_readable")

    def test_inheritable_read_on_container(self):
        sd = {"owner": None, "aces": [ace(f"{SID}-1051", 0x10, flags=0x02)]}
        hit = run("PRV-39", self.model(container_sd=sd))
        self.assertEqual(len(hit.items), 1)

    def test_container_ace_without_inheritance_does_not_count(self):
        sd = {"owner": None, "aces": [ace(f"{SID}-1051", 0x10)]}
        self.assertIsNone(run("PRV-39", self.model(container_sd=sd)))

    def test_read_on_key_object_and_other_attribute(self):
        keys = [{"dn": "CN=k1", "sd": {"owner": None, "aces": [ace(f"{SID}-1051", 0x10)]}}]
        self.assertIsNotNone(run("PRV-39", self.model(keys=keys)))
        keys = [{"dn": "CN=k1", "sd": {"owner": None, "aces": [ace(f"{SID}-1051", 0x10, "bf967a68-0de6-11d0-a285-00aa003049e2")]}}]
        self.assertIsNone(run("PRV-39", self.model(keys=keys, attr_guid="26627c27-08a2-0a40-a1b1-8dce85b42993")))

    def test_admins_and_dcs_are_expected(self):
        sd = {"owner": None, "aces": [ace(f"{SID}-512", 0x10000000, flags=0x02), ace(f"{SID}-516", 0x10, flags=0x02)]}
        self.assertIsNone(run("PRV-39", self.model(container_sd=sd)))

    def test_no_key_and_unknown(self):
        self.assertIsNone(run("PRV-39", self.model(present=False)))
        m = copy.deepcopy(BASE)
        m["config"]["kds"] = None
        with self.assertRaises(NotApplicable):
            run("PRV-39", m)

    def test_collection_never_reads_the_secret(self):
        calls = []

        class E(dict):
            dn = "CN=k"

            def get(self, k, d=None):
                return dict.get(self, k, d)

        def search(conn, base, flt, attrs, **kw):
            calls.append((flt, list(attrs)))
            return [E()] if "objectClass=msKds" in flt else []

        orig = (ldapsrc.search, ldapsrc.base_entry)
        ldapsrc.search, ldapsrc.base_entry = search, lambda *a, **k: None
        try:
            out = ldapsrc._collect_kds(None, "CN=Configuration,DC=firma,DC=local", "CN=Schema,CN=Configuration,DC=x")
        finally:
            ldapsrc.search, ldapsrc.base_entry = orig
        self.assertTrue(out["present"])
        for flt, attrs in calls:
            self.assertNotIn("msKds-RootKeyData", [a for a in attrs], "the key material must never be requested")


class GMSAReaders(unittest.TestCase):
    def model(self, reader_sid, priv=False):
        m = copy.deepcopy(BASE)
        g = next(u for u in m["users"] if u.get("is_gmsa"))
        g["gmsa_readers"] = {"owner": None, "aces": [ace(reader_sid, 0x000F01FF)]}
        if priv:
            da = next(x for x in m["groups"] if x.get("rid") == 512)
            da["members"] = list(da.get("members") or []) + [g["dn"]]
        return m

    def test_broad_group(self):
        hit = run("PRV-40", self.model(f"{SID}-513"))
        self.assertEqual(hit.items[0]["detail"], "@v_gmsa_broad")
        self.assertIsNone(hit.severity)

    def test_dedicated_server_group_is_fine(self):
        self.assertIsNone(run("PRV-40", self.model(f"{SID}-1999")))

    def test_privileged_gmsa_with_ordinary_reader_is_high(self):
        hit = run("PRV-40", self.model(f"{SID}-1999", priv=True))
        self.assertEqual(hit.severity, "high")
        self.assertEqual(hit.items[0]["detail"], "@v_gmsa_priv")


class Certighost(unittest.TestCase):
    def test_demo_meets_preconditions(self):
        hit = run("PRV-41", copy.deepcopy(BASE))
        self.assertEqual(hit.items[0]["detail"], "@v_certighost|10")

    def test_quota_zero(self):
        m = copy.deepcopy(BASE)
        m["domain"]["maq"] = 0
        self.assertIsNone(run("PRV-41", m))

    def test_machine_template_not_published_or_not_for_computers(self):
        m = copy.deepcopy(BASE)
        for ca in m["pki"]["cas"]:
            ca["templates"] = [t for t in ca["templates"] if t != "Machine"]
        self.assertIsNone(run("PRV-41", m))
        m = copy.deepcopy(BASE)
        t = next(t for t in m["pki"]["templates"] if t["name"] == "Machine")
        t["sd"]["aces"] = [ace(f"{SID}-512", 0x100, ENROLL)]
        self.assertIsNone(run("PRV-41", m))


class GPOAnonymous(unittest.TestCase):
    def model(self, guid, key, value):
        m = copy.deepcopy(BASE)
        m["sysvol"]["secedit"].setdefault(guid, {}).setdefault("Registry Values", {})[
            "MACHINE\\System\\CurrentControlSet\\" + key] = value
        return m

    def test_demo_client_gpo(self):
        hit = run("ANM-45", copy.deepcopy(BASE))
        self.assertEqual(hit.items[0]["detail"], "@v_gpo_anon_sam")

    def test_blank_passwords_on_dcs_is_high(self):
        hit = run("ANM-45", self.model("{6AC1786C-016F-11D2-945F-00C04FB984F9}", "Control\\Lsa\\LimitBlankPasswordUse", "4,0"))
        self.assertEqual(hit.severity, "high")

    def test_secure_values_are_fine(self):
        m = self.model("{0B7E3A55-3C1D-4E8B-A0D2-6F4C2B1E9D80}", "Control\\Lsa\\RestrictAnonymousSAM", "4,1")
        self.assertIsNone(run("ANM-45", m))


class ServerSupportEnd(unittest.TestCase):
    def ctx_at(self, when, dc=False):
        from datetime import datetime, timezone
        m = copy.deepcopy(BASE)
        for c in m["computers"]:
            if "2016" in (c.get("os") or ""):
                c["os"] = "Windows Server 2019 Standard"
        srv = next(c for c in m["computers"] if (c.get("is_dc") if dc else not c.get("is_dc")) and c.get("enabled"))
        srv["os"] = "Windows Server 2016 Standard"
        ctx = Ctx(m, settings)
        ctx.now = datetime(*when, tzinfo=timezone.utc)
        return ctx

    def check(self, rule_id, ctx):
        return next(r for r in RULES if canonical_id(r.id) == rule_id).check(ctx)

    def test_more_than_90_days_before(self):
        hit = self.check("STL-11", self.ctx_at((2026, 9, 1)))
        self.assertIsNone(hit.severity)                               # Hinweis ohne Punkte

    def test_within_90_days_and_dc(self):
        self.assertEqual(self.check("STL-11", self.ctx_at((2026, 10, 30))).severity, "low")
        hit = self.check("STL-11", self.ctx_at((2026, 10, 30), dc=True))
        self.assertEqual(hit.severity, "medium")
        self.assertEqual(hit.note, "@n_days_left|74")

    def test_after_the_end_it_is_unsupported(self):
        ctx = self.ctx_at((2027, 1, 13))
        self.assertIsNone(self.check("STL-11", ctx))
        hit = self.check("STL-09", ctx)
        self.assertIn("Windows Server 2016 Standard", [i.get("os") for i in hit.items])


if __name__ == "__main__":
    unittest.main()
