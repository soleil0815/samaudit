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

    def test_group_nested_into_administrators_is_critical(self):
        m = self.model()
        dn = m["pki"]["oids"][0]["group"]
        m["groups"].append({"dn": dn, "sam": "VPN-Nutzer", "sid": f"{SID}-1997", "rid": 1997, "members": [],
                            "group_type": -2147483640})                 # universelle Sicherheitsgruppe
        adm = next(g for g in m["groups"] if g.get("sid") == "S-1-5-32-544") if any(
            g.get("sid") == "S-1-5-32-544" for g in m["groups"]) else next(g for g in m["groups"] if g.get("rid") == 512)
        adm["members"] = list(adm.get("members") or []) + [dn]
        self.assertEqual(run("PRV-38", m).severity, "critical")

    def test_non_universal_group_is_ignored(self):
        m = self.model()
        dn = m["pki"]["oids"][0]["group"]
        m["groups"].append({"dn": dn, "sam": "VPN-Nutzer", "sid": f"{SID}-1997", "rid": 1997, "members": [],
                            "group_type": -2147483646})                 # globale Gruppe: Verknüpfung wirkt nicht
        self.assertIsNone(run("PRV-38", m))

    def test_only_admins_may_enroll(self):
        self.assertIsNone(run("PRV-38", self.model(enroll_sid=f"{SID}-512")))

    def test_no_logon_purpose(self):
        self.assertIsNone(run("PRV-38", self.model(ekus=("1.3.6.1.5.5.7.3.4",))))   # nur E-Mail-Schutz

    def test_no_links(self):
        self.assertIsNone(run("PRV-38", copy.deepcopy(BASE)))


KDS_ATTR = "26627c27-08a2-0a40-a1b1-8dce85b42993"
DEFAULT_KEY_SD = {"owner": None, "aces": [ace("S-1-5-18", 0x000F01FF), ace(f"{SID}-512", 0x000F01FF),
                                          ace(f"{SID}-519", 0x000F01FF), ace("S-1-5-9", 0x10, flags=0)]}


class KDSRootKey(unittest.TestCase):
    def model(self, keys=None, **kds):
        m = copy.deepcopy(BASE)
        m["config"]["kds"].update({"keys": keys if keys is not None else [{"dn": "CN=k1", "sd": DEFAULT_KEY_SD}],
                                   "attr_guid": KDS_ATTR}, **kds)
        return m

    def test_default_key_is_fine(self):
        self.assertIsNone(run("PRV-39", self.model()))

    def test_invisible_keys_are_not_a_pass(self):
        with self.assertRaises(NotApplicable):                       # Standard für normale Konten
            run("PRV-39", self.model(keys=[]))
        with self.assertRaises(NotApplicable):
            run("PRV-39", self.model(keys=[{"dn": "CN=k1", "sd": None}]))

    def test_auditor_can_read_key(self):
        hit = run("PRV-39", self.model(readable=True))
        self.assertEqual(hit.items[0]["detail"], "@v_kds_readable")

    def test_read_property_alone_is_not_enough(self):
        # vertrauliches Attribut: "Alle Eigenschaften lesen" ohne erweitertes Recht liest den Schlüssel nicht
        keys = [{"dn": "CN=k1", "sd": {"owner": None, "aces": DEFAULT_KEY_SD["aces"] + [ace(f"{SID}-1051", 0x20094)]}}]
        self.assertIsNone(run("PRV-39", self.model(keys=keys)))

    def test_read_property_and_control_access(self):
        aces = DEFAULT_KEY_SD["aces"] + [ace(f"{SID}-1051", 0x10, KDS_ATTR), ace(f"{SID}-1051", 0x100, KDS_ATTR)]
        hit = run("PRV-39", self.model(keys=[{"dn": "CN=k1", "sd": {"owner": None, "aces": aces}}]))
        self.assertEqual(hit.items[0]["detail"], "@v_kds_ace|1")

    def test_full_control_inherited_from_container(self):
        sd = {"owner": None, "aces": [ace(f"{SID}-1051", 0x000F01FF, flags=0x02)]}
        hit = run("PRV-39", self.model(container_sd=sd))
        self.assertEqual(len(hit.items), 1)

    def test_container_ace_for_other_classes_does_not_count(self):
        a = ace(f"{SID}-1051", 0x000F01FF, flags=0x0A)
        a["inherited_object_type"] = "bf967aba-0de6-11d0-a285-00aa003049e2"   # nur für user-Objekte
        self.assertIsNone(run("PRV-39", self.model(container_sd={"owner": None, "aces": [a]})))
        b = ace(f"{SID}-1051", 0x000F01FF)                                      # nicht vererbbar
        self.assertIsNone(run("PRV-39", self.model(container_sd={"owner": None, "aces": [b]})))

    def test_write_dacl_is_reported(self):
        aces = DEFAULT_KEY_SD["aces"] + [ace(f"{SID}-1051", 0x40000)]
        hit = run("PRV-39", self.model(keys=[{"dn": "CN=k1", "sd": {"owner": None, "aces": aces}}]))
        self.assertEqual(hit.items[0]["detail"], "@v_kds_control|1")

    def test_no_container_and_unknown(self):
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
        for _flt, attrs in calls:
            self.assertNotIn("msKds-RootKeyData", attrs, "the key material must never be requested")
            self.assertNotIn("*", attrs)


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

    def test_broad_group_nested(self):
        m = self.model(f"{SID}-1999")
        m["groups"].append({"dn": f"CN=SQL-Leser,OU=Gruppen,{m['domain']['dn']}", "sam": "SQL-Leser",
                            "sid": f"{SID}-1999", "rid": 1999,
                            "members": [next(g for g in m["groups"] if g.get("rid") == 513)["dn"]]})
        hit = run("PRV-40", m)
        self.assertEqual(hit.items[0]["detail"], "@v_gmsa_broad")

    def test_privileged_gmsa_read_by_tier0_group_is_fine(self):
        m = self.model(f"{SID}-1998", priv=True)
        da = next(x for x in m["groups"] if x.get("rid") == 512)
        m["groups"].append({"dn": f"CN=Tier0-Server,OU=Gruppen,{m['domain']['dn']}", "sam": "Tier0-Server",
                            "sid": f"{SID}-1998", "rid": 1998, "members": []})
        da["members"].append(f"CN=Tier0-Server,OU=Gruppen,{m['domain']['dn']}")
        self.assertIsNone(run("PRV-40", m))

    def test_privileged_gmsa_with_ordinary_reader_is_high(self):
        hit = run("PRV-40", self.model(f"{SID}-1999", priv=True))
        self.assertEqual(hit.severity, "high")
        self.assertEqual(hit.items[0]["detail"], "@v_gmsa_priv")


class Certighost(unittest.TestCase):
    def only(self, *templates):
        m = copy.deepcopy(BASE)
        for ca in m["pki"]["cas"]:
            ca["templates"] = list(templates)
        return m

    def test_default_machine_template(self):
        hit = run("PRV-41", self.only("Machine"))
        self.assertEqual(hit.items[0]["template"], "Computer")
        self.assertIsNone(hit.severity)                                # niedrig (Patchstand unbekannt)

    def test_copied_template_and_authenticated_users(self):
        m = self.only("FIRMA-Computer")
        m["pki"]["templates"].append({"name": "FIRMA-Computer", "display": "FIRMA-Computer", "name_flag": 0,
                                      "enroll_flag": 0, "ra_signature": 0, "ekus": ["1.3.6.1.5.5.7.3.2"],
                                      "published": True, "sd": {"owner": None, "aces": [ace("S-1-5-11", 0x100, ENROLL)]}})
        self.assertIsNotNone(run("PRV-41", m))

    def test_quota_zero(self):
        m = self.only("Machine")
        m["domain"]["maq"] = 0
        self.assertIsNone(run("PRV-41", m))

    def test_only_admins_or_no_logon_template(self):
        m = self.only("Machine")
        next(t for t in m["pki"]["templates"] if t["name"] == "Machine")["sd"]["aces"] = [ace(f"{SID}-512", 0x100, ENROLL)]
        self.assertIsNone(run("PRV-41", m))
        self.assertIsNone(run("PRV-41", self.only("SubCA")))


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
        self.assertEqual(hit.note, "@n_days_left|75")             # bis einschließlich 12.01.2027

    def test_last_patch_day_still_supported_and_iot_ltsc(self):
        from datetime import datetime, timezone
        from app.adutil import classify_os
        self.assertEqual(classify_os("Windows Server 2016 Standard", None, datetime(2027, 1, 12, 20, tzinfo=timezone.utc)), "expiring")
        self.assertEqual(classify_os("Windows 10 IoT Enterprise LTSC", "10.0 (19044)",
                                     datetime(2027, 2, 1, tzinfo=timezone.utc)), "supported")

    def test_after_the_end_it_is_unsupported(self):
        ctx = self.ctx_at((2027, 1, 13))
        self.assertIsNone(self.check("STL-11", ctx))
        hit = self.check("STL-09", ctx)
        self.assertIn("Windows Server 2016 Standard", [i.get("os") for i in hit.items])


class FailedSections(unittest.TestCase):
    def test_failed_reads_are_not_a_pass(self):
        from app import scanner
        for section, rid in (("pki_oids", "PRV-38"), ("pki_cas", "PRV-41"), ("pki_templates", "PRV-41"),
                             ("gmsa", "PRV-40")):
            m = copy.deepcopy(BASE)
            m["meta"]["failed_sections"] = [section]
            f, _ = scanner.evaluate(m)
            self.assertEqual(next(x for x in f if x["rule_id"] == rid)["state"], "na", section)


class GPOOneUnreadable(unittest.TestCase):
    def test_readable_gpo_still_reported(self):
        from app import rules2
        orig = rules2.check_gpos_readable

        def fake(ctx, guids):
            if "{8F2A4C1E-55B0-4F0E-9C11-2D3E4F5A6B7C}" in guids:
                raise NotApplicable("na_gpo_unreadable")
            return orig(ctx, guids)
        rules2.check_gpos_readable = fake
        try:
            hit = run("ANM-45", copy.deepcopy(BASE))
        finally:
            rules2.check_gpos_readable = orig
        self.assertIsNotNone(hit)


if __name__ == "__main__":
    unittest.main()
