# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Preparation of the raw data: indexes, recursive group resolution, privileged accounts."""
from __future__ import annotations

from .adutil import DOMAIN_RIDS, WELL_KNOWN_SIDS, days_since, now_utc, sid_rid

BUILTIN_RIDS = {544, 545, 546, 548, 549, 550, 551, 552, 554, 557, 560, 561}
ROOT_RIDS = {518, 519, 527, 498}

# Privileged groups: (RID or name, display key, "admin tier")
ADMIN_GROUP_RIDS = [512, 519, 518, 544]
OPERATOR_GROUP_RIDS = [548, 549, 550, 551]


class Ctx:
    def __init__(self, model: dict, cfg) -> None:
        self.m = model
        self.cfg = cfg
        self.now = now_utc()
        self.domain_type = model.get("meta", {}).get("domain_type", "windows")
        self.domain = model["domain"]
        self.domain_sid = self.domain.get("sid") or ""
        self.root_sid = self.domain.get("root_sid") or self.domain_sid
        self.users = model.get("users", [])
        self.computers = model.get("computers", [])
        self.groups = model.get("groups", [])
        self.accounts = self.users + self.computers
        self.by_dn: dict[str, dict] = {}
        self.by_sid: dict[str, dict] = {}
        for kind, coll in (("user", self.users), ("computer", self.computers), ("group", self.groups)):
            for o in coll:
                o.setdefault("_kind", kind)
                if o.get("dn"):
                    self.by_dn[o["dn"].lower()] = o
                if o.get("sid"):
                    self.by_sid[o["sid"]] = o
        self.dcs = [c for c in self.computers if c.get("is_dc") or c.get("is_rodc")]
        self.dc_names = set()
        for dc in self.dcs:
            self.dc_names.add((dc.get("dns") or "").lower())
            self.dc_names.add(dc.get("sam", "").rstrip("$").lower())
        self.dc_names.discard("")
        self._members_memo: dict[str, tuple] = {}
        self._build_priv()

    # ------------------------------------------------------------------
    def group_sid(self, rid: int) -> str:
        if rid in BUILTIN_RIDS:
            return f"S-1-5-32-{rid}"
        if rid in ROOT_RIDS:
            return f"{self.root_sid}-{rid}"
        return f"{self.domain_sid}-{rid}"

    def group(self, rid: int) -> dict | None:
        return self.by_sid.get(self.group_sid(rid))

    def group_by_name(self, name: str) -> dict | None:
        n = name.lower()
        return next((g for g in self.groups if (g.get("sam") or "").lower() == n), None)

    def name(self, sid: str | None) -> str:
        if not sid:
            return "?"
        o = self.by_sid.get(sid)
        if o:
            return o.get("sam") or o.get("dn") or sid
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        rid = sid_rid(sid)
        if rid in DOMAIN_RIDS and sid.rsplit("-", 1)[0] in (self.domain_sid, self.root_sid):
            return DOMAIN_RIDS[rid]
        return sid

    # ------------------------------------------------------------------
    def members(self, group: dict | None) -> list[dict]:
        """Recursive members (users/computers) of a group, including primaryGroupID."""
        if not group:
            return []
        return list(self._members_cached(group["dn"].lower()))

    def _members_cached(self, gdn: str) -> tuple:
        # Per-Ctx cache (lru_cache on methods would keep every Ctx and its domain data in RAM for good)
        if gdn in self._members_memo:
            return self._members_memo[gdn]
        seen_groups: set[str] = set()
        found: dict[str, dict] = {}

        def walk(g: dict):
            key = g["dn"].lower()
            if key in seen_groups:
                return
            seen_groups.add(key)
            for mdn in g.get("members", []):
                o = self.by_dn.get(mdn.lower())
                if o is None:
                    continue
                if o["_kind"] == "group":
                    walk(o)
                else:
                    found[o["dn"].lower()] = o
            rid = g.get("rid")
            if g.get("sid") == f"{self.domain_sid}-{rid}" and rid not in (513, 515):
                for a in self.accounts:
                    if a.get("primary_gid") == rid:
                        found[a["dn"].lower()] = a

        g0 = self.by_dn.get(gdn)
        if g0:
            walk(g0)
        res = tuple(found.values())
        self._members_memo[gdn] = res
        return res

    def foreign_members(self, group: dict | None) -> list[str]:
        """SIDs from ForeignSecurityPrincipals (e.g. Authenticated Users)."""
        out = []
        for mdn in (group or {}).get("members", []):
            if ",cn=foreignsecurityprincipals," in mdn.lower():
                cn = mdn.split(",", 1)[0]
                out.append(cn.split("=", 1)[1])
        return out

    # ------------------------------------------------------------------
    def _build_priv(self) -> None:
        self.priv_map: dict[str, list[str]] = {}   # dn -> groups
        self.admin_dns: set[str] = set()
        self.priv_groups: list[dict] = []
        candidates = [(rid, True) for rid in ADMIN_GROUP_RIDS] + [(rid, False) for rid in OPERATOR_GROUP_RIDS + [520, 526, 527]]
        for rid, is_admin in candidates:
            g = self.group(rid)
            if g:
                self.priv_groups.append({"group": g, "admin": is_admin})
        dns_admins = self.group_by_name("DnsAdmins")
        if dns_admins:
            self.priv_groups.append({"group": dns_admins, "admin": False})
        for pg in self.priv_groups:
            g = pg["group"]
            for acc in self.members(g):
                key = acc["dn"].lower()
                self.priv_map.setdefault(key, []).append(g.get("sam") or g["dn"])
                if pg["admin"]:
                    self.admin_dns.add(key)

    def is_priv(self, acc: dict) -> bool:
        return acc["dn"].lower() in self.priv_map

    def is_admin(self, acc: dict) -> bool:
        return acc["dn"].lower() in self.admin_dns

    @property
    def admins(self) -> list[dict]:
        return [self.by_dn[d] for d in sorted(self.admin_dns) if d in self.by_dn]

    @property
    def privileged_users(self) -> list[dict]:
        return [self.by_dn[d] for d in sorted(self.priv_map) if d in self.by_dn and self.by_dn[d]["_kind"] == "user"]

    def protected_users(self) -> set[str]:
        return {a["dn"].lower() for a in self.members(self.group(525))}

    # ------------------------------------------------------------------
    def inactive(self, acc: dict, days: int) -> bool:
        """Inactive = last logon older than `days` – or never logged on and older than `days`."""
        ll = acc.get("last_logon")
        if ll is not None:
            return (self.now - ll).days > days
        created = acc.get("created")
        return created is not None and (self.now - created).days > days

    def safe_sids(self) -> set[str]:
        """Principals that are allowed to hold default write/replication rights."""
        return {
            "S-1-5-18", "S-1-5-32-544", "S-1-5-9", "S-1-5-10", "S-1-3-0",
            self.group_sid(512), self.group_sid(519), self.group_sid(518), self.group_sid(516),
            self.group_sid(521), self.group_sid(498),
            # child domain: objects in the configuration partition grant rights to the forest root domain admins
            f"{self.root_sid}-512", f"{self.root_sid}-516",
        }

    def low_priv_sids(self) -> set[str]:
        return {"S-1-1-0", "S-1-5-11", "S-1-5-7", "S-1-5-32-545", "S-1-5-32-546",
                self.group_sid(513), self.group_sid(514), self.group_sid(515),
                f"{self.root_sid}-513", f"{self.root_sid}-514", f"{self.root_sid}-515"}

    @staticmethod
    def age(dt) -> int | None:
        return days_since(dt)

    # ------------------------------------------------------------------
    def nested_principals(self, group: dict | None) -> set[str]:
        """SIDs of all nested groups and ForeignSecurityPrincipals below a group."""
        out: set[str] = set()
        seen: set[str] = set()

        def walk(g: dict):
            if g["dn"].lower() in seen:
                return
            seen.add(g["dn"].lower())
            for mdn in g.get("members", []):
                low = mdn.lower()
                if ",cn=foreignsecurityprincipals," in low:
                    out.add(mdn.split(",", 1)[0].split("=", 1)[1])
                    continue
                o = self.by_dn.get(low)
                if o and o["_kind"] == "group":
                    if o.get("sid"):
                        out.add(o["sid"])
                    walk(o)

        if group:
            walk(group)
        return out

    def gpo_guids(self, scope: str = "dc") -> list[str]:
        """Actively linked GPOs: 'dc' = domain + Domain Controllers OU (in order of application), 'all' = all."""
        failed = set((self.m.get("meta") or {}).get("failed_sections") or [])
        if failed & {"all_links", "site_links", "dc_ou", "gpos"}:
            from .rules import NotApplicable
            raise NotApplicable("na_section")
        links = self.m.get("gpo_links") or {}
        if scope == "dc":
            seq = list(links.get("domain", [])) + list(links.get("dc_ou", []))
        else:
            seq = list(links.get("all", [])) or list(links.get("domain", [])) + list(links.get("dc_ou", []))
        out = []
        for lk in seq:
            g = lk["guid"].upper()
            if lk.get("enabled") and g not in out:
                out.append(g)
        return out

    def gpo_name(self, guid: str) -> str:
        for g in self.m.get("gpos", []):
            if g["guid"].upper() == guid.upper():
                return g.get("name") or guid
        return guid
