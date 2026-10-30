# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Führt einen Scan aus: Daten sammeln → Regeln auswerten → speichern."""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter

from . import db
from .adutil import classify_os, fmt_date
from .analysis import Ctx
from .config import settings
from .rules import CATEGORIES, RULES, Hit, NotApplicable

log = logging.getLogger("samaudit.scan")
_scan_lock = threading.Lock()
MAX_ITEMS = 2000

LEVEL_NAMES = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2",
               7: "2016", 10: "2025"}


class ScanBusy(Exception):
    pass


# Datenabschnitte der Sammlung → abhängige Regeln (interne Namen). Ist ein Abschnitt beim Lesen
# fehlgeschlagen, gelten diese Regeln als „nicht prüfbar“ – leere Daten dürfen nie „bestanden“ ergeben.
SECTION_RULES = {
    "trusts": ("T-",),
    "pki_cas": ("P-ADCS-", "A-CAWeakCrypto", "P-Certighost"),
    "pki_templates": ("P-ADCS-", "P-Certighost"),
    "pki_oids": ("P-ADCS-ESC13",),
    "gmsa": ("P-GMSAReaders",),
    "pki_obj": ("P-ADCS-ESC5", "A-CAWeakCrypto"),
    "psos": ("A-WeakPSO",),
    "gpos": ("P-GPOWrite",),
    "dc_owner": ("P-DCOwner",),
    "dc_ou": ("P-DCOUACL",),
    "adminsdholder": ("P-AdminSDHolder",),
    "dsheuristics": ("A-AnonymousAccess", "A-DSHeuristicsSDProp", "A-UPNSPNUniqueness", "A-Tombstone"),
    "recyclebin": ("A-RecycleBin",),
    "laps_schema": ("S-LAPS",),
    "root_groups": ("P-SchemaEnterpriseAdmins",),
}


def _blocked(rule, failed: set[str]) -> bool:
    lid = getattr(rule, "legacy_id", rule.id)
    return any(lid.startswith(p) for sec in failed for p in SECTION_RULES.get(sec, ()))


def _remember_dc_names(model: dict) -> None:
    """DNS-Namen der DCs merken – damit das LDAPS-Pinning einen weiteren DC erkennt (siehe pins.check)."""
    try:
        names = sorted({(c.get("dns") or "").lower() for c in model.get("computers", [])
                        if (c.get("is_dc") or c.get("is_rodc")) and c.get("dns")})
        if names:
            db.set_kv("dc_names", ",".join(names))
    except Exception as e:  # noqa: BLE001
        log.debug("dc_names: %s", e)


def evaluate(model: dict) -> tuple[list[dict], dict]:
    ctx = Ctx(model, settings)
    dtype = ctx.domain_type
    failed = set((model.get("meta") or {}).get("failed_sections") or [])
    results = []
    for r in RULES:
        res = {"rule_id": r.id, "category": r.category, "state": "pass", "severity": r.severity,
               "points": 0, "count": 0, "items": [], "note": None}
        if dtype not in r.platforms:
            res.update(state="na", note="na_platform")
            results.append(res)
            continue
        if _blocked(r, failed):
            res.update(state="na", note="na_section")
            results.append(res)
            continue
        try:
            hit = r.check(ctx)
        except NotApplicable as e:
            res.update(state="na", note=str(e) or "na_unknown")
            results.append(res)
            continue
        except Exception as e:  # noqa: BLE001
            log.exception("Regel %s fehlgeschlagen", r.id)
            res.update(state="na", note="na_error", items=[{"detail": str(e)[:200]}])
            results.append(res)
            continue
        if isinstance(hit, Hit):
            pts = r.points if hit.points is None else hit.points
            res.update(state="fail", severity=hit.severity or r.severity, points=pts,
                       count=hit.count if hit.count is not None else len(hit.items),
                       items=hit.items[:MAX_ITEMS], note=hit.note)
        results.append(res)
    scores = {c: min(100, sum(x["points"] for x in results if x["category"] == c and x["state"] == "fail"))
              for c in CATEGORIES}
    scores["global"] = max(scores.values()) if scores else 0
    return results, scores


def build_overview(model: dict) -> dict:
    ctx = Ctx(model, settings)
    d = ctx.domain
    users = [u for u in ctx.users if not u.get("is_gmsa")]
    en_users = [u for u in users if u.get("enabled")]
    en_comp = [c for c in ctx.computers if c.get("enabled")]
    active_comp = [c for c in en_comp if not ctx.inactive(c, settings.inactive_days)]
    os_counter = Counter((c.get("os") or "–") for c in active_comp)
    top = os_counter.most_common(8)
    rest = sum(os_counter.values()) - sum(n for _, n in top)
    if rest:
        top.append(("@other", rest))
    priv = []
    for pg in ctx.priv_groups:
        g = pg["group"]
        mem = ctx.members(g)
        priv.append({"name": g.get("sam"), "count": len(mem), "enabled": sum(1 for m in mem if m.get("enabled")),
                     "members": sorted(m["sam"] for m in mem)[:40]})
    sv = model.get("sysvol") or {}
    windows_targets = [c for c in active_comp if not (c.get("is_dc") or c.get("is_rodc"))
                       and classify_os(c.get("os")) not in ("samba", "other")]
    laps = sum(1 for c in windows_targets if c.get("laps"))
    return {
        "fqdn": d.get("fqdn"), "netbios": d.get("netbios"), "sid": d.get("sid"), "dn": d.get("dn"),
        "domain_type": ctx.domain_type, "dc_host": model.get("meta", {}).get("dc_host"),
        "domain_level": LEVEL_NAMES.get(d.get("domain_level"), d.get("domain_level")),
        "forest_level": LEVEL_NAMES.get(d.get("forest_level"), d.get("forest_level")),
        "created": fmt_date(d.get("created")), "is_root": d.get("is_root"),
        "users": {"total": len(users), "enabled": len(en_users),
                  "inactive": sum(1 for u in en_users if ctx.inactive(u, settings.inactive_days))},
        "computers": {"total": len(ctx.computers), "enabled": len(en_comp),
                      "inactive": len(en_comp) - len(active_comp)},
        "groups": len(ctx.groups),
        "admins": len([a for a in ctx.admins if a.get("enabled")]),
        "laps": {"covered": laps, "total": len(windows_targets)},
        "dcs": [{"name": dc.get("dns") or dc["sam"], "os": dc.get("os"), "last_logon": fmt_date(dc.get("last_logon")),
                 "rodc": bool(dc.get("is_rodc"))} for dc in ctx.dcs],
        "os_dist": top,
        "trusts": [{"name": t["name"], "direction": t.get("direction"), "type": t.get("type"),
                    "attributes": t.get("attributes"), "changed": fmt_date(t.get("changed"))}
                   for t in model.get("trusts", [])],
        "policy": d.get("policy", {}), "maq": d.get("maq"),
        "priv_groups": priv,
        "sysvol": {"status": sv.get("status", "disabled"), "error": sv.get("error"),
                   "files": sv.get("files_scanned", 0)},
        "pki_cas": [c.get("name") for c in (model.get("pki") or {}).get("cas", [])],
        "warnings": model.get("meta", {}).get("warnings", []),
        "last_backup": (lambda lb: fmt_date(lb) if hasattr(lb, "year") else lb)((model.get("config") or {}).get("last_backup")),
        "dns_zones": len((model.get("config") or {}).get("dns_zones") or []),
        "demo": bool(model.get("meta", {}).get("demo")),
        "unprivileged": bool(model.get("meta", {}).get("unprivileged")),
        "vendor": model.get("meta", {}).get("vendor") or "",
    }


def _run(scan_id: int, bind_name: str, password: str) -> None:
    t0 = time.time()

    def progress(pct: int, phase: str):
        db.update_progress(scan_id, pct, phase)

    try:
        if settings.demo_mode:
            from . import demo
            for pct, ph in ((5, "phase_domain"), (20, "phase_users"), (40, "phase_computers"), (55, "phase_groups"),
                            (65, "phase_trusts"), (72, "phase_config"), (78, "phase_pki"), (82, "phase_gpo"),
                            (88, "phase_sysvol")):
                progress(pct, ph)
                time.sleep(0.35)
            model = demo.build()
        else:
            from . import ldapsrc, sysvol
            # Berechtigung erneut prüfen (Gruppenmitgliedschaft könnte entzogen worden sein)
            ldapsrc.authenticate(bind_name, password)
            progress(3, "phase_start")
            conn = ldapsrc.open_connection(bind_name, password)
            try:
                model = ldapsrc.collect(conn, progress)
                _remember_dc_names(model)
            finally:
                try:
                    conn.unbind()
                except Exception:  # noqa: BLE001
                    pass
            progress(88, "phase_sysvol")
            model["sysvol"] = sysvol.scan(model["meta"]["dc_host"], model["domain"]["fqdn"], bind_name, password,
                                          model.get("gpos", []), model.get("gpo_links", {}))
        password = ""  # noqa: F841 – Referenz so früh wie möglich verwerfen
        progress(94, "phase_rules")
        results, scores = evaluate(model)
        overview = build_overview(model)
        db.finish_scan(scan_id, scores, overview, results, round(time.time() - t0, 1),
                       overview.get("fqdn") or settings.domain_fqdn)
        db.audit("act_scan_done", detail=f"#{scan_id} score={scores['global']}")
    except Exception as e:  # noqa: BLE001
        log.exception("Scan %s fehlgeschlagen", scan_id)
        msg = getattr(e, "code", None) or str(e) or e.__class__.__name__
        db.fail_scan(scan_id, msg)
        db.audit("act_scan_error", detail=f"#{scan_id}: {msg}")
    finally:
        _scan_lock.release()


def start_scan(user_label: str, bind_name: str, password: str) -> int:
    if not _scan_lock.acquire(blocking=False):
        raise ScanBusy()
    try:
        dtype = settings.domain_type if settings.domain_type != "auto" else (db.get_kv("domain_type") or "auto")
        scan_id = db.create_scan(settings.domain_fqdn or "firma.local", dtype, user_label,
                                 settings.demo_mode)
    except Exception:
        _scan_lock.release()
        raise
    try:
        threading.Thread(target=_run, args=(scan_id, bind_name, password), daemon=True,
                         name=f"scan-{scan_id}").start()
    except Exception:
        db.fail_scan(scan_id, "thread_failed")
        _scan_lock.release()
        raise
    return scan_id
