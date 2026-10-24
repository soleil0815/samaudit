# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""SQLite-Speicher für Scans, Befunde und das Aktivitätsprotokoll."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import settings

_lock = threading.RLock()
log = logging.getLogger("samaudit.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT,
    domain_type   TEXT,
    status        TEXT NOT NULL DEFAULT 'running',
    progress      INTEGER NOT NULL DEFAULT 0,
    phase         TEXT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    duration      REAL,
    started_by    TEXT,
    score_global  INTEGER,
    score_stale   INTEGER,
    score_privileged INTEGER,
    score_trusts  INTEGER,
    score_anomalies INTEGER,
    overview_json TEXT,
    error         TEXT,
    demo          INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id   TEXT NOT NULL,
    category  TEXT NOT NULL,
    state     TEXT NOT NULL,          -- fail | pass | na
    severity  TEXT,
    points    INTEGER NOT NULL DEFAULT 0,
    count     INTEGER NOT NULL DEFAULT 0,
    note      TEXT,
    items_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS cert_pins (
    host        TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    subject     TEXT,
    not_after   TEXT,
    is_ca       INTEGER NOT NULL DEFAULT 0,
    der         BLOB,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    user    TEXT,
    ip      TEXT,
    action  TEXT NOT NULL,
    detail  TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rename_previous_db() -> None:
    """Einmalig: Datenbankdatei früherer Versionen auf samaudit.db umbenennen (Inhalt bleibt erhalten)."""
    old = os.path.join(os.path.dirname(settings.db_path), "adaudit.db")
    if os.path.exists(old) and not os.path.exists(settings.db_path):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(old + suffix):
                os.replace(old + suffix, settings.db_path + suffix)


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    _rename_previous_db()
    con = sqlite3.connect(settings.db_path, timeout=30, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA secure_delete=ON")  # gelöschte Inhalte überschreiben (Datenschutz)
    return con


_con: sqlite3.Connection | None = None


@contextmanager
def conn():
    global _con
    with _lock:
        if _con is None:
            _con = _connect()
        try:
            yield _con
            _con.commit()
        except Exception:
            _con.rollback()
            raise


def _backup_before_migration(c: sqlite3.Connection, tag: str) -> None:
    """Vor einer Schemaänderung eine Kopie der Datenbank in data/ ablegen (für den Fall eines Rückfalls)."""
    dest = f"{settings.db_path}.vor-{tag}.bak"
    if os.path.exists(dest):
        return
    try:
        target = sqlite3.connect(dest)
        with target:
            c.backup(target)
        target.close()
        os.chmod(dest, 0o600)
        log.info("Datenbank vor Schemaänderung gesichert: %s", dest)
    except Exception as e:  # noqa: BLE001
        log.warning("Sicherung vor Schemaänderung fehlgeschlagen: %s", e)


def _migrate(c: sqlite3.Connection) -> None:
    cols = {r[1] for r in c.execute("PRAGMA table_info(cert_pins)").fetchall()}
    if "names" not in cols:
        _backup_before_migration(c, "pin-names")
        c.execute("ALTER TABLE cert_pins ADD COLUMN names TEXT")


def init() -> None:
    with conn() as c:
        c.executescript(SCHEMA)
        _migrate(c)
        # Scans, die beim letzten Beenden noch liefen, als abgebrochen markieren
        c.execute("UPDATE scans SET status='error', error='Abgebrochen (Neustart)' WHERE status='running'")
    try:
        os.chmod(settings.db_path, 0o600)
    except OSError:
        pass


# --- Scans --------------------------------------------------------------------

def create_scan(domain: str, domain_type: str, user: str, demo: bool) -> int:
    with conn() as c:
        cur = c.execute("INSERT INTO scans(domain, domain_type, started_at, started_by, phase, demo) VALUES(?,?,?,?,?,?)",
                        (domain, domain_type, now_iso(), user, "phase_start", int(demo)))
        return int(cur.lastrowid)


def update_progress(scan_id: int, pct: int, phase: str) -> None:
    with conn() as c:
        c.execute("UPDATE scans SET progress=?, phase=? WHERE id=?", (pct, phase, scan_id))


def finish_scan(scan_id: int, scores: dict, overview: dict, findings: list[dict], duration: float, domain: str) -> None:
    with conn() as c:
        c.execute("""UPDATE scans SET status='done', progress=100, phase='phase_done', finished_at=?, duration=?,
                     score_global=?, score_stale=?, score_privileged=?, score_trusts=?, score_anomalies=?,
                     overview_json=?, domain=? WHERE id=?""",
                  (now_iso(), duration, scores["global"], scores["stale"], scores["privileged"], scores["trusts"],
                   scores["anomalies"], json.dumps(overview, ensure_ascii=False, default=str), domain, scan_id))
        c.executemany("""INSERT INTO findings(scan_id, rule_id, category, state, severity, points, count, note, items_json)
                         VALUES(?,?,?,?,?,?,?,?,?)""",
                      [(scan_id, f["rule_id"], f["category"], f["state"], f.get("severity"), f.get("points", 0),
                        f.get("count", 0), f.get("note"), json.dumps(f.get("items", []), ensure_ascii=False, default=str))
                       for f in findings])


def fail_scan(scan_id: int, error: str) -> None:
    with conn() as c:
        c.execute("UPDATE scans SET status='error', error=?, finished_at=? WHERE id=?", (error[:1000], now_iso(), scan_id))


def get_scan(scan_id: int) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["overview"] = json.loads(d.pop("overview_json") or "{}")
    return d


def list_scans(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute("""SELECT s.id, s.domain, s.status, s.progress, s.started_at, s.finished_at, s.duration,
                                   s.started_by, s.score_global, s.score_stale, s.score_privileged, s.score_trusts,
                                   s.score_anomalies, s.demo,
                                   (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id AND f.state='fail') AS n_fail
                            FROM scans s ORDER BY s.id DESC LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_findings(scan_id: int) -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY points DESC, rule_id", (scan_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["items"] = json.loads(d.pop("items_json") or "[]")
        out.append(d)
    return out


def previous_done_scan(scan_id: int) -> int | None:
    with conn() as c:
        r = c.execute("SELECT id FROM scans WHERE id<? AND status='done' ORDER BY id DESC LIMIT 1", (scan_id,)).fetchone()
    return int(r["id"]) if r else None


def failed_rule_ids(scan_id: int) -> set[str]:
    with conn() as c:
        rows = c.execute("SELECT rule_id FROM findings WHERE scan_id=? AND state='fail'", (scan_id,)).fetchall()
    return {r["rule_id"] for r in rows}


def delete_scan(scan_id: int) -> bool:
    """Löscht einen Bericht samt Befunden – nie einen laufenden Scan."""
    with conn() as c:
        if c.execute("DELETE FROM scans WHERE id=? AND status!='running'", (scan_id,)).rowcount == 0:
            return False
        c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        return True


def running_scan() -> dict | None:
    with conn() as c:
        r = c.execute("SELECT id FROM scans WHERE status='running' ORDER BY id DESC LIMIT 1").fetchone()
    return dict(r) if r else None


# --- Protokoll ---------------------------------------------------------------

def audit(action: str, user: str | None = None, ip: str | None = None, detail: str | None = None) -> None:
    with conn() as c:
        c.execute("INSERT INTO audit_log(ts, user, ip, action, detail) VALUES(?,?,?,?,?)",
                  (now_iso(), user, ip, action, (detail or "")[:500]))


def audit_entries(limit: int = 300) -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# --- Gemerkte DC-Zertifikate (LDAPS-Autovertrauen) ---------------------------

def get_pin(host: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM cert_pins WHERE host=?", (host.lower(),)).fetchone()
    return dict(r) if r else None


def save_pin(host: str, fp: str, subject: str, not_after: str, is_ca: bool, der: bytes, names: str = "") -> None:
    with conn() as c:
        c.execute("""INSERT OR REPLACE INTO cert_pins(host, fingerprint, subject, not_after, is_ca, der, first_seen, last_seen, names)
                     VALUES(?,?,?,?,?,?,?,?,?)""", (host.lower(), fp, subject, not_after, int(is_ca), der, now_iso(), now_iso(),
                                                  names))


def set_pin_names(host: str, names: str) -> None:
    with conn() as c:
        c.execute("UPDATE cert_pins SET names=? WHERE host=?", (names, host.lower()))


def family_pins(base: str) -> list[dict]:
    """Alle gemerkten Einträge eines konfigurierten Namens (\"name\" und \"name [IP]\")."""
    b = base.lower()
    with conn() as c:
        rows = c.execute("SELECT * FROM cert_pins WHERE host=? OR substr(host, 1, ?)=?",
                         (b, len(b) + 2, b + " [")).fetchall()
    return [dict(r) for r in rows]


def touch_pin(host: str) -> None:
    with conn() as c:
        c.execute("UPDATE cert_pins SET last_seen=? WHERE host=?", (now_iso(), host.lower()))


def list_pins() -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT host, fingerprint, subject, not_after, is_ca, first_seen, last_seen FROM cert_pins ORDER BY host").fetchall()
    return [dict(r) for r in rows]


def delete_pins(host: str | None = None) -> int:
    with conn() as c:
        if host:
            cur = c.execute("DELETE FROM cert_pins WHERE host=?", (host.lower(),))
        else:
            cur = c.execute("DELETE FROM cert_pins")
        return cur.rowcount


# --- Einfache Schlüssel/Wert-Ablage (z. B. erkannter Domänentyp) -------------

def set_kv(key: str, value: str) -> None:
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO kv(key, value) VALUES(?,?)", (key, value))


def get_kv(key: str, default: str | None = None) -> str | None:
    with conn() as c:
        r = c.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


# --- Löschfristen (Datenschutz) ------------------------------------------------

def purge_expired(report_days: int, audit_days: int) -> dict:
    """Löscht Berichte und Protokolleinträge, die älter als die Frist sind (0 = nie)."""
    from datetime import timedelta
    out = {"scans": 0, "audit": 0}
    now = datetime.now(timezone.utc)
    with conn() as c:
        if report_days and report_days > 0:
            cutoff = (now - timedelta(days=report_days)).isoformat(timespec="seconds")
            old = "SELECT id FROM scans WHERE started_at < ? AND status != 'running'"
            c.execute(f"DELETE FROM findings WHERE scan_id IN ({old})", (cutoff,))
            out["scans"] = c.execute(f"DELETE FROM scans WHERE id IN ({old})", (cutoff,)).rowcount
        if audit_days and audit_days > 0:
            cutoff = (now - timedelta(days=audit_days)).isoformat(timespec="seconds")
            out["audit"] = c.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,)).rowcount
    if out["scans"] or out["audit"]:
        compact()
    return out


def compact() -> None:
    """Gelöschte Daten auch physisch entfernen: Datei neu aufbauen und WAL-Datei leeren."""
    with _lock:
        with conn():
            pass  # stellt die Verbindung her
        _con.execute("VACUUM")
        _con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
