# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Protect the database at start-up – regardless of how the update arrived (Dockhand, Watchtower,
docker compose pull, update.sh):

1. Only one SAMAUDIT instance per data folder (lock file with an fcntl lock – also works across containers).
2. If the database comes from a NEWER program version (downgrade), the program does not start but
   states clearly which backup to restore – instead of carrying on with follow-up errors.
3. If a different program version runs than last time, a backup "vor-<version>" is created first
   (data/backups/samaudit-vor-<version>-<time>.db; "vor" = "before", the name is kept for existing
   installations); only then do migrations change the schema.
4. The Compose file reports its version (SAMAUDIT_COMPOSE); if it is too old, a note is shown.
"""
from __future__ import annotations

import fcntl
import glob
import logging
import os
import re
import sqlite3
import time

from .config import settings
from .version import VERSION

log = logging.getLogger("samaudit.data")

# version of the database schema – increase with every schema change (migration in db._migrate)
SCHEMA_VERSION = 2
# version of docker-compose.yml this program expects (increase when the file changes)
COMPOSE_REQUIRED = 1

_lock_fd: int | None = None


class StartRefused(Exception):
    """Start refused – the message is written for humans."""


def version_key(v: str | None) -> tuple[int, ...]:
    m = re.match(r"^v?(\d+(?:\.\d+)*)", (v or "").strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def backup_dir() -> str:
    return os.path.join(settings.data_dir, "backups")


def backup_keep() -> int:
    try:
        return max(0, int(os.environ.get("BACKUP_KEEP", "5")))
    except ValueError:
        return 5


# --------------------------------------------------------------------------- lock
def acquire_lock() -> None:
    """Only one instance per data folder. The lock holds as long as the process runs."""
    global _lock_fd
    os.makedirs(settings.data_dir, exist_ok=True)
    fd = os.open(os.path.join(settings.data_dir, ".samaudit.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise StartRefused("A SAMAUDIT container is already running on this data folder. Please run only one "
                           "container per data folder (e.g. remove the old container: "
                           "docker ps -a).") from None
    _lock_fd = fd


def is_locked_elsewhere() -> bool:
    """True if a running SAMAUDIT is currently using this data folder (for restore)."""
    path = os.path.join(settings.data_dir, ".samaudit.lock")
    if not os.path.exists(path):
        return False
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.lockf(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- metadata
def _read_meta(path: str) -> dict[str, str]:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='kv'").fetchone():
            return {}
        return {k: v for k, v in con.execute(
            "SELECT key, value FROM kv WHERE key IN ('app_version', 'schema_version')").fetchall()}
    finally:
        con.close()


def write_meta(con: sqlite3.Connection) -> None:
    con.execute("INSERT OR REPLACE INTO kv(key, value) VALUES('app_version', ?)", (VERSION,))
    con.execute("INSERT OR REPLACE INTO kv(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))


def list_backups() -> list[str]:
    """All backups, newest first (including the single backups of earlier versions)."""
    files = glob.glob(os.path.join(backup_dir(), "samaudit-*.db"))
    files += glob.glob(settings.db_path + ".vor-*.bak")
    return sorted(files, key=lambda f: os.path.getmtime(f), reverse=True)


def _backups_for(version: str) -> list[str]:
    return [f for f in list_backups() if os.path.basename(f).startswith(f"samaudit-vor-{version}-")]


_VOR = re.compile(r"^samaudit-vor-(.+?)-(\d{8}-\d{6})(?:-\d+)?\.db$")


def _prune() -> None:
    """Per program version the oldest (state before the first switch) and the newest backup remain;
    the backups of the last BACKUP_KEEP versions are kept. This way a crash loop cannot push out
    useful older backups."""
    keep = backup_keep()
    if keep == 0:
        return
    groups: dict[str, list[str]] = {}
    for f in list_backups():                                   # newest first
        m = _VOR.match(os.path.basename(f))
        if m:
            groups.setdefault(m.group(1), []).append(f)
    order = sorted(groups, key=lambda v: os.path.getmtime(groups[v][0]), reverse=True)
    remove: list[str] = []
    for i, v in enumerate(order):
        files = groups[v]
        if i >= keep:
            remove += files
        elif len(files) > 2:
            remove += files[1:-1]                              # between newest and oldest
    for f in remove:
        try:
            os.remove(f)
            log.info("Old backup removed: %s", f)
        except OSError as e:
            log.warning("Old backup could not be removed: %s (%s)", f, e)


def _db_mtime() -> float:
    return max(os.path.getmtime(p) for p in (settings.db_path, settings.db_path + "-wal") if os.path.exists(p))


def backup_now(label: str) -> str:
    """Consistent copy of the database (SQLite backup API) to data/backups/."""
    os.makedirs(backup_dir(), mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(backup_dir(), f"samaudit-{label}-{stamp}.db")
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(backup_dir(), f"samaudit-{label}-{stamp}-{n}.db")
    # open read-only: does not change the database (or its timestamp)
    src = sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True, timeout=30)
    try:
        tmp = dest + ".part"
        target = sqlite3.connect(tmp)
        try:
            src.backup(target)
        finally:
            target.close()
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    finally:
        src.close()
    return dest


def check_and_backup() -> str | None:
    """Before db.init(): detect a downgrade, back up on a version change. Returns the backup path."""
    if not os.path.exists(settings.db_path):
        return None                                   # new installation
    try:
        meta = _read_meta(settings.db_path)
    except sqlite3.DatabaseError as e:
        raise StartRefused(f"The database {settings.db_path} is not readable ({e}). Please restore a backup: "
                           "\"docker compose run --rm samaudit restore\".") from None
    db_app = meta.get("app_version")
    try:
        db_schema = int(meta.get("schema_version", "0"))
    except ValueError:
        db_schema = 0
    if (db_app and version_key(db_app) > version_key(VERSION)) or db_schema > SCHEMA_VERSION:
        newer = db_app or f"schema {db_schema}"
        hint = _backups_for(db_app) if db_app else []
        if hint:
            what = (f"Please restore the backup from before the switch to {newer}: "
                    f"{os.path.relpath(hint[0], settings.data_dir)} (in the data folder) – "
                    "\"docker compose run --rm samaudit restore\" lists the backups and restores the chosen one.")
        else:
            what = ("There is no backup \"vor-" + str(db_app) + "\". Either use the newer version again "
                    "(SAMAUDIT_VERSION in .env) or restore an older backup: "
                    "\"docker compose run --rm samaudit restore\".")
        raise StartRefused(f"The database comes from SAMAUDIT {newer} and is newer than this program "
                           f"({VERSION}). An older version cannot use it safely. {what}")
    if db_app == VERSION and db_schema == SCHEMA_VERSION:
        return None                                   # same version as last time – nothing to do
    # already backed up and unchanged since (e.g. restart after a crash)? then no further copy
    same = [b for b in _backups_for(VERSION) if os.path.getmtime(b) >= _db_mtime()]
    if same:
        log.info("Backup from before the switch to %s already exists: %s", VERSION, same[0])
        return same[0]
    try:
        dest = backup_now(f"vor-{VERSION}")
    except Exception as e:  # noqa: BLE001
        raise StartRefused(f"Backup before the switch to {VERSION} failed ({e}). Without a backup the database "
                           "is not changed – please check free space and permissions of ./data.") from e
    log.info("Version change %s → %s: database backed up: %s", db_app or "unknown (before 2.0)", VERSION, dest)
    _prune()
    return dest


# --------------------------------------------------------------------------- Compose file
def compose_status() -> dict | None:
    """None = all good; otherwise details for the note (log and web UI)."""
    raw = os.environ.get("SAMAUDIT_COMPOSE", "").strip()
    have = int(raw) if raw.isdigit() else 0
    if have >= COMPOSE_REQUIRED:
        return None
    return {"have": have, "need": COMPOSE_REQUIRED}


def compose_message(lang: str = "de") -> str | None:
    """Note about an outdated Compose file, in the UI language (lang "de" or "en"); None = no note."""
    st = compose_status()
    if not st:
        return None
    if lang == "en":
        what = (f"your docker-compose.yml is outdated (version {st['have'] or 'none'}, needed {st['need']})"
                if st["have"] else "SAMAUDIT was not started with the current docker-compose.yml")
        return (f"Note: {what}. Get the current file with “sh update.sh” or "
                "“docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.yml”, "
                "keep your own changes in docker-compose.override.yml and run “docker compose up -d”.")
    what = (f"Ihre docker-compose.yml ist veraltet (Version {st['have']}, benötigt {st['need']})"
            if st["have"] else "SAMAUDIT wurde nicht mit der aktuellen docker-compose.yml gestartet")
    return (f"Hinweis: {what}. Aktuelle Datei mit „sh update.sh“ holen oder mit "
            "„docker run --rm --entrypoint cat ghcr.io/soleil0815/samaudit:latest /app/dist/docker-compose.yml“, "
            "eigene Änderungen in die docker-compose.override.yml, dann „docker compose up -d“.")


def prepare() -> None:
    """Call at start-up before anything else."""
    acquire_lock()
    check_and_backup()
    msg = compose_message("en")                       # the log is in English; the web UI shows its own language
    if msg:
        log.warning(msg)
