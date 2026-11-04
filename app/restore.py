# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Restore a database backup.

    docker compose stop samaudit
    docker compose run --rm samaudit restore              # list, choose by number
    docker compose run --rm samaudit restore <file name>  # directly
    docker compose up -d

The current database is backed up first to data/backups/samaudit-ersetzt-<time>.db ("ersetzt" =
"replaced"; the name is kept for existing installations) – so a restore can itself be undone.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time

from . import datastate
from .config import settings


def _info(path: str) -> str:
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            v = con.execute("SELECT value FROM kv WHERE key='app_version'").fetchone()
        finally:
            con.close()
        ver = v[0] if v else "before 2.0"
    except sqlite3.Error:
        ver = "?"
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(path)))
    return f"{when}  version: {ver}"


def _check(path: str) -> None:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        r = con.execute("PRAGMA integrity_check").fetchone()
    finally:
        con.close()
    if not r or r[0] != "ok":
        raise SystemExit(f"The backup is damaged ({r[0] if r else '?'}) – nothing changed.")


def _restore(chosen: str) -> None:
    _check(chosen)
    db = settings.db_path
    if os.path.exists(db):
        saved = datastate.backup_now("ersetzt")
        print(f"Current database backed up: {os.path.relpath(saved, settings.data_dir)}")
    tmp = db + ".restore"
    src = sqlite3.connect(f"file:{chosen}?mode=ro", uri=True)
    try:
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    os.chmod(tmp, 0o600)
    for suffix in ("-wal", "-shm"):
        if os.path.exists(db + suffix):
            os.remove(db + suffix)
    os.replace(tmp, db)
    print(f"Restored: {os.path.basename(chosen)}  ({_info(db)})")


def rollback(since: float) -> int:
    """For update.sh: rollback after a failed update. If the new version created a backup "vor-…"
    since `since`, it has taken over the database – then the OLDEST of these (the state before the update)
    is restored. Otherwise nothing was changed (e.g. security update of the same version)."""
    cands = [b for b in datastate.list_backups()
             if os.path.basename(b).startswith("samaudit-vor-") and os.path.getmtime(b) >= since - 5]
    if not cands:
        print("The database was not changed by this update – nothing to restore.")
        return 0
    _restore(cands[-1])                       # list_backups: newest first → last = oldest
    return 0


def main(argv: list[str]) -> int:
    try:
        datastate.acquire_lock()             # for the whole run: no start while restoring
    except datastate.StartRefused:
        print("SAMAUDIT is still running on this data folder. Please stop it first: docker compose stop samaudit")
        return 1
    if argv[:1] == ["--rollback"]:
        if len(argv) != 2:
            print("Usage: restore --rollback <start time>")
            return 2
        return rollback(float(argv[1]))
    backups = datastate.list_backups()
    if not backups:
        print("No backups found (data/backups/).")
        return 1
    if argv:
        name = os.path.basename(argv[0])
        chosen = next((b for b in backups if os.path.basename(b) == name), None)
        if not chosen:
            print(f"Backup not found: {name}")
            return 1
    else:
        print("Available backups (newest first):")
        for i, b in enumerate(backups, 1):
            print(f"  {i:2}  {os.path.basename(b):55}  {_info(b)}")
        if not sys.stdin.isatty():
            print("\nGive the file name: docker compose run --rm samaudit restore <file name>")
            return 1
        try:
            a = input("Number of the backup (Enter = cancel): ").strip()
        except EOFError:
            a = ""
        if not a.isdigit() or not 1 <= int(a) <= len(backups):
            print("Cancelled – nothing changed.")
            return 1
        chosen = backups[int(a) - 1]
    _restore(chosen)
    print("Now start it: docker compose up -d")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
