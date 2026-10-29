# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Sicherung der Datenbank zurückspielen.

    docker compose stop samaudit
    docker compose run --rm samaudit restore              # Liste, Auswahl per Nummer
    docker compose run --rm samaudit restore <Dateiname>  # direkt
    docker compose up -d

Die aktuelle Datenbank wird vorher nach data/backups/samaudit-ersetzt-<Zeit>.db gesichert –
ein Zurückspielen lässt sich also selbst wieder rückgängig machen.
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
        ver = v[0] if v else "vor 2.0"
    except sqlite3.Error:
        ver = "?"
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(path)))
    return f"{when}  Stand: {ver}"


def _check(path: str) -> None:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        r = con.execute("PRAGMA integrity_check").fetchone()
    finally:
        con.close()
    if not r or r[0] != "ok":
        raise SystemExit(f"Die Sicherung ist beschädigt ({r[0] if r else '?'}) – nichts geändert.")


def _restore(chosen: str) -> None:
    _check(chosen)
    db = settings.db_path
    if os.path.exists(db):
        saved = datastate.backup_now("ersetzt")
        print(f"Aktuelle Datenbank gesichert: {os.path.relpath(saved, settings.data_dir)}")
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
    print(f"Zurückgespielt: {os.path.basename(chosen)}  ({_info(db)})")


def rollback(version: str, since: float) -> int:
    """Für update.sh: Rückfall nach einem fehlgeschlagenen Update. Nur wenn die neue Version die Datenbank
    bereits übernommen hat, wird die dabei angelegte Sicherung „vor-<Version>“ zurückgespielt."""
    db = settings.db_path
    if not os.path.exists(db):
        print("Keine Datenbank – nichts zurückzuspielen.")
        return 0
    meta = datastate._read_meta(db)
    if meta.get("app_version") != version:
        print(f"Datenbank wurde von {version} nicht verändert – nichts zurückzuspielen.")
        return 0
    cands = [b for b in datastate.list_backups()
             if os.path.basename(b).startswith(f"samaudit-vor-{version}-") and os.path.getmtime(b) >= since - 5]
    if not cands:
        print(f"Keine Sicherung „vor-{version}“ aus diesem Update gefunden – bitte von Hand wählen: sh update.sh --restore")
        return 1
    _restore(cands[0])
    return 0


def main(argv: list[str]) -> int:
    if datastate.is_locked_elsewhere():
        print("SAMAUDIT läuft noch auf diesem Datenordner. Bitte zuerst anhalten: docker compose stop samaudit")
        return 1
    if argv[:1] == ["--rollback"]:
        if len(argv) != 3:
            print("Aufruf: restore --rollback <Version> <Startzeit>")
            return 2
        return rollback(argv[1], float(argv[2]))
    backups = datastate.list_backups()
    if not backups:
        print("Keine Sicherungen gefunden (data/backups/).")
        return 1
    if argv:
        name = os.path.basename(argv[0])
        chosen = next((b for b in backups if os.path.basename(b) == name), None)
        if not chosen:
            print(f"Sicherung nicht gefunden: {name}")
            return 1
    else:
        print("Vorhandene Sicherungen (neueste zuerst):")
        for i, b in enumerate(backups, 1):
            print(f"  {i:2}  {os.path.basename(b):55}  {_info(b)}")
        if not sys.stdin.isatty():
            print("\nDateiname angeben: docker compose run --rm samaudit restore <Dateiname>")
            return 1
        try:
            a = input("Nummer der Sicherung (Enter = abbrechen): ").strip()
        except EOFError:
            a = ""
        if not a.isdigit() or not 1 <= int(a) <= len(backups):
            print("Abgebrochen – nichts geändert.")
            return 1
        chosen = backups[int(a) - 1]
    _restore(chosen)
    print("Jetzt starten: docker compose up -d")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
