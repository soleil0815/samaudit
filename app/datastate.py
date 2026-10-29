# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Datenbank beim Start schützen – unabhängig davon, wie das Update kam (Dockhand, Watchtower,
docker compose pull, update.sh):

1. Nur eine SAMAUDIT-Instanz je Datenordner (Sperrdatei mit fcntl-Lock – wirkt auch zwischen Containern).
2. Stammt die Datenbank von einer NEUEREN Programmversion (Rückschritt), wird nicht gestartet, sondern
   klar gemeldet, welche Sicherung zurückzuspielen ist – statt mit Folgefehlern weiterzulaufen.
3. Läuft eine andere Programmversion als zuletzt, wird zuerst eine Sicherung „vor-<Version>“ angelegt
   (data/backups/samaudit-vor-<Version>-<Zeit>.db), erst danach ändern Migrationen das Schema.
4. Die Compose-Datei meldet ihre Version (SAMAUDIT_COMPOSE); ist sie zu alt, gibt es einen Hinweis.
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

log = logging.getLogger("samaudit.daten")

# Version des Datenbankschemas – bei jeder Schemaänderung (Migration in db._migrate) erhöhen
SCHEMA_VERSION = 2
# Version der docker-compose.yml, die dieses Programm erwartet (bei Änderungen an der Datei erhöhen)
COMPOSE_REQUIRED = 1

_lock_fd: int | None = None


class StartRefused(Exception):
    """Start abgelehnt – die Meldung ist für Menschen geschrieben."""


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


# --------------------------------------------------------------------------- Sperre
def acquire_lock() -> None:
    """Nur eine Instanz je Datenordner. Der Lock gilt, solange der Prozess läuft."""
    global _lock_fd
    os.makedirs(settings.data_dir, exist_ok=True)
    fd = os.open(os.path.join(settings.data_dir, ".samaudit.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise StartRefused("Auf diesem Datenordner läuft bereits ein SAMAUDIT-Container. Bitte nur einen "
                           "Container je Datenordner betreiben (z. B. den alten Container entfernen: "
                           "docker ps -a).") from None
    _lock_fd = fd


def is_locked_elsewhere() -> bool:
    """True, wenn gerade ein laufendes SAMAUDIT diesen Datenordner benutzt (für restore)."""
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


# --------------------------------------------------------------------------- Metadaten
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
    """Alle Sicherungen, neueste zuerst (auch die Einzelsicherungen früherer Versionen)."""
    files = glob.glob(os.path.join(backup_dir(), "samaudit-*.db"))
    files += glob.glob(settings.db_path + ".vor-*.bak")
    return sorted(files, key=lambda f: os.path.getmtime(f), reverse=True)


def _backups_for(version: str) -> list[str]:
    return [f for f in list_backups() if os.path.basename(f).startswith(f"samaudit-vor-{version}-")]


def _prune() -> None:
    keep = backup_keep()
    if keep == 0:
        return
    vor = [f for f in list_backups() if os.path.basename(f).startswith("samaudit-vor-")]
    for f in vor[keep:]:
        try:
            os.remove(f)
            log.info("Alte Sicherung entfernt: %s", f)
        except OSError as e:
            log.warning("Alte Sicherung nicht entfernbar: %s (%s)", f, e)


def backup_now(label: str) -> str:
    """Konsistente Kopie der Datenbank (SQLite-Backup-API) nach data/backups/."""
    os.makedirs(backup_dir(), mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(backup_dir(), f"samaudit-{label}-{stamp}.db")
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(backup_dir(), f"samaudit-{label}-{stamp}-{n}.db")
    src = sqlite3.connect(settings.db_path, timeout=30)
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
    """Vor db.init(): Rückschritt erkennen, bei Versionswechsel sichern. Gibt den Sicherungspfad zurück."""
    if not os.path.exists(settings.db_path):
        return None                                   # neue Installation
    meta = _read_meta(settings.db_path)
    db_app = meta.get("app_version")
    try:
        db_schema = int(meta.get("schema_version", "0"))
    except ValueError:
        db_schema = 0
    if (db_app and version_key(db_app) > version_key(VERSION)) or db_schema > SCHEMA_VERSION:
        newer = db_app or f"Schema {db_schema}"
        hint = _backups_for(db_app) if db_app else []
        if hint:
            what = (f"Bitte die Sicherung von vor dem Wechsel auf {newer} zurückspielen: "
                    f"{os.path.relpath(hint[0], settings.data_dir)} (im Datenordner) – "
                    f"„docker compose run --rm samaudit restore“ zeigt die Sicherungen und spielt die gewählte zurück.")
        else:
            what = ("Es gibt keine Sicherung „vor-" + str(db_app) + "“. Entweder wieder die neuere Version "
                    "verwenden (SAMAUDIT_VERSION in der .env) oder eine ältere Sicherung zurückspielen: "
                    "„docker compose run --rm samaudit restore“.")
        raise StartRefused(f"Die Datenbank stammt von SAMAUDIT {newer} und ist neuer als dieses Programm "
                           f"({VERSION}). Eine ältere Version kann sie nicht sicher verwenden. {what}")
    if db_app == VERSION and db_schema == SCHEMA_VERSION:
        return None                                   # gleiche Version wie zuletzt – nichts zu tun
    try:
        dest = backup_now(f"vor-{VERSION}")
    except Exception as e:  # noqa: BLE001
        raise StartRefused(f"Sicherung vor dem Wechsel auf {VERSION} fehlgeschlagen ({e}). Ohne Sicherung "
                           "wird die Datenbank nicht verändert – bitte Speicherplatz und Rechte von ./data prüfen.") from e
    log.info("Versionswechsel %s → %s: Datenbank gesichert: %s", db_app or "unbekannt (vor 2.0)", VERSION, dest)
    _prune()
    return dest


# --------------------------------------------------------------------------- Compose-Datei
def compose_status() -> dict | None:
    """None = alles gut; sonst Angaben für den Hinweis (Log und Oberfläche)."""
    raw = os.environ.get("SAMAUDIT_COMPOSE", "").strip()
    have = int(raw) if raw.isdigit() else 0
    if have >= COMPOSE_REQUIRED:
        return None
    return {"have": have, "need": COMPOSE_REQUIRED}


def compose_message(lang: str = "de") -> str | None:
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
    """Beim Start vor allem anderen aufrufen."""
    acquire_lock()
    check_and_backup()
    msg = compose_message("de")
    if msg:
        log.warning(msg)
