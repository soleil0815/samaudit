# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Is there a newer version? For installations that do not update automatically.

Two parts:

1. Age hint (always, no network): every version knows its release date (app/docs/news.json).
   If the running version is older than UPDATE_HINT_DAYS (default 60, 0 = off), the overview
   suggests checking for a newer version. Nothing is loaded from the internet for this.

2. Online check (only with UPDATE_CHECK=true, default off): at most once a day the server asks
   GitHub for the number of the latest published version (one HTTPS GET on
   api.github.com/repos/<owner>/<repo>/releases/latest). Nothing is sent apart from the request
   itself – no domain, no names, no statistics. The egress guard then allows exactly this host on
   port 443 and nothing else. Proxies from the environment are not used. A failed check stays
   silent: no error in the interface, only a note in the server log and the diagnostics package.

SAMAUDIT never updates itself – that remains the job of Dockhand, Watchtower or update.sh."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.request
from datetime import date, datetime, timezone
from typing import Any

from .config import settings
from .version import IMAGE_VERSION, SOURCE_URL, VERSION

log = logging.getLogger("samaudit.update")

HOST = "api.github.com"
PORT = 443
INTERVAL = 24 * 3600          # successful check: once a day
RETRY = 6 * 3600              # failed check: try again after 6 hours
FIRST_DELAY = 60              # first check one minute after start
MAX_BYTES = 256 * 1024
COOKIE = "samaudit_update"

_repo = re.sub(r"^https://github\.com/", "", SOURCE_URL).strip("/")
API_URL = f"https://{HOST}/repos/{_repo}/releases/latest"
RELEASES_URL = f"{SOURCE_URL}/releases"
_TAG = re.compile(r"v?(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-s\d{1,4})?)")

_lock = threading.Lock()
_state: dict[str, Any] = {"checked_at": None, "ok_at": None, "latest": None, "error": None}
_started = time.time()
_ips: dict[str, Any] = {"ips": set(), "ts": 0.0}


def vkey(v: str) -> tuple:
    """"2.4.1" → (2, 4, 1, 0), security update "2.4.1-s2" → (2, 4, 1, 2)."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-s(\d+))?", str(v or "").strip())
    if not m:
        return (0, 0, 0, 0)
    return tuple(int(x or 0) for x in m.groups())


def newer(latest: str | None) -> bool:
    """Is `latest` newer than the running image (program version or security update)?"""
    return latest is not None and vkey(latest) > vkey(IMAGE_VERSION)


# --- egress guard -------------------------------------------------------------

def host_ips() -> set[str]:
    """Current addresses of the GitHub API (only needed while UPDATE_CHECK is on)."""
    if not settings.update_check:
        return set()
    now = time.time()
    with _lock:
        if now - float(_ips["ts"]) < 120 and _ips["ips"]:
            return set(_ips["ips"])
    from . import egress
    ips: set[str] = set()
    try:
        for info in egress._orig_getaddrinfo(HOST, PORT, type=socket.SOCK_STREAM):
            ips.add(str(ipaddress.ip_address(str(info[4][0]).split("%")[0])))
    except (OSError, ValueError):
        pass
    with _lock:
        _ips.update(ips=ips, ts=now)
    return ips


def allows(ip: str, port: int) -> bool:
    """For the egress guard: is this the GitHub API while the online check is on?"""
    return bool(settings.update_check) and port == PORT and ip in host_ips()


# --- online check --------------------------------------------------------------

def parse_latest(body: bytes) -> str:
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict) or data.get("draft") or data.get("prerelease"):
        raise ValueError("no published release")
    m = _TAG.fullmatch(str(data.get("tag_name", "")).strip())
    if not m:
        raise ValueError("unexpected tag")
    return m.group(1)


def _fetch() -> str:
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json",
                                                   "User-Agent": "SAMAUDIT-update-check"})   # no version, no ID
    with opener.open(req, timeout=15) as r:   # noqa: S310 – fixed https URL
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError("answer too large")
    return parse_latest(body)


def check_now(fetch=None) -> dict:
    """One check (blocking). Returns the new state."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        latest = (fetch or _fetch)()
        with _lock:
            _state.update(checked_at=now, ok_at=now, latest=latest, error=None)
        if newer(latest):
            log.info("Update check: version %s is available (running %s)", latest, IMAGE_VERSION)
        else:
            log.info("Update check: %s is up to date", IMAGE_VERSION)
    except Exception as e:  # noqa: BLE001 – never disturb the program
        with _lock:
            _state.update(checked_at=now, error=type(e).__name__)
        log.info("Update check failed (%s) – trying again later", type(e).__name__)
    return state()


def due() -> bool:
    if not settings.update_check or settings.demo_mode:
        return False
    with _lock:
        checked, ok = _state["checked_at"], _state["error"] is None
    if checked is None:
        return time.time() - _started >= FIRST_DELAY
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(checked)).total_seconds()
    return age >= (INTERVAL if ok else RETRY)


def state() -> dict:
    with _lock:
        return dict(_state)


def set_state(**kw) -> None:
    """For tests and the screenshots."""
    with _lock:
        _state.update(kw)


# --- what the overview shows -----------------------------------------------------

def release_date() -> date | None:
    """Date of the running image: the security update's entry if there is one, else the program version's."""
    from . import news
    for wanted in dict.fromkeys((IMAGE_VERSION, VERSION)):
        for r in news.ENTRIES:
            if r["version"] == wanted:
                try:
                    return date.fromisoformat(r["date"])
                except ValueError:
                    return None
    return None


def notice(dismissed: str | None, today: date | None = None) -> dict | None:
    """The hint for the overview or None.
    kind "new": the online check found a newer version (stays until dismissed for this version).
    kind "age": this version is older than UPDATE_HINT_DAYS (no network; not shown when the online
                check confirmed within the last 3 days that it is up to date)."""
    st = state()
    if settings.update_check and newer(st["latest"]):
        key = f"new:{st['latest']}"
        return None if dismissed == key else {"kind": "new", "version": st["latest"], "key": key}
    days = settings.update_hint_days
    rel = release_date()
    if days <= 0 or rel is None:
        return None
    age = ((today or date.today()) - rel).days
    if age < days:
        return None
    if settings.update_check and st["ok_at"]:
        ok_age = (datetime.now(timezone.utc) - datetime.fromisoformat(st["ok_at"])).total_seconds()
        if ok_age < 3 * 86400:
            return None
    key = f"age:{VERSION}"
    return None if dismissed == key else {"kind": "age", "version": VERSION, "date": rel, "days": age, "key": key}


def diag_part() -> dict:
    st = state()
    rel = release_date()
    return {"online_check": bool(settings.update_check), "hint_days": settings.update_hint_days,
            "release_date": rel.isoformat() if rel else None,
            "last_check": st["checked_at"], "last_success": st["ok_at"], "latest": st["latest"],
            "error": st["error"],
            "newer_available": newer(st["latest"])}
