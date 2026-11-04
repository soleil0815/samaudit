# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""In-memory sessions, brute-force protection, CSRF.

The signed-in auditor's password is kept encrypted for the duration of the session (Fernet,
key only in the RAM of this process) so that a scan can run with the auditor's
rights. It is never written to the database or to logs.
After sign-out, timeout or a container restart it is gone."""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field

from cryptography.fernet import Fernet

from .config import settings

_FERNET = Fernet(Fernet.generate_key())
_lock = threading.Lock()


@dataclass
class Session:
    sid: str
    user: str
    display: str
    upn: str
    bind_name: str
    groups: list[str]
    secret: bytes
    csrf: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    ip: str = ""

    def password(self) -> str:
        return _FERNET.decrypt(self.secret).decode()


_sessions: dict[str, Session] = {}
_failures: dict[str, list[float]] = {}
_MAX_AGE_ABS = 12 * 3600  # absolute maximum lifetime of a session


def create(user: str, display: str, upn: str, bind_name: str, groups: list[str], password: str, ip: str) -> Session:
    s = Session(sid=secrets.token_urlsafe(32), user=user, display=display, upn=upn, bind_name=bind_name,
                groups=groups, secret=_FERNET.encrypt(password.encode()), csrf=secrets.token_urlsafe(24), ip=ip)
    with _lock:
        _sessions[s.sid] = s
    return s


def get(sid: str | None) -> Session | None:
    if not sid:
        return None
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return None
        now = time.time()
        if now - s.last_seen > settings.session_timeout_min * 60 or now - s.created > _MAX_AGE_ABS:
            _sessions.pop(sid, None)
            return None
        s.last_seen = now
        return s


def destroy(sid: str | None) -> None:
    if sid:
        with _lock:
            _sessions.pop(sid, None)


def cleanup() -> None:
    now = time.time()
    with _lock:
        for k in [k for k, s in _sessions.items()
                  if now - s.last_seen > settings.session_timeout_min * 60 or now - s.created > _MAX_AGE_ABS]:
            _sessions.pop(k, None)
        for k in list(_failures):
            _failures[k] = [t for t in _failures[k] if now - t < settings.lockout_min * 60]
            if not _failures[k]:
                _failures.pop(k)


# --- Brute-force protection --------------------------------------------------

def _keys(username: str, ip: str) -> list[str]:
    u = (username or "").lower().split("\\")[-1].split("@")[0]
    return [f"u:{u}", f"ip:{ip}"]


def is_locked(username: str, ip: str) -> bool:
    now = time.time()
    window = settings.lockout_min * 60
    with _lock:
        for k in _keys(username, ip):
            recent = [t for t in _failures.get(k, []) if now - t < window]
            limit = settings.max_login_attempts * (3 if k.startswith("ip:") else 1)
            if len(recent) >= limit:
                return True
    return False


def record_failure(username: str, ip: str) -> None:
    with _lock:
        for k in _keys(username, ip):
            _failures.setdefault(k, []).append(time.time())


def reserve_attempt(username: str, ip: str) -> float | None:
    """Checks the lockout and counts the attempt in one step – *before* the (slow) LDAP bind runs.
    That way parallel requests cannot try more passwords than allowed.
    Returns a mark for release_attempt(), or None if locked out."""
    now = time.time()
    window = settings.lockout_min * 60
    with _lock:
        keys = _keys(username, ip)
        for k in keys:
            recent = [t for t in _failures.get(k, []) if now - t < window]
            limit = settings.max_login_attempts * (3 if k.startswith("ip:") else 1)
            if len(recent) >= limit:
                return None
        for k in keys:
            _failures.setdefault(k, []).append(now)
    return now


def release_attempt(username: str, ip: str, mark: float | None) -> None:
    """Do not count the attempt as a failure (success or technical error)."""
    if mark is None:
        return
    with _lock:
        for k in _keys(username, ip):
            lst = _failures.get(k)
            if lst and mark in lst:
                lst.remove(mark)
                if not lst:
                    _failures.pop(k, None)


_lock_logged: dict[str, float] = {}


def should_log_locked(username: str, ip: str) -> bool:
    """Log locked-out retries only once per lockout window (no flooding of the log)."""
    now = time.time()
    key = "|".join(_keys(username, ip))
    with _lock:
        if now - _lock_logged.get(key, 0) < settings.lockout_min * 60:
            return False
        _lock_logged[key] = now
        if len(_lock_logged) > 10_000:
            for k in [k for k, t in _lock_logged.items() if now - t > settings.lockout_min * 60]:
                _lock_logged.pop(k, None)
    return True


def clear_failures(username: str, ip: str) -> None:
    with _lock:
        _failures.pop(_keys(username, ip)[0], None)


# --- CSRF for the sign-in form (before the session) ---------------------------

def new_login_token() -> str:
    return secrets.token_urlsafe(24)


def check_token(expected: str | None, given: str | None) -> bool:
    return bool(expected and given and hmac.compare_digest(expected, given))
