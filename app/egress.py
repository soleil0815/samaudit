# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Egress guard: SAMAUDIT may only connect to its own domain controllers.

Every outbound connection attempt of the program is
checked: only the IP addresses of the DCs (DC_HOSTS or DOMAIN_FQDN) on the
LDAP/SMB ports are allowed, plus connections inside the container (localhost).
Everything else is rejected and logged."""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from typing import Any

from .config import settings

log = logging.getLogger("samaudit.egress")

ALLOWED_PORTS = {389, 636, 445, 3268, 3269}
_lock = threading.Lock()
_cache: dict[str, Any] = {"ips": set(), "ts": 0.0}
_last_log: dict[str, float] = {}
_installed = False


def _allowed_ips() -> set[str]:
    now = time.time()
    with _lock:
        if now - float(_cache["ts"]) < 300 and _cache["ips"]:
            return set(_cache["ips"])
    ips: set[str] = set()
    for host in set(settings.dc_hosts) | ({settings.domain_fqdn} if settings.domain_fqdn else set()):
        try:
            for info in _orig_getaddrinfo(host, None):
                ips.add(str(info[4][0]))
        except OSError:
            pass
    for extra in settings.egress_allow:
        try:
            net = ipaddress.ip_network(extra, strict=False)
            ips.add(str(net))
        except ValueError:
            try:
                for info in _orig_getaddrinfo(extra, None):
                    ips.add(str(info[4][0]))
            except OSError:
                pass
    with _lock:
        _cache.update(ips=ips, ts=now)
    return ips


def is_allowed(host: str, port: int) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        # host name instead of an IP: resolve it and check every address
        try:
            addrs = {str(i[4][0]) for i in _orig_getaddrinfo(host, port)}
        except OSError:
            return False
        return bool(addrs) and all(is_allowed(a, port) for a in addrs)
    if ip.is_loopback:
        return True
    if port not in ALLOWED_PORTS | {settings.ldap_port}:
        return False
    for entry in _allowed_ips():
        if "/" in entry:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        elif str(ip) == entry:
            return True
    return False


def _report(host: str, port: int) -> None:
    key = f"{host}:{port}"
    now = time.time()
    if now - _last_log.get(key, 0) < 600:
        return
    _last_log[key] = now
    log.warning("Outbound connection blocked: %s:%s (only domain controllers allowed)", host, port)
    try:
        from . import db
        db.audit("act_egress_blocked", detail=key)
    except Exception:  # noqa: BLE001
        pass


class EgressBlocked(PermissionError):
    pass


def _check(address) -> None:
    if isinstance(address, tuple) and len(address) >= 2:
        host, port = str(address[0]), int(address[1])
        if not is_allowed(host, port):
            _report(host, port)
            raise EgressBlocked(f"connection to {host}:{port} blocked by the SAMAUDIT egress guard")


_orig_getaddrinfo = socket.getaddrinfo
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex


def _connect(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        _check(address)
    return _orig_connect(self, address)


def _connect_ex(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        try:
            _check(address)
        except EgressBlocked:
            return 13  # EACCES
    return _orig_connect_ex(self, address)


def install() -> None:
    """Activates the guard (EGRESS_GUARD=true, default)."""
    global _installed
    if _installed or not settings.egress_guard or settings.demo_mode:
        return
    socket.socket.connect = _connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _connect_ex  # type: ignore[method-assign]
    _installed = True
    log.info("Egress guard active: connections only to %s (ports %s)",
             ", ".join(sorted(set(settings.dc_hosts) | set(settings.egress_allow))) or "–",
             ", ".join(str(p) for p in sorted(ALLOWED_PORTS)))
