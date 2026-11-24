# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Encrypted LDAP on port 389 without a certificate: SASL GSS-SPNEGO bind with Kerberos (or NTLM) and
"sign and seal" of every following message – as the Windows tools (RSAT) do it.

Many Windows domains have no certificate on their domain controllers, so LDAPS (636) is not available there. A
simple bind on 389 would send the password in clear text, and a DC that requires LDAP signing refuses it anyway.
With SASL sealing the connection is encrypted after the bind.

ldap3 can bind with NTLM but never seals the traffic, so the security layer sits below ldap3: after the bind, the
connection's socket is replaced by SealedSocket, which wraps (encrypts) every outgoing LDAP message and unwraps every
incoming one. The SASL framing is a 4-byte big-endian length followed by the wrapped token (RFC 4422 / 4752).
pyspnego provides NTLM and – with the MIT Kerberos libraries and the packages gssapi and krb5 – Kerberos (see
app/kerberos.py). Kerberos is tried first; its target name comes from the configuration (DC_HOSTS), never from the
unauthenticated RootDSE. Adapted from SAMONBOARDING (same authors' approach, 2.10.0).
"""
from __future__ import annotations

import logging
import struct
import threading
import time
from typing import Any

log = logging.getLogger("samaudit.ldap")

SASL_MECHANISM = "GSS-SPNEGO"
MAX_FRAME = 16 * 1024 * 1024        # a broken or hostile server must not make us allocate unlimited memory
SASL_BIND_IN_PROGRESS = 14
INVALID_CREDENTIALS = 49


class SealError(Exception):
    """The encrypted connection could not be set up (not a password problem)."""

    def __init__(self, message: str, reason: str = "other"):
        super().__init__(message)
        self.reason = reason


class SealedSocket:
    """Socket replacement for ldap3's sync strategy: only sendall, recv, settimeout, shutdown and close are used."""

    def __init__(self, sock, ctx):
        self._sock = sock
        self._ctx = ctx
        self._raw = bytearray()      # bytearray: appending chunks does not copy the whole buffer each time
        self._plain = b""

    def sendall(self, data) -> None:
        try:
            wrapped = self._ctx.wrap(bytes(data), encrypt=True).data
        except Exception as e:  # noqa: BLE001
            raise OSError(f"LDAP encryption failed: {type(e).__name__}") from None
        self._sock.sendall(struct.pack(">I", len(wrapped)) + wrapped)

    def _read(self, n: int) -> bytes:
        while len(self._raw) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise OSError("LDAP connection closed by the server")
            self._raw += chunk
        out = bytes(self._raw[:n])
        del self._raw[:n]
        return out

    def recv(self, size: int) -> bytes:
        if not self._plain:
            length = struct.unpack(">I", self._read(4))[0]
            if not 0 < length <= MAX_FRAME:
                raise OSError(f"invalid length of an encrypted LDAP message: {length}")
            frame = self._read(length)
            try:
                self._plain = self._ctx.unwrap(frame).data
            except Exception as e:  # noqa: BLE001 – a message that cannot be decrypted is never passed on
                raise OSError(f"LDAP message cannot be decrypted: {type(e).__name__}") from None
            if not self._plain:
                raise OSError("empty encrypted LDAP message")
        out, self._plain = self._plain[:size], self._plain[size:]
        return out

    def settimeout(self, value) -> None:
        self._sock.settimeout(value)

    def shutdown(self, how) -> None:
        self._sock.shutdown(how)

    def close(self) -> None:
        self._sock.close()

    def __getattr__(self, name):     # anything else (fileno, getpeername …) from the real socket
        return getattr(self._sock, name)


_SPNEGO_CLASSES: dict[str, Any] = {}


def _spnego_class(protocol: str):
    """SPNEGO that offers exactly ONE mechanism. pyspnego's "negotiate" would try Kerberos and then NTLM on its own –
    with a wrong password that would count twice towards the account lockout, and after a refused Kerberos it
    would silently use NTLM. The order (Kerberos first, NTLM only if allowed) is decided in sealed_bind."""
    if protocol not in _SPNEGO_CLASSES:
        from spnego._negotiate import NegotiateProxy

        class OneMechanism(NegotiateProxy):
            @classmethod
            def available_protocols(cls, options=None):
                return [protocol, "negotiate"]

        _SPNEGO_CLASSES[protocol] = OneMechanism
    return _SPNEGO_CLASSES[protocol]


def _client_context(user, password, hostname: str, protocol: str):
    """protocol: 'kerberos' or 'ntlm', always wrapped in SPNEGO (the SASL mechanism is GSS-SPNEGO)."""
    import spnego
    req = spnego.ContextReq.default | spnego.ContextReq.integrity | spnego.ContextReq.confidentiality
    return _spnego_class(protocol)(user, password, hostname=hostname, service="ldap", context_req=req)


# Kerberos per DC name: worked once in this process (then never NTLM again – someone blocking port 88 must not be
# able to force the weaker NTLM), or failed a moment ago (then NTLM for a while, without waiting and logging each
# time – only when NTLM is allowed at all)
KERBEROS_RETRY_SECONDS = 600
_state_lock = threading.Lock()
_kerberos_seen: set[str] = set()
_kerberos_missing: dict[str, float] = {}


def reset_state() -> None:
    with _state_lock:
        _kerberos_seen.clear()
        _kerberos_missing.clear()


def kerberos_seen(target: str) -> bool:
    with _state_lock:
        return target.lower() in _kerberos_seen


def kerberos_failed_recently(target: str) -> bool:
    with _state_lock:
        return _kerberos_missing.get(target.lower(), 0) > time.monotonic()


def _start(password: str, host: str, kerberos: dict | None, ntlm_user: str | None):
    """Context and first token: Kerberos first (if possible), else NTLM (if allowed).
    Returns (ctx, token, kind, ticket, why) – the ticket must be destroyed by the caller; why = reason Kerberos
    was not used ('' if it was)."""
    from . import kerberos as krb
    from .ldapsrc import AuthError

    if kerberos is None:
        why = "off"                    # LDAP_KERBEROS=false
    else:
        why = "" if kerberos.get("principal") else kerberos.get("skip", "other")
    target = str((kerberos or {}).get("target", "")).lower()
    if kerberos and kerberos.get("principal"):
        with _state_lock:
            backoff = ntlm_user is not None and _kerberos_missing.get(target, 0) > time.monotonic()
        if backoff:
            why = "backoff"
        else:
            ticket = None
            try:
                import spnego
                ticket = krb.new_ticket(kerberos["principal"], password)
                ctx = _client_context(spnego.KerberosCCache(ccache=ticket.name), None, target, "kerberos")
                token = ctx.step()
                with _state_lock:
                    _kerberos_seen.add(target)
                    _kerberos_missing.pop(target, None)
                return ctx, token, "kerberos", ticket, ""
            except Exception as e:  # noqa: BLE001
                krb.destroy_ticket(ticket)
                code = krb.credential_error(e)
                if code:
                    # the KDC refused the password or the account: do NOT try NTLM with the same password as well
                    raise AuthError(code) from None
                why = krb.reason(e)
                with _state_lock:
                    seen = target in _kerberos_seen
                if seen:
                    raise SealError(f"Kerberos to {target} not possible (it worked before) – no fallback to NTLM",
                                    why) from None
                if ntlm_user is None:
                    raise SealError(f"Kerberos to {target} not possible: {_short(e)}", why) from None
                with _state_lock:
                    first = target not in _kerberos_missing
                    _kerberos_missing[target] = time.monotonic() + KERBEROS_RETRY_SECONDS
                if first:
                    log.info("Kerberos to %s not possible (%s), NTLM is used: %s", target, why, _short(e))
    if ntlm_user is None:
        raise SealError("Kerberos not possible and NTLM not allowed (LDAP_NTLM)", why or "other")
    try:
        ctx = _client_context(ntlm_user, password, host, "ntlm")
        return ctx, ctx.step(), "ntlm", None, why or "other"
    except Exception as e:  # noqa: BLE001
        raise SealError(f"encrypted sign-in not possible: {type(e).__name__}") from None


def _short(error, limit: int = 200) -> str:
    text = " ".join(str(error).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _negotiate(conn, token: bytes):
    """One SASL bind round (replaceable in tests)."""
    from ldap3.protocol.sasl.sasl import send_sasl_negotiation
    return send_sasl_negotiation(conn, None, token)


class _Result:
    def __init__(self, result):
        self.result = result


def sealed_bind(conn, password: str, host: str, kerberos: dict | None, ntlm_user: str | None,
                keep_ticket: bool = False):
    """SASL GSS-SPNEGO bind on an opened (not yet bound) ldap3 connection; afterwards all traffic is encrypted.

    kerberos:  {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"} to try Kerberos first (the target
               from the configuration, never from the network), or {"skip": reason} / None.
    ntlm_user: "FIRMA\\anna" if NTLM may be used, None if not.

    Returns (kind, ticket, why): kind "kerberos" or "ntlm"; ticket only with keep_ticket (destroy it with
    kerberos.destroy_ticket); why = reason Kerberos was not used. Raises AuthError for a wrong password or a
    locked account (like a simple bind) and SealError if the encrypted connection could not be set up."""
    from . import kerberos as krb
    ctx, token, kind, ticket, why = _start(password, host, kerberos, ntlm_user)
    try:
        _bind_rounds(conn, ctx, token)
    except BaseException:
        krb.destroy_ticket(ticket)
        raise
    if not keep_ticket:
        # the user's Kerberos tickets are not kept: the established context has its own session key
        krb.destroy_ticket(ticket)
        ticket = None
    return kind, ticket, why


def _bind_rounds(conn, ctx, token: bytes) -> None:
    from .ldapsrc import AuthError, _bind_error
    conn.sasl_mechanism = SASL_MECHANISM
    conn.sasl_in_progress = True
    try:
        for _round in range(10):     # NTLM needs 2, Kerberos 1-2 rounds
            result = _negotiate(conn, token) or {}
            code = result.get("result")
            creds = result.get("saslCreds") or b""
            if code == INVALID_CREDENTIALS:
                _bind_error(_Result(result))          # data 775 / 52e … → the matching AuthError
            if code == 0:
                if creds and not ctx.complete:
                    ctx.step(creds)
                break
            if code != SASL_BIND_IN_PROGRESS:
                desc = str(result.get("description") or "")
                if desc.lower() in ("strongerauthrequired", "confidentialityrequired"):
                    raise AuthError("tls_required", desc)
                raise SealError(f"the DC refuses the encrypted sign-in: {desc}")
            token = ctx.step(creds)
        else:
            raise SealError("encrypted sign-in: too many rounds")
        if not ctx.complete:
            raise SealError("encrypted sign-in not completed")
        import spnego
        if spnego.ContextReq.confidentiality not in ctx.context_attr:
            # the DC agreed to the bind but not to encryption – never continue unencrypted
            raise SealError("the DC did not agree to encryption")
    except (AuthError, SealError):
        raise
    except Exception as e:  # noqa: BLE001
        raise SealError(f"encrypted sign-in failed: {type(e).__name__}") from None
    finally:
        conn.sasl_in_progress = False
    conn.socket = SealedSocket(conn.socket, ctx)
    conn.bound = True
