# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Automatic trust for LDAPS (trust on first use with pinning).

On first contact with a DC its certificate chain is read and the topmost
verifiably connected issuer (usually the enterprise CA, with Samba the
self-generated certificate) is remembered. Later connections are only
accepted if the chain leads back to this pinned certificate.
That way LDAPS works without importing a CA, and a foreign certificate slipped
in later (man-in-the-middle) is still detected. If the CA renews a
DC certificate, the trust remains.

Reset (e.g. after a CA change):
    docker exec samaudit python -m app.pins reset            # all
    docker exec samaudit python -m app.pins reset dc01.firma.local
"""
from __future__ import annotations

import hashlib
import logging
import sys

from . import db

log = logging.getLogger("samaudit.pins")


class PinMismatch(Exception):
    def __init__(self, host: str, expected: str, got: str):
        super().__init__(f"{host}: expected {expected[:16]}…, got {got[:16]}…")
        self.host, self.expected, self.got = host, expected, got


def peer_chain(sock) -> list[bytes]:
    """DER certificates as sent by the server (leaf first)."""
    chain: list[bytes] = []
    getter = getattr(sock, "get_unverified_chain", None)  # Python ≥ 3.13
    if getter:
        try:
            for c in getter() or []:
                chain.append(bytes(c) if isinstance(c, (bytes, bytearray)) else c.public_bytes(_der_format()))
        except Exception:  # noqa: BLE001
            chain = []
    if not chain:
        leaf = sock.getpeercert(binary_form=True)
        if leaf:
            chain = [leaf]
    return chain


def _der_format():
    import ssl
    return getattr(ssl, "ENCODING_DER", None) or getattr(ssl._ssl, "ENCODING_DER", 1)  # noqa: SLF001


def _load(der: bytes):
    from cryptography import x509
    return x509.load_der_x509_certificate(der)


def _issued_by(child, parent) -> bool:
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:  # noqa: BLE001
        return False


def verified_prefix(chain: list[bytes]) -> list:
    """The partial chain from the leaf in which each certificate is signed by the next one."""
    certs = [_load(d) for d in chain]
    out = certs[:1]
    for i in range(len(certs) - 1):
        if _issued_by(certs[i], certs[i + 1]):
            out.append(certs[i + 1])
        else:
            break
    return out


def fingerprint(cert) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _describe(cert) -> tuple[str, str, bool]:
    from cryptography import x509
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except Exception:  # noqa: BLE001
        is_ca = False
    try:
        not_after = cert.not_valid_after_utc.isoformat(timespec="seconds")
    except AttributeError:
        not_after = cert.not_valid_after.isoformat()
    return cert.subject.rfc4514_string(), not_after, is_ca


SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"


def leaf_names(cert) -> set[str]:
    """DNS names of the server certificate (SAN, or CN as a fallback), lower case."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    names: set[str] = set()
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names |= {n.lower().rstrip(".") for n in san.get_values_for_type(x509.DNSName)}
    except Exception:  # noqa: BLE001
        pass
    if not names:
        names |= {str(a.value).lower().rstrip(".") for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)}
    return names


def _server_cert_ok(cert) -> bool:
    """A server certificate: either without EKU (= all purposes) or with "Server Authentication"."""
    from cryptography import x509
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return True
    except Exception:  # noqa: BLE001
        return False
    return any(o.dotted_string in (SERVER_AUTH_OID, "2.5.29.37.0") for o in eku)


def _anchor_matches(pin: dict, fp: str, path: list, anchor) -> bool:
    if pin["fingerprint"] == fp or any(fingerprint(c) == pin["fingerprint"] for c in path):
        return True
    try:                                   # chain without the pinned certificate this time → check the signature
        return _issued_by(anchor, _load(pin["der"]))
    except Exception:  # noqa: BLE001
        return False


def _names_of(pin: dict) -> set[str]:
    return {n for n in (pin.get("names") or "").split(",") if n}


def _host_matches(host: str, names: set[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(n == h or (n.startswith("*.") and h.endswith(n[1:]) and h.count(".") == n.count(".")) for n in names)


def check(host: str, chain: list[bytes]) -> dict:
    """Checks or pins the certificate. Raises PinMismatch on a deviation.

    Rules (against man-in-the-middle):
    - The certificate must be a server certificate (otherwise any user/computer certificate issued by the
      enterprise CA could impersonate a DC).
    - Known connection: the chain must lead to the pinned certificate AND the server certificate must carry one
      of the DNS names seen on first contact (renewals keep the name).
    - New address of an already pinned name: no new "first trust" – only if the chain leads to
      a pinned certificate of this name and the server certificate carries the configured name.
    """
    if not chain:
        raise PinMismatch(host, "?", "no certificate")
    try:
        path = verified_prefix(chain)
    except Exception as e:  # noqa: BLE001 – unreadable certificate
        raise PinMismatch(host, "?", f"unreadable certificate ({e.__class__.__name__})") from e
    leaf, anchor = path[0], path[-1]
    fp = fingerprint(anchor)
    names = leaf_names(leaf)
    if not _server_cert_ok(leaf):
        db.audit("act_cert_mismatch", detail=f"{host}: kein Serverzertifikat ({leaf.subject.rfc4514_string()})")
        raise PinMismatch(host, "server certificate", "certificate without server authentication")
    base = host.split(" [", 1)[0]
    pin = db.get_pin(host)

    if pin is not None:
        if not _anchor_matches(pin, fp, path, anchor):
            db.audit("act_cert_mismatch", detail=f"{host}: erwartet {pin['fingerprint'][:23]}…, erhalten {fp[:23]}…")
            raise PinMismatch(host, pin["fingerprint"], fp)
        known = _names_of(pin)
        if known and not (known & names):
            db.audit("act_cert_mismatch", detail=f"{host}: Zertifikat für {', '.join(sorted(names))[:120]} "
                                                 f"statt {', '.join(sorted(known))[:120]}")
            raise PinMismatch(host, ", ".join(sorted(known)), ", ".join(sorted(names)) or "?")
        if not known:                      # entries from versions before 1.9.2: add the names now
            db.set_pin_names(host, ",".join(sorted(names)))
        db.touch_pin(host)
        return {"first_use": False, "fingerprint": pin["fingerprint"]}

    family = [p for p in db.family_pins(base) if p["host"] != host.lower()]
    if family:
        # Further address of an already pinned name (e.g. a second DC behind the domain name):
        # only adopt it if the certificate recognisably belongs to a DC of this domain.
        dcs = known_dc_names()

        def plausible_dc() -> bool:
            if dcs:
                return bool(names & dcs) or _host_matches(base, names)
            b = base.lower()
            return any(n == b or n.endswith("." + b) for n in names)

        for p in family:
            if not _anchor_matches(p, fp, path, anchor):
                continue
            if not _names_of(p) or _names_of(p) & names or plausible_dc():
                db.save_pin(host, p["fingerprint"], p["subject"], p["not_after"], bool(p["is_ca"]), p["der"],
                            ",".join(sorted(names)))
                db.touch_pin(host)
                return {"first_use": False, "fingerprint": p["fingerprint"]}
        if not any(p["is_ca"] for p in family) and plausible_dc():
            # self-signed DC certificates (e.g. Samba): every DC has its own – first contact as before
            return _first_use(host, anchor, fp, names, note="weiterer DC")
        db.audit("act_cert_mismatch", detail=f"{host}: neue Adresse mit unbekanntem Zertifikat "
                                             f"({', '.join(sorted(names))[:120]}, SHA256 {fp[:23]}…)")
        raise PinMismatch(host, family[0]["fingerprint"], fp)

    return _first_use(host, anchor, fp, names)


def known_dc_names() -> set[str]:
    """DNS names of the DCs from the last scan (empty until a scan has run)."""
    try:
        return {n for n in (db.get_kv("dc_names") or "").split(",") if n}
    except Exception:  # noqa: BLE001
        return set()


def _first_use(host: str, anchor, fp: str, names: set[str], note: str = "") -> dict:
    from cryptography.hazmat.primitives.serialization import Encoding
    subject, not_after, is_ca = _describe(anchor)
    db.save_pin(host, fp, subject, not_after, is_ca, anchor.public_bytes(Encoding.DER), ",".join(sorted(names)))
    db.audit("act_cert_pinned", detail=f"{host}: {subject} SHA256 {fp[:23]}…" + (f" ({note})" if note else ""))
    log.warning("LDAPS: certificate of %s trusted automatically and pinned (%s, SHA256 %s)", host, subject, fp)
    return {"first_use": True, "fingerprint": fp, "subject": subject}


def _cli(argv: list[str]) -> int:
    db.init()
    if len(argv) < 1 or argv[0] not in ("list", "reset"):
        print("Usage: python -m app.pins list | reset [host]")
        return 2
    if argv[0] == "list":
        for p in db.list_pins():
            print(f"{p['host']:35} {'CA ' if p['is_ca'] else 'DC '} {p['subject']}\n{'':35} SHA256 {p['fingerprint']}  "
                  f"valid until {p['not_after']}  pinned {p['first_seen']}")
        return 0
    n = db.delete_pins(argv[1] if len(argv) > 1 else None)
    print(f"{n} pinned certificate(s) removed. They will be trusted again at the next sign-in.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
