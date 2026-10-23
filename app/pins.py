# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Automatisches Vertrauen für LDAPS (Trust on First Use mit Pinning).

Beim ersten Kontakt zu einem DC wird dessen Zertifikatskette gelesen und der
oberste nachweisbar zusammenhängende Aussteller (meist die Unternehmens-CA,
bei Samba das selbst erzeugte Zertifikat) gemerkt. Spätere Verbindungen werden
nur akzeptiert, wenn die Kette wieder zu diesem gemerkten Zertifikat führt.
So funktioniert LDAPS ohne CA-Import, ein später untergeschobenes fremdes
Zertifikat (Man-in-the-Middle) wird trotzdem erkannt. Erneuert die CA ein
DC-Zertifikat, bleibt das Vertrauen bestehen.

Zurücksetzen (z. B. nach CA-Wechsel):
    docker exec samaudit python -m app.pins reset            # alle
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
        super().__init__(f"{host}: erwartet {expected[:16]}…, erhalten {got[:16]}…")
        self.host, self.expected, self.got = host, expected, got


def peer_chain(sock) -> list[bytes]:
    """DER-Zertifikate, wie sie der Server gesendet hat (Blatt zuerst)."""
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
    """Die Teilkette ab dem Blatt, in der jedes Zertifikat vom nächsten signiert ist."""
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


def check(host: str, chain: list[bytes]) -> dict:
    """Prüft bzw. merkt das Zertifikat. Wirft PinMismatch bei Abweichung."""
    if not chain:
        raise PinMismatch(host, "?", "kein Zertifikat")
    path = verified_prefix(chain)
    anchor = path[-1]
    fp = fingerprint(anchor)
    pin = db.get_pin(host)
    if pin is None and " [" in host:
        # Übergang: früher gab es einen Eintrag nur für den Namen – passt das Zertifikat, wird er übernommen
        legacy = db.get_pin(host.split(" [", 1)[0])
        if legacy and (legacy["fingerprint"] == fp or any(fingerprint(c) == legacy["fingerprint"] for c in path)):
            db.save_pin(host, legacy["fingerprint"], legacy["subject"], legacy["not_after"], bool(legacy["is_ca"]),
                        legacy["der"])
            pin = db.get_pin(host)
    if pin is None:
        from cryptography.hazmat.primitives.serialization import Encoding
        subject, not_after, is_ca = _describe(anchor)
        db.save_pin(host, fp, subject, not_after, is_ca, anchor.public_bytes(Encoding.DER))
        db.audit("act_cert_pinned", detail=f"{host}: {subject} SHA256 {fp[:23]}…")
        log.warning("LDAPS: Zertifikat von %s automatisch vertraut und gemerkt (%s, SHA256 %s)", host, subject, fp)
        return {"first_use": True, "fingerprint": fp, "subject": subject}
    if pin["fingerprint"] == fp or any(fingerprint(c) == pin["fingerprint"] for c in path):
        db.touch_pin(host)
        return {"first_use": False, "fingerprint": pin["fingerprint"]}
    # Server sendet die Kette diesmal ohne das gemerkte Zertifikat → Signatur prüfen
    try:
        pinned = _load(pin["der"])
        if _issued_by(anchor, pinned):
            db.touch_pin(host)
            return {"first_use": False, "fingerprint": pin["fingerprint"]}
    except Exception:  # noqa: BLE001
        pass
    db.audit("act_cert_mismatch", detail=f"{host}: erwartet {pin['fingerprint'][:23]}…, erhalten {fp[:23]}…")
    raise PinMismatch(host, pin["fingerprint"], fp)


def _cli(argv: list[str]) -> int:
    db.init()
    if len(argv) < 1 or argv[0] not in ("list", "reset"):
        print("Verwendung: python -m app.pins list | reset [host]")
        return 2
    if argv[0] == "list":
        for p in db.list_pins():
            print(f"{p['host']:35} {'CA ' if p['is_ca'] else 'DC '} {p['subject']}\n{'':35} SHA256 {p['fingerprint']}  "
                  f"gültig bis {p['not_after']}  gemerkt {p['first_seen']}")
        return 0
    n = db.delete_pins(argv[1] if len(argv) > 1 else None)
    print(f"{n} gemerkte(s) Zertifikat(e) entfernt. Beim nächsten Login wird neu vertraut.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
