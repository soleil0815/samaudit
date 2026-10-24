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


SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"


def leaf_names(cert) -> set[str]:
    """DNS-Namen des Serverzertifikats (SAN, ersatzweise CN), klein geschrieben."""
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
    """Ein Serverzertifikat: entweder ohne EKU (= alle Zwecke) oder mit „Serverauthentifizierung“."""
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
    try:                                   # Kette diesmal ohne das gemerkte Zertifikat → Signatur prüfen
        return _issued_by(anchor, _load(pin["der"]))
    except Exception:  # noqa: BLE001
        return False


def _names_of(pin: dict) -> set[str]:
    return {n for n in (pin.get("names") or "").split(",") if n}


def _host_matches(host: str, names: set[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(n == h or (n.startswith("*.") and h.endswith(n[1:]) and h.count(".") == n.count(".")) for n in names)


def check(host: str, chain: list[bytes]) -> dict:
    """Prüft bzw. merkt das Zertifikat. Wirft PinMismatch bei Abweichung.

    Regeln (gegen Man-in-the-Middle):
    - Das Zertifikat muss ein Serverzertifikat sein (sonst könnte jedes von der Unternehmens-CA ausgestellte
      Benutzer-/Computerzertifikat einen DC vortäuschen).
    - Bekannte Verbindung: Kette muss zum gemerkten Zertifikat führen UND das Serverzertifikat muss einen der
      beim ersten Kontakt gesehenen DNS-Namen tragen (Erneuerungen behalten den Namen).
    - Neue Adresse eines bereits gemerkten Namens: kein erneutes „erstes Vertrauen“ – nur, wenn die Kette zu
      einem gemerkten Zertifikat dieses Namens führt und das Serverzertifikat den konfigurierten Namen trägt.
    """
    if not chain:
        raise PinMismatch(host, "?", "kein Zertifikat")
    try:
        path = verified_prefix(chain)
    except Exception as e:  # noqa: BLE001 – unlesbares Zertifikat
        raise PinMismatch(host, "?", f"unlesbares Zertifikat ({e.__class__.__name__})") from e
    leaf, anchor = path[0], path[-1]
    fp = fingerprint(anchor)
    names = leaf_names(leaf)
    if not _server_cert_ok(leaf):
        db.audit("act_cert_mismatch", detail=f"{host}: kein Serverzertifikat ({leaf.subject.rfc4514_string()})")
        raise PinMismatch(host, "Serverzertifikat", "Zertifikat ohne Serverauthentifizierung")
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
        if not known:                      # Einträge aus Versionen vor 1.9.2: Namen jetzt ergänzen
            db.set_pin_names(host, ",".join(sorted(names)))
        db.touch_pin(host)
        return {"first_use": False, "fingerprint": pin["fingerprint"]}

    family = [p for p in db.family_pins(base) if p["host"] != host.lower()]
    if family:
        for p in family:
            if _anchor_matches(p, fp, path, anchor) and (_names_of(p) & names or _host_matches(base, names)):
                db.save_pin(host, p["fingerprint"], p["subject"], p["not_after"], bool(p["is_ca"]), p["der"],
                            ",".join(sorted(names)))
                db.touch_pin(host)
                return {"first_use": False, "fingerprint": p["fingerprint"]}
        db.audit("act_cert_mismatch", detail=f"{host}: neue Adresse mit unbekanntem Zertifikat "
                                             f"({', '.join(sorted(names))[:120]}, SHA256 {fp[:23]}…)")
        raise PinMismatch(host, family[0]["fingerprint"], fp)

    from cryptography.hazmat.primitives.serialization import Encoding
    subject, not_after, is_ca = _describe(anchor)
    db.save_pin(host, fp, subject, not_after, is_ca, anchor.public_bytes(Encoding.DER), ",".join(sorted(names)))
    db.audit("act_cert_pinned", detail=f"{host}: {subject} SHA256 {fp[:23]}…")
    log.warning("LDAPS: Zertifikat von %s automatisch vertraut und gemerkt (%s, SHA256 %s)", host, subject, fp)
    return {"first_use": True, "fingerprint": fp, "subject": subject}


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
