# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""HTTPS-Zertifikat der Weboberfläche – eigenes Zertifikat ohne Reverse Proxy.

Reihenfolge:
1. Über die Weboberfläche hochgeladen (Seite „Verbindung“) – gespeichert in data/tls/custom.
2. Im Ordner certs abgelegt (oder per TLS_PFX / TLS_CERT / TLS_KEY ausgewählt).
3. Sonst: selbstsigniertes Zertifikat in data/tls (wird einmalig erzeugt).

Erkannt werden PFX/PKCS#12 (z. B. Export aus der Windows-CA) sowie Zertifikat + privater Schlüssel
als PEM oder DER, auch mit verschlüsseltem Schlüssel. Zwischenzertifikate werden automatisch als Kette
angehängt. Ein neues Zertifikat wird ohne Neustart aktiv (gilt für neue Verbindungen)."""
from __future__ import annotations

import datetime as dt
import glob
import ipaddress
import json
import logging
import os
import shutil
import socket
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import settings

log = logging.getLogger("samaudit.tls")

PFX_EXT = (".pfx", ".p12")
MAX_FILE = 64 * 1024
MAX_FILES = 10

LOG_TEXT = {
    "cert_expired": "abgelaufen",
    "cert_expiring": "läuft in weniger als 30 Tagen ab",
    "cert_host_mismatch": "PUBLIC_HOSTNAME steht nicht im Zertifikat (Browserwarnung möglich)",
}

# Wird von prepare() gesetzt und unter „Verbindung“ angezeigt
INFO: dict = {}
# Austausch ohne Neustart: der Webserver-Kontext (run.py) leitet jeden Verbindungsaufbau per
# SNI-Rückruf auf den jeweils aktuellen Kontext um (_current), sobald ein neues Zertifikat aktiv ist.
_current: ssl.SSLContext | None = None
_tmpdir: str | None = None
_lock = threading.Lock()


# Nur Verfahren mit Vorwärtsgeheimnis und AEAD (gilt für TLS 1.2; TLS 1.3 ist ohnehin sicher)
CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!MD5:!DSS:!SHA1"


def _harden(ctx: ssl.SSLContext) -> None:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE


def new_context(cert_p: str, key_p: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _harden(ctx)
    ctx.load_cert_chain(cert_p, key_p)
    return ctx


def attach(base: ssl.SSLContext) -> None:
    """Vom Start aufgerufen: Webserver-Kontext härten und für spätere Zertifikatswechsel vorbereiten."""
    _harden(base)

    def _sni(sslobj, _server_name, _ctx):
        cur = _current
        if cur is not None:
            sslobj.context = cur
        return None

    base.sni_callback = _sni


class CertError(Exception):
    pass


def _custom_dir() -> str:
    return os.path.join(settings.data_dir, "tls", "custom")


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _pem_certs(data: bytes) -> list[x509.Certificate]:
    try:
        return x509.load_pem_x509_certificates(data) if b"-----BEGIN CERTIFICATE-----" in data else []
    except ValueError:
        return []


def _pem_key(data: bytes, password: str | None, name: str):
    start = data.find(b"-----BEGIN ")
    while start != -1:
        line_end = data.find(b"-----", start + 11)
        label = data[start + 11:line_end]
        if label.endswith(b"PRIVATE KEY"):
            end_marker = b"-----END " + label + b"-----"
            end = data.find(end_marker, line_end)
            block = data[start:end + len(end_marker)]
            try:
                return serialization.load_pem_private_key(block, password.encode() if password else None)
            except TypeError as e:
                if password:
                    raise CertError(f"{name}: Der Schlüssel ist nicht verschlüsselt – Passwort weglassen.") from e
                raise CertError(f"{name}: Der private Schlüssel ist verschlüsselt – bitte Passwort angeben.") from e
            except ValueError as e:
                raise CertError(f"{name}: Passwort für den privaten Schlüssel ist falsch.") from e
        start = data.find(b"-----BEGIN ", line_end + 5)
    return None


def _pub(obj) -> bytes:
    return obj.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else name.rfc4514_string()


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(v) for v in ext.get_values_for_type(x509.DNSName)] + \
           [str(v) for v in ext.get_values_for_type(x509.IPAddress)]


def _not_after(cert: x509.Certificate) -> dt.datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # ältere cryptography-Versionen
        return cert.not_valid_after.replace(tzinfo=dt.timezone.utc)


def _build_chain(leaf: x509.Certificate, pool: list[x509.Certificate]) -> list[x509.Certificate]:
    """Hängt passende Zwischenzertifikate an (Aussteller-Name + Signatur), ohne Wurzel-CA."""
    chain, cur = [leaf], leaf
    for _ in range(8):
        if cur.issuer == cur.subject:
            break
        nxt = None
        for c in pool:
            if c.subject == cur.issuer and c not in chain:
                try:
                    cur.verify_directly_issued_by(c)
                except Exception:  # noqa: BLE001
                    continue
                nxt = c
                break
        if nxt is None or nxt.issuer == nxt.subject:  # Wurzel nicht mitsenden
            break
        chain.append(nxt)
        cur = nxt
    return chain


def _host_matches(host: str, sans: list[str]) -> bool:
    host = host.lower()
    for s in sans:
        s = s.lower()
        if s == host or (s.startswith("*.") and host.count(".") == s.count(".") and host.endswith(s[1:])):
            return True
    return False


# ---------------------------------------------------------------------------
# Dateien auswerten (Inhalt entscheidet, nicht die Dateiendung)
# ---------------------------------------------------------------------------

def analyze(files: list[tuple[str, bytes]], password: str | None, ca_only_ok: bool = False):
    """Sucht in den Dateien ein Server-Zertifikat mit passendem privatem Schlüssel.

    Liefert (Zertifikat, Schlüssel, alle Zertifikate, Quelle) oder None, wenn gar nichts Verwertbares
    dabei ist. Wirft CertError mit verständlicher Meldung bei Problemen."""
    certs: list[tuple[x509.Certificate, str]] = []
    keys: list[tuple[object, str]] = []
    for name, data in files:
        if len(data) > MAX_FILE:
            raise CertError(f"{name}: Datei ist zu groß für ein Zertifikat.")
        if b"-----BEGIN " in data:
            certs += [(c, name) for c in _pem_certs(data)]
            k = _pem_key(data, password, name)
            if k is not None:
                keys.append((k, name))
            continue
        # Binär: DER-Zertifikat, DER-Schlüssel oder PFX
        try:
            certs.append((x509.load_der_x509_certificate(data), name))
            continue
        except ValueError:
            pass
        try:
            keys.append((serialization.load_der_private_key(data, password.encode() if password else None), name))
            continue
        except (ValueError, TypeError):
            pass
        try:
            k, c, extra = pkcs12.load_key_and_certificates(data, password.encode() if password else None)
        except ValueError as e:
            if name.lower().endswith(PFX_EXT):
                raise CertError(f"{name}: Passwort falsch oder Datei beschädigt.") from e
            raise CertError(f"{name}: Format nicht erkannt (erwartet PFX, PEM oder DER).") from e
        if c is not None:
            certs.append((c, name))
        certs += [(x, name) for x in (extra or [])]
        if k is not None:
            keys.append((k, name))

    pool = [c for c, _ in certs]
    leaves = [(c, n) for c, n in certs if not _is_ca(c)]
    for leaf, cname in leaves:
        for k, kname in keys:
            if _pub(leaf) == _pub(k):
                return leaf, k, pool, cname if cname == kname else f"{cname} + {kname}"
    if leaves and keys:
        raise CertError("Zertifikat und privater Schlüssel passen nicht zusammen.")
    if leaves and not keys:
        raise CertError("Zertifikat gefunden, aber kein privater Schlüssel – Schlüsseldatei (.key) mit angeben "
                        "oder eine PFX-Datei verwenden.")
    if keys and not leaves:
        raise CertError("Privater Schlüssel gefunden, aber kein Server-Zertifikat.")
    if certs and not ca_only_ok:
        raise CertError("Nur CA-Zertifikate gefunden – es fehlt das Zertifikat für den Server selbst.")
    return None


def _from_certs_folder():
    """Zertifikat aus dem Ordner certs (oder TLS_PFX / TLS_CERT / TLS_KEY)."""
    d = settings.certs_dir
    if not os.path.isdir(d):
        return None
    chosen = [os.environ.get(v, "").strip() for v in ("TLS_PFX", "TLS_CERT", "TLS_KEY")]
    chosen = [os.path.basename(c) for c in chosen if c]
    names = sorted(os.path.basename(f) for f in glob.glob(os.path.join(d, "*"))
                   if os.path.isfile(f) and not os.path.basename(f).upper().startswith("README"))
    if chosen:
        missing = [c for c in chosen if c not in names]
        if missing:
            raise CertError(f"Ordner certs: {', '.join(missing)} nicht gefunden.")
        # gewählte Dateien + alle übrigen Zertifikate (für die Kette), aber keine weiteren Schlüssel/PFX
        others = [n for n in names if n not in chosen and not n.lower().endswith(PFX_EXT + (".key",))]
        names = chosen + others
    elif len([n for n in names if n.lower().endswith(PFX_EXT)]) > 1:
        raise CertError("Mehrere PFX-Dateien im Ordner certs – mit TLS_PFX die richtige angeben.")
    if not names:
        return None
    password = os.environ.get("TLS_PFX_PASSWORD") or os.environ.get("TLS_KEY_PASSWORD") or None
    try:
        # ca_only_ok: eine CA-Datei für LDAP_CERT_MODE=verify allein ist kein Fehler
        res = analyze([(n, _read(os.path.join(d, n))) for n in names], password, ca_only_ok=True)
    except CertError as e:
        raise CertError(f"Ordner certs: {e}") from e
    if res:
        leaf, key, pool, src = res
        return leaf, key, pool, f"certs/{src}"
    return None


def _from_upload():
    d = _custom_dir()
    cert_p, key_p = os.path.join(d, "fullchain.pem"), os.path.join(d, "key.pem")
    if not (os.path.exists(cert_p) and os.path.exists(key_p)):
        return None
    res = analyze([("fullchain.pem", _read(cert_p)), ("key.pem", _read(key_p))], None)
    if not res:
        return None
    meta = {}
    try:
        meta = json.loads(_read(os.path.join(d, "meta.json")))
    except (OSError, ValueError):
        pass
    leaf, key, pool, _ = res
    return leaf, key, pool, meta.get("files") or "Upload", meta


# ---------------------------------------------------------------------------
# Selbstsigniert
# ---------------------------------------------------------------------------

def _self_signed() -> tuple[str, str]:
    d = os.path.join(settings.data_dir, "tls")
    cert_p, key_p = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    if os.path.exists(cert_p) and os.path.exists(key_p):
        return cert_p, key_p
    os.makedirs(d, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    host = os.environ.get("PUBLIC_HOSTNAME") or socket.gethostname()
    names = [x509.DNSName(host), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SAMAUDIT (selbstsigniert)")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    _write_pair(cert_p, key_p, [cert], key)
    log.warning("Selbstsigniertes Zertifikat erzeugt. Eigenes Zertifikat: unter „Verbindung“ hochladen.")
    return cert_p, key_p


def _write_pair(cert_p: str, key_p: str, chain: list[x509.Certificate], key) -> None:
    fd = os.open(key_p + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(cert_p + ".new", "wb") as f:
        for c in chain:
            f.write(c.public_bytes(serialization.Encoding.PEM))
    os.replace(key_p + ".new", key_p)
    os.replace(cert_p + ".new", cert_p)


# ---------------------------------------------------------------------------
# Einstieg
# ---------------------------------------------------------------------------

def prepare() -> tuple[str, str]:
    """Ermittelt das aktive Zertifikat und liefert (Pfad Kette, Pfad Schlüssel) für den Webserver."""
    info: dict = {}
    own = None
    try:
        up = _from_upload()
        if up:
            leaf, key, pool, src, meta = up
            own = (leaf, key, pool, src)
            info.update(source="upload", uploaded_by=meta.get("user"), uploaded_at=meta.get("at"))
    except CertError as e:
        log.error("Hochgeladenes Zertifikat nicht lesbar: %s", e)
        info["error"] = str(e)
    if own is None:
        try:
            own = _from_certs_folder()
            if own:
                info["source"] = "folder"
        except CertError as e:
            log.error("Eigenes Zertifikat nicht verwendbar: %s – es wird das selbstsignierte verwendet.", e)
            info["error"] = str(e)

    if own is None:
        cert_p, key_p = _self_signed()
        cert = _pem_certs(_read(cert_p))[0]
        info.update(source="self", file="data/tls/cert.pem", chain=1)
        _publish(info, cert)
        return cert_p, key_p

    leaf, key, pool, source = own
    chain = _build_chain(leaf, pool)
    if info["source"] == "upload":
        d = _custom_dir()
        cert_p, key_p = os.path.join(d, "fullchain.pem"), os.path.join(d, "key.pem")
    else:  # Ordner certs: aufbereitete Kopie nur im Arbeitsspeicher-Dateisystem (/tmp)
        global _tmpdir
        if _tmpdir:
            shutil.rmtree(_tmpdir, ignore_errors=True)
        out = _tmpdir = tempfile.mkdtemp(prefix="samaudit-tls-")
        os.chmod(out, 0o700)
        cert_p, key_p = os.path.join(out, "fullchain.pem"), os.path.join(out, "key.pem")
        _write_pair(cert_p, key_p, chain, key)
    info.update(file=source, chain=len(chain))
    _publish(info, leaf)
    log.info("Eigenes Zertifikat aktiv: %s (gültig bis %s, Kette %d)", INFO["subject"], INFO["not_after"][:10],
             len(chain))
    for w in INFO["warnings"]:
        log.warning("Zertifikat: %s", LOG_TEXT.get(w, w))
    return cert_p, key_p


def _publish(info: dict, cert: x509.Certificate) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    na = _not_after(cert)
    sans = _sans(cert)
    own = info.get("source") in ("upload", "folder")
    warnings = []
    if na < now:
        warnings.append("cert_expired")
    elif (na - now).days < 30:
        warnings.append("cert_expiring")
    host = os.environ.get("PUBLIC_HOSTNAME", "").strip()
    if own and host and sans and not _host_matches(host, sans):
        warnings.append("cert_host_mismatch")
    info.update(subject=_cn(cert.subject), issuer=_cn(cert.issuer), sans=sans,
                not_after=na.isoformat(timespec="seconds"), days_left=(na - now).days,
                fingerprint=cert.fingerprint(hashes.SHA256()).hex(":").upper(), warnings=warnings)
    INFO.clear()
    INFO.update(info)


def _activate() -> None:
    """Lädt das aktuelle Zertifikat neu – neue Verbindungen nutzen es sofort, ohne Neustart."""
    global _current
    cert_p, key_p = prepare()
    _current = new_context(cert_p, key_p)


# ---------------------------------------------------------------------------
# Hochladen / Entfernen über die Weboberfläche
# ---------------------------------------------------------------------------

def install_upload(files: list[tuple[str, bytes]], password: str | None, user: str) -> dict:
    files = [(os.path.basename(n or "datei")[:100], b) for n, b in files if b]
    if not files:
        raise CertError("Bitte mindestens eine Datei auswählen.")
    if len(files) > MAX_FILES:
        raise CertError(f"Höchstens {MAX_FILES} Dateien auf einmal.")
    res = analyze(files, password or None)
    if not res:
        raise CertError("In den Dateien wurde kein Zertifikat gefunden.")
    leaf, key, pool, _ = res
    from cryptography.hazmat.primitives.asymmetric import dsa, rsa
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise CertError(f"RSA-Schlüssel mit {key.key_size} Bit ist zu schwach – mindestens 2048 Bit verwenden.")
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.key_size < 256:
        raise CertError("EC-Schlüssel ist zu schwach – mindestens P-256 verwenden.")
    if isinstance(key, dsa.DSAPrivateKey):
        raise CertError("DSA-Schlüssel werden nicht unterstützt.")
    if _not_after(leaf) < dt.datetime.now(dt.timezone.utc):
        raise CertError(f"Das Zertifikat ist am {_not_after(leaf):%d.%m.%Y} abgelaufen.")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
            raise CertError("Das Zertifikat ist nicht für Webserver ausgestellt (Verwendungszweck „Serverauthentifizierung“ "
                            "fehlt) – Browser würden es ablehnen. Vorlage „Webserver“ der CA verwenden.")
    except x509.ExtensionNotFound:
        pass
    chain = _build_chain(leaf, pool)
    # Probe: lässt sich die Kombination wirklich als Server-Zertifikat laden?
    tmp = tempfile.mkdtemp(prefix="samaudit-up-")
    try:
        _write_pair(os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem"), chain, key)
        ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(
            os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem"))
    except ssl.SSLError as e:
        raise CertError(f"Zertifikat lässt sich nicht verwenden: {e.reason or e}") from e
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    with _lock:
        d = _custom_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        _write_pair(os.path.join(d, "fullchain.pem"), os.path.join(d, "key.pem"), chain, key)
        meta = {"files": ", ".join(n for n, _ in files), "user": user,
                "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f)
        _activate()
    return dict(INFO)


def remove_upload() -> None:
    with _lock:
        shutil.rmtree(_custom_dir(), ignore_errors=True)
        _activate()
