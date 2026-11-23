# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""2.7.0: Kerberos and encrypted LDAP on port 389 ("sign and seal"), Kerberos for SMB, the build of gssapi/krb5.

With SAMAUDIT_TEST_KDC=1 (a local MIT KDC for FIRMA.LOCAL with the user anna / SAMAUDIT_TEST_PASSWORD, the DC name
dc01.firma.local and the keytab in SAMAUDIT_TEST_KEYTAB) also against a real KDC – CI has none, so that test is
skipped there."""
from __future__ import annotations

import importlib.util
import os
import socket
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="samaudit-krb-"))

from app import db, kerberos, ldapseal, ldapsrc, sysvol  # noqa: E402

HAS_SPNEGO = importlib.util.find_spec("spnego") is not None
HAS_LDAP3 = importlib.util.find_spec("ldap3") is not None


class FakeCtx:
    """Stand-in for a pyspnego context: 'encrypts' by reversing and prefixing a marker."""

    def __init__(self, rounds=2, confidential=True):
        self.complete = False
        self.rounds = rounds
        self.steps: list = []
        self.confidential = confidential

    def step(self, token=None):
        self.steps.append(token)
        if len(self.steps) >= self.rounds:
            self.complete = True
        return b"token-%d" % len(self.steps)

    @property
    def context_attr(self):
        import spnego
        return spnego.ContextReq.confidentiality if self.confidential else spnego.ContextReq.integrity

    def wrap(self, data, encrypt=True):
        return mock.Mock(data=b"SEAL" + bytes(reversed(data)))

    def unwrap(self, data):
        if not data.startswith(b"SEAL"):
            raise ValueError("bad signature")
        return mock.Mock(data=bytes(reversed(data[4:])))


class RawSocket:
    def __init__(self, incoming=b"", chunk=3):
        self.incoming, self.chunk, self.sent = incoming, chunk, b""

    def recv(self, n):
        out, self.incoming = self.incoming[: min(n, self.chunk)], self.incoming[min(n, self.chunk):]
        return out

    def sendall(self, data):
        self.sent += data


def frame(ctx, plain):
    wrapped = ctx.wrap(plain).data
    return struct.pack(">I", len(wrapped)) + wrapped


class SealedSocketTests(unittest.TestCase):
    def test_messages_are_sent_encrypted_with_length(self):
        raw, ctx = RawSocket(), FakeCtx()
        ldapseal.SealedSocket(raw, ctx).sendall(b"\x30\x05hello")
        self.assertEqual(raw.sent, frame(ctx, b"\x30\x05hello"))
        self.assertNotIn(b"hello", raw.sent)

    def test_frames_split_over_tcp_packets_are_joined(self):
        ctx = FakeCtx()
        raw = RawSocket(frame(ctx, b"first-message") + frame(ctx, b"second"), chunk=3)
        sock = ldapseal.SealedSocket(raw, ctx)
        got = b""
        while len(got) < len(b"first-messagesecond"):
            got += sock.recv(4)
        self.assertEqual(got, b"first-messagesecond")

    def test_a_message_that_cannot_be_decrypted_is_never_passed_on(self):
        raw = RawSocket(struct.pack(">I", 6) + b"PLAIN!")
        with self.assertRaises(OSError):
            ldapseal.SealedSocket(raw, FakeCtx()).recv(100)

    def test_absurd_length_is_refused(self):
        with self.assertRaises(OSError):
            ldapseal.SealedSocket(RawSocket(struct.pack(">I", ldapseal.MAX_FRAME + 1)), FakeCtx()).recv(100)
        with self.assertRaises(OSError):
            ldapseal.SealedSocket(RawSocket(struct.pack(">I", 0)), FakeCtx()).recv(100)

    def test_closed_connection(self):
        with self.assertRaises(OSError):
            ldapseal.SealedSocket(RawSocket(b"\x00\x00"), FakeCtx()).recv(10)

    def test_other_socket_functions_reach_the_real_socket(self):
        a, b = socket.socketpair()
        try:
            self.assertEqual(ldapseal.SealedSocket(a, FakeCtx()).fileno(), a.fileno())
        finally:
            a.close()
            b.close()


@unittest.skipUnless(HAS_SPNEGO, "pyspnego not installed")
class BindRounds(unittest.TestCase):
    def _rounds(self, results, ctx=None):
        ctx = ctx or FakeCtx(rounds=1)      # the first step happened in _start
        conn = types.SimpleNamespace(socket=RawSocket(), bound=False)
        sent = []

        def negotiate(c, payload):
            sent.append(payload)
            return results.pop(0)
        with mock.patch.object(ldapseal, "_negotiate", side_effect=negotiate):
            ldapseal._bind_rounds(conn, ctx, b"token-0")
        return conn, sent

    def test_two_rounds_then_everything_is_sealed(self):
        conn, sent = self._rounds([{"result": 14, "saslCreds": b"challenge"}, {"result": 0, "saslCreds": b""}])
        self.assertEqual(sent, [b"token-0", b"token-1"])
        self.assertIsInstance(conn.socket, ldapseal.SealedSocket)
        self.assertTrue(conn.bound)
        self.assertFalse(conn.sasl_in_progress)

    def test_wrong_password_and_locked_account_are_auth_errors(self):
        with self.assertRaises(ldapsrc.AuthError) as cm:
            self._rounds([{"result": 49, "description": "invalidCredentials",
                           "message": "80090308: LdapErr: DSID-0C09, comment: AcceptSecurityContext error, data 52e"}])
        self.assertEqual(cm.exception.code, "bad_credentials")
        with self.assertRaises(ldapsrc.AuthError) as cm:
            self._rounds([{"result": 49, "description": "invalidCredentials", "message": "data 775, v4563"}])
        self.assertEqual(cm.exception.code, "account_locked")

    def test_refused_mechanism_is_a_connection_problem(self):
        with self.assertRaises(ldapseal.SealError):
            self._rounds([{"result": 7, "description": "authMethodNotSupported"}])

    def test_never_continues_without_encryption(self):
        with self.assertRaises(ldapseal.SealError):
            self._rounds([{"result": 14, "saslCreds": b"c"}, {"result": 0, "saslCreds": b""}],
                         FakeCtx(rounds=1, confidential=False))

    def test_server_must_prove_its_identity(self):
        # the DC says "done" but the context (Kerberos: mutual authentication) is not complete
        with self.assertRaises(ldapseal.SealError):
            self._rounds([{"result": 0, "saslCreds": b""}], FakeCtx(rounds=5))


class KrbError(Exception):
    def __init__(self, code):
        super().__init__(f"error {code}")
        self.err_code = code


@unittest.skipUnless(HAS_SPNEGO, "pyspnego not installed")
class Order(unittest.TestCase):
    """Kerberos first; NTLM only if allowed, never after a refused password and never once Kerberos worked."""

    KRB = {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"}

    def setUp(self):
        ldapseal.reset_state()

    def _start(self, ticket_effect, ntlm_user="FIRMA\\anna", kerberos=None):
        made = []

        def ctx(user, pw, host, protocol):
            made.append((protocol, host, pw))
            return FakeCtx()
        with mock.patch.object(kerberos_mod, "new_ticket", side_effect=ticket_effect), \
             mock.patch.object(kerberos_mod, "destroy_ticket") as destroy, \
             mock.patch.object(ldapseal, "_client_context", side_effect=ctx):
            try:
                out = ldapseal._start("pw", "dc01.firma.local", kerberos or self.KRB, ntlm_user)
            except Exception as e:  # noqa: BLE001
                out = e
        return out, made, destroy

    def test_kerberos_first(self):
        ticket = kerberos.Ticket(None, None, "MEMORY:x", "anna@FIRMA.LOCAL")
        out, made, _ = self._start([ticket])
        self.assertEqual(out[2], "kerberos")
        self.assertEqual(made, [("kerberos", "dc01.firma.local", None)], "no password in the Kerberos context")
        self.assertTrue(ldapseal.kerberos_seen("dc01.firma.local"))

    def test_wrong_password_is_never_tried_with_ntlm_too(self):
        out, made, _ = self._start(KrbError(kerberos._BASE + 24))
        self.assertIsInstance(out, ldapsrc.AuthError)
        self.assertEqual(out.code, "bad_credentials")
        self.assertEqual(made, [])
        out, made, _ = self._start(KrbError(kerberos._BASE + 18))
        self.assertEqual(out.code, "account_locked")

    def test_ntlm_when_kerberos_is_not_possible_and_ntlm_is_allowed(self):
        out, made, _ = self._start(KrbError(kerberos._BASE + 37))
        self.assertEqual(out[2], "ntlm")
        self.assertEqual(out[4], "skew")
        self.assertEqual(made, [("ntlm", "dc01.firma.local", "pw")])

    def test_no_ntlm_without_permission(self):
        out, made, _ = self._start(KrbError(-1765328228), ntlm_user=None)
        self.assertIsInstance(out, ldapseal.SealError)
        self.assertEqual(out.reason, "kdc_unreachable")
        self.assertEqual(made, [])
        out, made, _ = self._start([], ntlm_user=None, kerberos={"skip": "ip"})
        self.assertIsInstance(out, ldapseal.SealError)
        self.assertEqual(out.reason, "ip")

    def test_never_ntlm_once_kerberos_worked_with_this_dc(self):
        ticket = kerberos.Ticket(None, None, "MEMORY:x", "anna@FIRMA.LOCAL")
        self._start([ticket])
        out, made, _ = self._start(KrbError(-1765328228))         # port 88 blocked now
        self.assertIsInstance(out, ldapseal.SealError)
        self.assertEqual(made, [])

    def test_backoff_only_while_ntlm_is_allowed(self):
        self._start(KrbError(-1765328228))
        out, made, _ = self._start(AssertionError("must not be called"))
        self.assertEqual(out[2], "ntlm")
        self.assertEqual(out[4], "backoff")
        out, made, _ = self._start(KrbError(-1765328228), ntlm_user=None)   # without NTLM: always try again
        self.assertIsInstance(out, ldapseal.SealError)

    def test_ticket_is_destroyed_after_the_bind_unless_kept(self):
        ticket = kerberos.Ticket(None, None, "MEMORY:x", "anna@FIRMA.LOCAL")
        conn = types.SimpleNamespace(socket=RawSocket(), bound=False)
        for keep in (False, True):
            ldapseal.reset_state()
            with mock.patch.object(kerberos_mod, "new_ticket", return_value=ticket), \
                 mock.patch.object(kerberos_mod, "destroy_ticket") as destroy, \
                 mock.patch.object(ldapseal, "_client_context", return_value=FakeCtx(rounds=1)), \
                 mock.patch.object(ldapseal, "_negotiate", return_value={"result": 0, "saslCreds": b""}):
                kind, kept, _why = ldapseal.sealed_bind(conn, "pw", "dc01.firma.local", self.KRB, None,
                                                        keep_ticket=keep)
            self.assertEqual(kind, "kerberos")
            self.assertEqual(destroy.called, not keep)
            self.assertIs(kept, ticket if keep else None)

    def test_ticket_is_destroyed_when_the_bind_fails(self):
        ticket = kerberos.Ticket(None, None, "MEMORY:x", "anna@FIRMA.LOCAL")
        conn = types.SimpleNamespace(socket=RawSocket(), bound=False)
        with mock.patch.object(kerberos_mod, "new_ticket", return_value=ticket), \
             mock.patch.object(kerberos_mod, "destroy_ticket") as destroy, \
             mock.patch.object(ldapseal, "_client_context", return_value=FakeCtx(rounds=1)), \
             mock.patch.object(ldapseal, "_negotiate", return_value={"result": 7, "description": "x"}):
            with self.assertRaises(ldapseal.SealError):
                ldapseal.sealed_bind(conn, "pw", "dc01.firma.local", self.KRB, None, keep_ticket=True)
        destroy.assert_called_once_with(ticket)


kerberos_mod = kerberos


class Helpers(unittest.TestCase):
    def test_principal(self):
        self.assertEqual(kerberos.principal("anna@firma.local", "firma.local"), "anna@FIRMA.LOCAL")
        self.assertEqual(kerberos.principal("FIRMA\\anna", "firma.local"), "anna@FIRMA.LOCAL")
        self.assertEqual(kerberos.principal("anna", "firma.local"), "anna@FIRMA.LOCAL")
        self.assertIsNone(kerberos.principal("anna@other.example", "firma.local"))
        self.assertIsNone(kerberos.principal("anna", ""))

    def test_dns_names_only(self):
        self.assertTrue(kerberos.is_dns_name("dc01.firma.local"))
        for bad in ("10.0.10.5", "dc01", "", "::1", "dc01.firma.local\n[realms]", "a b.local"):
            self.assertFalse(kerberos.is_dns_name(bad), bad)

    def test_config_is_aes_only_and_never_asks_dns(self):
        text = kerberos.config_text("firma.local", ["dc01.firma.local", "dc02.firma.local"])
        self.assertIn("default_realm = FIRMA.LOCAL", text)
        self.assertIn("dns_lookup_kdc = false", text)
        self.assertIn("rdns = false", text)
        self.assertIn("kdc = dc01.firma.local", text)
        self.assertIn("kdc = dc02.firma.local", text)
        self.assertIn("forwardable = false", text)
        self.assertNotIn("rc4", text.lower())
        self.assertNotIn("des", text.lower().replace("default", ""))

    def test_config_refuses_injection(self):
        for dom, kdcs in (("firma.local\n[realms]", ["dc"]), ("firma.local", ["dc }\n kdc = evil"]),
                          ("firma.local", [])):
            with self.assertRaises(ValueError):
                kerberos.config_text(dom, kdcs)

    def test_error_codes(self):
        self.assertEqual(kerberos.credential_error(KrbError(kerberos._BASE + 24)), "bad_credentials")
        self.assertEqual(kerberos.credential_error(KrbError(kerberos._BASE + 31)), "bad_credentials")
        self.assertEqual(kerberos.credential_error(KrbError(kerberos._BASE + 23)), "account_unusable")
        self.assertEqual(kerberos.credential_error(Exception("Clock skew too great -1765328347")), "")
        self.assertEqual(kerberos.reason(Exception("Clock skew too great -1765328347")), "skew")
        wrapped = RuntimeError("SpnegoError")
        wrapped.__cause__ = KrbError(kerberos._BASE + 24)
        self.assertEqual(kerberos.credential_error(wrapped), "bad_credentials")
        self.assertEqual(kerberos.reason(Exception("?")), "other")

    def test_target_comes_from_the_configuration(self):
        s, ks = ldapsrc.settings, kerberos.settings
        with mock.patch.object(s, "ldap_kerberos", True), mock.patch.object(s, "domain_fqdn", "firma.local"), \
             mock.patch.object(ks, "dc_hosts", ["dc01.firma.local", "10.0.10.6"]), \
             mock.patch.object(kerberos, "libraries", return_value=True), \
             mock.patch.object(kerberos, "ensure_config") as ensure:
            self.assertEqual(ldapsrc.kerberos_target("DC01.firma.local", "anna@firma.local"),
                             {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"})
            ensure.assert_called_with("firma.local", ["dc01.firma.local"])
            self.assertEqual(ldapsrc.kerberos_target("10.0.10.6", "anna@firma.local"), {"skip": "ip"})
            self.assertEqual(ldapsrc.kerberos_target("dc01.firma.local", "anna@other.example"), {"skip": "upn"})
        with mock.patch.object(s, "ldap_kerberos", False):
            self.assertIsNone(ldapsrc.kerberos_target("dc01.firma.local", "anna@firma.local"))

    def test_krb5_conf_is_written_by_the_program(self):
        path = kerberos.ensure_config("firma.local", ["dc01.firma.local"])
        try:
            self.assertEqual(os.environ["KRB5_CONFIG"], path)
            self.assertIn("kdc = dc01.firma.local", Path(path).read_text(encoding="utf-8"))
            self.assertEqual(kerberos.ensure_config("firma.local", ["dc01.firma.local"]), path)
        finally:
            kerberos.remove_config()
            kerberos._written.update(key=None, path="")

    def test_egress_and_diagnostics(self):
        from app import diag, egress
        self.assertIn(88, egress.ALLOWED_PORTS)
        self.assertEqual(diag.SETTINGS_POLICY["ldap_kerberos"], "value")
        self.assertEqual(diag.KV_POLICY["kerberos_reason"], "value")

    def test_texts_exist(self):
        from app.i18n import T
        for k in kerberos.REASON_KEYS:
            self.assertIn(f"kerberos_reason_{k}", T)
        for k in ("err_kerberos_failed", "ldap_mode_kerberos", "smb_auth_kerberos", "kerberos_reason_title"):
            self.assertIn(k, T)


@unittest.skipUnless(HAS_LDAP3, "ldap3 not installed")
class ErrorsDoNotHideEachOther(unittest.TestCase):
    def setUp(self):
        db.init()
        db.delete_pins()

    def _open(self, fails):
        def fake_connect(bind, pw, addr, key, mode, **kw):
            raise fails[mode]
        s = ldapsrc.settings
        with mock.patch.object(ldapsrc, "_targets", lambda: [("10.0.10.5", "10.0.10.5", "10.0.10.5")]), \
             mock.patch.object(ldapsrc, "_connect", fake_connect), mock.patch.object(s, "ldap_kerberos", True), \
             mock.patch.object(s, "ldap_ntlm", False), mock.patch.object(s, "ldap_ssl", True), \
             mock.patch.object(s, "ldap_port", 636):
            with self.assertRaises(ldapsrc.AuthError) as cm:
                ldapsrc.open_connection("anna@firma.local", "pw")
        return cm.exception

    def test_dc_down_stays_dc_down(self):
        down = ldapsrc.AuthError("dc_unreachable", "10.0.10.5: timeout")
        err = self._open({"": down, "starttls": down, "sasl": ldapseal.SealError("x", "ip")})
        self.assertEqual(err.code, "dc_unreachable")
        err = self._open({"": down, "starttls": down, "sasl": ldapseal.SealError("x", "kdc_unreachable")})
        self.assertEqual(err.code, "dc_unreachable")

    def test_no_certificate_and_kerberos_failed(self):
        no_tls = ldapsrc.AuthError("tls_failed", "no certificate")
        err = self._open({"": no_tls, "starttls": no_tls, "sasl": ldapseal.SealError("x", "skew")})
        self.assertEqual(err.code, "kerberos_failed")
        self.assertEqual(db.get_kv("kerberos_reason"), "skew")


def _smb_standin(seen: list, fail_kerberos: bool = False):
    fake = types.ModuleType("smbclient")

    def register_session(server, **kw):
        seen.append((server, kw))
        if fail_kerberos and kw.get("auth_protocol") == "kerberos":
            raise RuntimeError("Server not found in Kerberos database")
    fake.register_session = register_session
    fake.scandir = lambda p: iter(())
    fake.delete_session = lambda s: None
    fake.reset_connection_cache = lambda **kw: None
    fake.walk = lambda p: iter(())
    fake_path = types.ModuleType("smbclient.path")
    fake_path.isdir = lambda p: False
    fake_path.isfile = lambda p: False
    fake.path = fake_path
    return {"smbclient": fake, "smbclient.path": fake_path}


@unittest.skipUnless(HAS_SPNEGO, "pyspnego not installed")
class SmbWithKerberos(unittest.TestCase):
    KRB = {"ccache": "MEMORY:abc", "host": "DC01.firma.local"}

    def setUp(self):
        sysvol._smb_kerberos_seen.clear()

    def _scan(self, fail=False, krb=KRB):
        seen: list = []
        with mock.patch.dict(sys.modules, _smb_standin(seen, fail)), mock.patch.object(sysvol.settings, "smb_checks", True):
            res = sysvol.scan("10.0.10.5", "firma.local", "anna@firma.local", "pw", [], {}, kerberos=krb)
        return res, seen

    def test_kerberos_with_the_scan_ticket_and_the_dc_name(self):
        import spnego
        res, seen = self._scan()
        self.assertEqual(res["auth"], "kerberos")
        server, kw = seen[0]
        self.assertEqual(server, "dc01.firma.local")
        self.assertEqual(kw["auth_protocol"], "kerberos")
        self.assertIsInstance(kw["username"], spnego.KerberosCCache)
        self.assertIsNone(kw["password"], "no password for Kerberos – the ticket is used")
        self.assertTrue(kw["require_signing"])

    def test_ntlm_to_the_checked_address_if_kerberos_fails(self):
        res, seen = self._scan(fail=True)
        self.assertEqual(res["auth"], "ntlm")
        self.assertEqual(res["kerberos_error"], "spn")
        self.assertEqual(seen[-1][0], "10.0.10.5")
        self.assertEqual(seen[-1][1]["auth_protocol"], "ntlm")

    def test_never_ntlm_once_smb_kerberos_worked(self):
        self._scan()
        res, seen = self._scan(fail=True)
        self.assertEqual(res["status"], "error")
        self.assertEqual(len(seen), 1, "no NTLM attempt")

    def test_without_ticket_ntlm(self):
        res, seen = self._scan(krb=None)
        self.assertEqual(res["auth"], "ntlm")
        self.assertEqual(seen[0][1]["auth_protocol"], "ntlm")


def _get(path: str, query: str = "") -> tuple[int, str]:
    import asyncio

    from app.main import app
    out: dict = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")
    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": query.encode(),
             "headers": [(b"host", b"samaudit.firma.local")], "client": ("203.0.113.7", 50000),
             "server": ("127.0.0.1", 9400), "scheme": "http", "http_version": "1.1", "root_path": ""}
    asyncio.run(app(scope, receive, send))
    return out["status"], out["body"].decode("utf-8", "replace")


class LoginPageNamesTheReason(unittest.TestCase):
    def test_reason_only_with_the_kerberos_error(self):
        db.init()
        db.set_kv("kerberos_reason", "skew")
        with mock.patch.object(sys.modules["app.config"].settings, "tls_enabled", False):
            status, body = _get("/login", "e=kerberos_failed")
            self.assertEqual(status, 200)
            self.assertIn("NTP", body)
            _status, body = _get("/login", "e=bad_credentials")
            self.assertNotIn("NTP", body)


class SmbTicketWithoutLdapKerberos(unittest.TestCase):
    """LDAP went over LDAPS: a ticket for SMB is fetched with the password the DC has just accepted."""

    def setUp(self):
        ldapseal.reset_state()

    def test_ticket_only_when_kerberos_is_possible_and_did_not_just_fail(self):
        tgt = {"principal": "anna@FIRMA.LOCAL", "target": "dc01.firma.local"}
        with mock.patch.object(sysvol.settings, "smb_checks", True), \
             mock.patch.object(ldapsrc, "kerberos_target", return_value=tgt), \
             mock.patch.object(kerberos, "new_ticket", return_value="T") as nt:
            self.assertEqual(sysvol.kerberos_ticket("dc01.firma.local", "anna@firma.local", "pw"), "T")
            nt.assert_called_once_with("anna@FIRMA.LOCAL", "pw")
            ldapseal._kerberos_missing["dc01.firma.local"] = 1e18
            self.assertIsNone(sysvol.kerberos_ticket("dc01.firma.local", "anna@firma.local", "pw"))
        with mock.patch.object(sysvol.settings, "smb_checks", True), \
             mock.patch.object(ldapsrc, "kerberos_target", return_value={"skip": "ip"}):
            self.assertIsNone(sysvol.kerberos_ticket("10.0.10.5", "anna@firma.local", "pw"))
        with mock.patch.object(sysvol.settings, "smb_checks", False):
            self.assertIsNone(sysvol.kerberos_ticket("dc01.firma.local", "anna@firma.local", "pw"))


class ScannerReleasesTheTicket(unittest.TestCase):
    def test_ticket_destroyed_even_if_the_scan_fails(self):
        from app import scanner
        db.init()
        ticket = kerberos.Ticket(None, None, "MEMORY:x", "anna@FIRMA.LOCAL")
        conn = types.SimpleNamespace(_samaudit_ticket=ticket, unbind=lambda: None)
        assert scanner._scan_lock.acquire(blocking=False)
        scan_id = db.create_scan("firma.local", "windows", "anna", False)
        with mock.patch.object(scanner.settings, "demo_mode", False), \
             mock.patch.object(ldapsrc, "authenticate", return_value=None), \
             mock.patch.object(ldapsrc, "open_connection", return_value=conn) as oc, \
             mock.patch.object(ldapsrc, "collect", side_effect=RuntimeError("DC gone")), \
             mock.patch.object(kerberos, "destroy_ticket") as destroy:
            scanner._run(scan_id, "anna@firma.local", "pw")
        self.assertTrue(oc.call_args.kwargs.get("keep_ticket"))
        destroy.assert_called_once_with(ticket)


class Build(unittest.TestCase):
    def test_kerberos_stage_and_wheels_only_otherwise(self):
        df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        stage, final = df.split("AS kerberos", 1)[1].split("\nFROM ${PYTHON_IMAGE}\n", 1)
        self.assertIn("libkrb5-dev", stage)
        self.assertIn("--require-hashes", stage)
        self.assertIn("--no-binary=gssapi,krb5", stage)
        self.assertNotIn("libkrb5-dev", final, "no compiler or headers in the image")
        self.assertNotIn("gcc", final)
        self.assertIn("--only-binary=:all:", final)
        self.assertIn("without requirements.txt gssapi krb5", final)
        self.assertIn("libgssapi-krb5-2", final)
        self.assertIn('import gssapi, krb5', final)

    def test_lock_has_hashes_for_the_sources_and_build_tools(self):
        import lockutil
        req = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        sel = lockutil.blocks(req, ["gssapi", "krb5"], keep=True)
        self.assertEqual(set(lockutil.parse_lock(sel)), {"gssapi", "krb5"})
        self.assertIn("--hash=sha256:", sel)
        rest = lockutil.blocks(req, ["gssapi", "krb5"], keep=False)
        self.assertEqual(set(lockutil.parse_lock(rest)), set(lockutil.parse_lock(req)) - {"gssapi", "krb5"})
        self.assertTrue(rest.startswith("# SAMAUDIT"))
        build = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
        self.assertEqual(set(lockutil.parse_lock(build)), {"cython", "setuptools"})
        self.assertGreaterEqual(build.count("--hash=sha256:"), 2)
        self.assertEqual(set(lockutil.SOURCE_BUILT), {"gssapi", "krb5"})


@unittest.skipUnless(os.environ.get("SAMAUDIT_TEST_KDC") == "1", "no test KDC (SAMAUDIT_TEST_KDC=1)")
class RealKdc(unittest.TestCase):
    def test_ticket_seal_and_cifs(self):
        import spnego
        kerberos.ensure_config("firma.local", ["dc01.firma.local"])
        with self.assertRaises(Exception) as cm:
            kerberos.new_ticket("anna@FIRMA.LOCAL", "wrong-password")
        self.assertEqual(kerberos.credential_error(cm.exception), "bad_credentials")
        ticket = kerberos.new_ticket("anna@FIRMA.LOCAL", os.environ["SAMAUDIT_TEST_PASSWORD"])
        try:
            os.environ["KRB5_KTNAME"] = os.environ["SAMAUDIT_TEST_KEYTAB"]
            srv = spnego.server(service="ldap", hostname="dc01.firma.local", protocol="negotiate")
            cli = ldapseal._client_context(spnego.KerberosCCache(ccache=ticket.name), None, "dc01.firma.local",
                                           "kerberos")
            out = srv.step(cli.step())
            if out:
                cli.step(out)
            self.assertTrue(cli.complete)
            self.assertIn(spnego.ContextReq.confidentiality, cli.context_attr)
            a, b = socket.socketpair()
            ldapseal.SealedSocket(a, cli).sendall(b"\x30\x05hello")
            n = struct.unpack(">I", b.recv(4))[0]
            data = b.recv(n)
            self.assertNotIn(b"hello", data)
            self.assertEqual(srv.unwrap(data).data, b"\x30\x05hello")
            cifs = spnego.client(spnego.KerberosCCache(ccache=ticket.name), None, service="cifs",
                                 hostname="dc01.firma.local", protocol="kerberos")
            self.assertTrue(cifs.step())
        finally:
            kerberos.destroy_ticket(ticket)


if __name__ == "__main__":
    unittest.main()
