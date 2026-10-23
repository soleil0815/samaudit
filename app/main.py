# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Webanwendung (Starlette)."""
from __future__ import annotations

import asyncio
import time
import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from . import auth, db, scanner
from .charts import hbars, level_class, login_dial, seal, trend
from .config import settings
from .adutil import LOCAL_TZ
from .i18n import T, level_key, t, tv
from .rules import CATEGORIES, RULE_ALIASES, RULES, SEVERITIES, canonical_id
from .version import APP_NAME, VERSION

log = logging.getLogger("samaudit")
BASE = os.path.dirname(__file__)
SID_COOKIE = "samaudit_sid"
LOGIN_COOKIE = "samaudit_lt"
LANG_COOKIE = "samaudit_lang"
RULE_BY_ID = {r.id: r for r in RULES}
RULE_BY_ID.update({old: RULE_BY_ID[new] for old, new in RULE_ALIASES.items()})

templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))
templates.env.globals.update(t=t, tv=tv, settings=settings, CATEGORIES=CATEGORIES, SEVERITIES=SEVERITIES,
                             level_class=level_class, level_key=level_key, seal=seal,
                             login_dial=login_dial, APP_NAME=APP_NAME, VERSION=VERSION)


def effective_domain_type() -> str | None:
    if settings.domain_type in ("windows", "samba"):
        return settings.domain_type
    return db.get_kv("domain_type")


def fmt_dt(v: str | None, lang: str = "de") -> str:
    if not v:
        return "–"
    try:
        d = datetime.fromisoformat(v).astimezone(LOCAL_TZ)
    except ValueError:
        return v
    return d.strftime("%d.%m.%Y %H:%M") if lang == "de" else d.strftime("%Y-%m-%d %H:%M")


templates.env.filters["dt"] = fmt_dt
templates.env.globals["domain_type"] = effective_domain_type


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------

def lang_of(request: Request) -> str:
    v = request.cookies.get(LANG_COOKIE)
    return v if v in ("de", "en") else settings.default_lang


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def safe_next(nxt: str | None) -> str:
    """Nur lokale Pfade als Weiterleitungsziel (kein //host, kein /\\host, keine Steuerzeichen)."""
    nxt = nxt or "/"
    if (not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt
            or any(ord(c) < 32 or ord(c) == 127 for c in nxt) or len(nxt) > 200):
        return "/"
    return nxt


def session_of(request: Request) -> auth.Session | None:
    return auth.get(request.cookies.get(SID_COOKIE))


async def form_of(request: Request) -> dict[str, str]:
    body = await request.body()
    if len(body) > 16_384:
        return {}
    data = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
    return {k: v[0] for k, v in data.items()}


def render(request: Request, name: str, ctx: dict, status: int = 200) -> Response:
    lang = lang_of(request)
    base = {"request": request, "lang": lang, "sess": session_of(request), "path": request.url.path}
    base.update(ctx)
    return templates.TemplateResponse(request, name, base, status_code=status)


def to_login(request: Request, reason: str | None = None) -> Response:
    url = "/login" + (f"?e={reason}" if reason else "")
    if request.headers.get("accept", "").startswith("application/json"):
        return JSONResponse({"error": "auth"}, status_code=401)
    return RedirectResponse(url, status_code=303)


def require(fn):
    async def wrapper(request: Request):
        s = session_of(request)
        if not s:
            return to_login(request, "session" if request.cookies.get(SID_COOKIE) else None)
        request.state.sess = s
        return await fn(request)
    wrapper.__name__ = fn.__name__
    return wrapper


async def multipart_of(request: Request, limit: int = 1_000_000) -> tuple[dict[str, str], list[tuple[str, bytes]]]:
    """Kleiner multipart/form-data-Leser (nur Standardbibliothek) für den Zertifikats-Upload."""
    from email import policy
    from email.parser import BytesParser
    ctype = request.headers.get("content-type", "")
    if not ctype.startswith("multipart/form-data"):
        return {}, []
    try:
        if int(request.headers.get("content-length", "0")) > limit:
            return {}, []
    except ValueError:
        return {}, []
    body = await request.body()
    if len(body) > limit:
        return {}, []
    msg = BytesParser(policy=policy.HTTP).parsebytes(b"Content-Type: " + ctype.encode("latin-1") + b"\r\n\r\n" + body)
    fields: dict[str, str] = {}
    files: list[tuple[str, bytes]] = []
    if not msg.is_multipart():
        return {}, []
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        if filename is not None:
            if payload:
                files.append((filename, payload))
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields, files


async def check_csrf(request: Request, form: dict) -> bool:
    s = request.state.sess
    return auth.check_token(s.csrf, form.get("csrf"))


# ---------------------------------------------------------------------------
# Anmeldung
# ---------------------------------------------------------------------------

async def login_page(request: Request):
    if session_of(request):
        return RedirectResponse("/", status_code=303)
    token = auth.new_login_token()
    err = request.query_params.get("e")
    resp = render(request, "login.html", {"token": token, "error": f"err_{err}" if err and f"err_{err}" in T else None,
                                          "config_problems": settings.validate()})
    resp.set_cookie(LOGIN_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict", max_age=900)
    return resp


async def login_submit(request: Request):
    form = await form_of(request)
    ip = client_ip(request)
    username = (form.get("username") or "").strip()
    password = form.get("password") or ""
    if not auth.check_token(request.cookies.get(LOGIN_COOKIE), form.get("token")):
        return RedirectResponse("/login?e=csrf", status_code=303)
    if auth.is_locked(username, ip):
        db.audit("act_login_failed", username[:80], ip, "locked")
        return RedirectResponse("/login?e=locked", status_code=303)

    if settings.demo_mode:
        if username.lower() in ("admin", "administrator") and password == "demo":
            db.audit("act_login_failed", username[:80], ip, "privileged_denied")
            return RedirectResponse("/login?e=privileged_denied", status_code=303)
        ok = username.lower() == "demo" and password == "demo"
        if not ok:
            auth.record_failure(username, ip)
            db.audit("act_login_failed", username[:80], ip, "demo")
            return RedirectResponse("/login?e=bad_credentials", status_code=303)
        sess = auth.create("demo", "Demo-Prüfer", "demo@firma.local", "demo", ["SAMAUDIT-Benutzer"], password, ip)
        db.set_kv("domain_type", "windows")
    else:
        from .ldapsrc import AuthError, authenticate
        try:
            res = await run_in_threadpool(authenticate, username, password)
        except AuthError as e:
            if e.code in ("bad_credentials", "not_allowed", "privileged_denied", "user_not_found", "account_unusable"):
                auth.record_failure(username, ip)
            log.warning("Login fehlgeschlagen für %s von %s: %s %s", username[:80], ip, e.code, e.detail)
            db.audit("act_login_failed", username[:80], ip, e.code)
            code = "bad_credentials" if e.code == "user_not_found" else e.code
            return RedirectResponse(f"/login?e={code}", status_code=303)
        auth.clear_failures(username, ip)
        sess = auth.create(res.sam, res.display_name, res.upn, res.bind_name, res.matched_groups, password, ip)
    db.audit("act_login", sess.user, ip, ", ".join(sess.groups))
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(SID_COOKIE, sess.sid, httponly=True, secure=settings.cookie_secure, samesite="strict",
                    path="/")
    resp.delete_cookie(LOGIN_COOKIE)
    return resp


@require
async def logout(request: Request):
    form = await form_of(request)
    if await check_csrf(request, form):
        db.audit("act_logout", request.state.sess.user, client_ip(request))
        auth.destroy(request.state.sess.sid)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SID_COOKIE, path="/")
    return resp


async def set_lang(request: Request):
    code = request.path_params["code"]
    nxt = safe_next(request.query_params.get("next", "/"))
    resp = RedirectResponse(nxt, status_code=303)
    if code in ("de", "en"):
        resp.set_cookie(LANG_COOKIE, code, max_age=365 * 86400, samesite="lax", secure=settings.cookie_secure)
    return resp


# ---------------------------------------------------------------------------
# Übersicht & Scans
# ---------------------------------------------------------------------------

@require
async def dashboard(request: Request):
    lang = lang_of(request)
    scans = db.list_scans(60)
    done = [s for s in scans if s["status"] == "done"]
    latest = done[0] if done else None
    pts = [(fmt_dt(s["started_at"], lang)[:10] if lang == "en" else fmt_dt(s["started_at"], lang)[:5],
            s["score_global"], s["id"]) for s in reversed(done[:20])]
    findings = db.get_findings(latest["id"]) if latest else []
    for f in findings:
        f["rule_id"] = canonical_id(f["rule_id"])
    fails = [f for f in findings if f["state"] == "fail"]
    sev_counts = {sv: sum(1 for f in fails if f["severity"] == sv) for sv in SEVERITIES}
    top = sorted(fails, key=lambda f: (-f["points"], SEVERITIES.index(f["severity"] or "info")))[:5]
    overview = db.get_scan(latest["id"])["overview"] if latest else {}
    return render(request, "dashboard.html", {
        "scans": scans[:8], "latest": latest, "trend_svg": trend(pts, lang), "sev_counts": sev_counts,
        "top": top, "rules": RULE_BY_ID, "overview": overview, "running": db.running_scan(),
    })


@require
async def scan_start(request: Request):
    form = await form_of(request)
    if not await check_csrf(request, form):
        return RedirectResponse("/?e=csrf", status_code=303)
    s = request.state.sess
    try:
        scan_id = scanner.start_scan(s.display or s.user, s.bind_name, s.password())
    except scanner.ScanBusy:
        r = db.running_scan()
        return RedirectResponse(f"/scan/{r['id']}" if r else "/", status_code=303)
    db.audit("act_scan_start", s.user, client_ip(request), f"#{scan_id}")
    return RedirectResponse(f"/scan/{scan_id}", status_code=303)


@require
async def scan_view(request: Request):
    scan = db.get_scan(int(request.path_params["id"]))
    if not scan:
        return render(request, "error.html", {"msg": "not_found"}, 404)
    if scan["status"] == "done":
        return RedirectResponse(f"/report/{scan['id']}", status_code=303)
    return render(request, "progress.html", {"scan": scan})


@require
async def scan_status(request: Request):
    scan = db.get_scan(int(request.path_params["id"]))
    if not scan:
        return JSONResponse({"error": "not_found"}, status_code=404)
    lang = lang_of(request)
    err = scan.get("error")
    if err and f"err_{err}" in T:
        err = t(f"err_{err}", lang)
    return JSONResponse({"status": scan["status"], "progress": scan["progress"],
                         "phase": t(scan["phase"] or "phase_start", lang), "error": err})


@require
async def scans_page(request: Request):
    return render(request, "scans.html", {"scans": db.list_scans(500)})


@require
async def scan_delete(request: Request):
    form = await form_of(request)
    if await check_csrf(request, form):
        sid = int(request.path_params["id"])
        if await run_in_threadpool(db.delete_scan, sid):
            db.audit("act_delete", request.state.sess.user, client_ip(request), f"#{sid}")
            await run_in_threadpool(db.compact)
    return RedirectResponse("/scans", status_code=303)


# ---------------------------------------------------------------------------
# Bericht
# ---------------------------------------------------------------------------

def report_data(scan_id: int) -> dict | None:
    scan = db.get_scan(scan_id)
    if not scan or scan["status"] != "done":
        return None
    findings = db.get_findings(scan_id)
    for f in findings:
        f["rule_id"] = canonical_id(f["rule_id"])
    prev = db.previous_done_scan(scan_id)
    prev_fail = {canonical_id(r) for r in db.failed_rule_ids(prev)} if prev else set()
    for f in findings:
        f["rule"] = RULE_BY_ID.get(f["rule_id"])
        f["new"] = bool(prev) and f["state"] == "fail" and f["rule_id"] not in prev_fail
        if f["rule"]:
            present = set().union(*(i.keys() for i in f["items"])) if f["items"] else set()
            f["columns"] = [c for c in f["rule"].columns if c in present]
    findings = [f for f in findings if f["rule"]]
    fails = sorted([f for f in findings if f["state"] == "fail"],
                   key=lambda f: (SEVERITIES.index(f["severity"] or "info"), -f["points"], f["rule_id"]))
    by_cat = {c: [f for f in fails if f["category"] == c] for c in CATEGORIES}
    cur_fail = {f["rule_id"] for f in fails}
    resolved = [RULE_BY_ID[r] for r in sorted(prev_fail - cur_fail) if r in RULE_BY_ID]
    sev_counts = {sv: sum(1 for f in fails if f["severity"] == sv) for sv in SEVERITIES}
    top = sorted(fails, key=lambda f: (-f["points"], SEVERITIES.index(f["severity"] or "info")))[:6]
    return {
        "scan": scan, "ov": scan["overview"], "fails": fails, "by_cat": by_cat,
        "passed": [f for f in findings if f["state"] == "pass"],
        "na": [f for f in findings if f["state"] == "na"],
        "resolved": resolved, "sev_counts": sev_counts, "top": top, "has_prev": bool(prev),
        "scores": {c: scan[f"score_{c}"] for c in CATEGORIES},
    }


@require
async def report_page(request: Request):
    data = report_data(int(request.path_params["id"]))
    if not data:
        return render(request, "error.html", {"msg": "not_found"}, 404)
    lang = lang_of(request)
    ov = data["ov"]
    os_rows = [(tv(n, lang) if n != "@other" else ("Andere" if lang == "de" else "Other"), c) for n, c in ov.get("os_dist", [])]
    data["os_svg"] = hbars(os_rows)
    return render(request, "report.html", data)


@require
async def report_pdf(request: Request):
    data = report_data(int(request.path_params["id"]))
    if not data:
        return render(request, "error.html", {"msg": "not_found"}, 404)
    from .pdfreport import build_pdf
    lang = lang_of(request)
    pdf = await run_in_threadpool(build_pdf, data, lang)
    db.audit("act_pdf", request.state.sess.user, client_ip(request), f"#{data['scan']['id']}")
    started = (data["scan"]["started_at"] or "")[:10]
    dom = re.sub(r"[^A-Za-z0-9._-]", "_", str(data["ov"].get("fqdn") or "domain"))[:80]
    fname = f"SAMAUDIT_{dom}_{re.sub(r'[^0-9-]', '', started)}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@require
async def rules_page(request: Request):
    return render(request, "rules.html", {"rules": RULES})


@require
async def audit_page(request: Request):
    return render(request, "audit.html", {"entries": db.audit_entries(500)})


async def health(request: Request):
    return JSONResponse({"ok": True, "version": VERSION})


async def privacy_page(request: Request):
    return render(request, "privacy.html", {})


async def help_page(request: Request):
    from .mdhelp import manual
    html, toc = manual(lang_of(request))
    return render(request, "help.html", {"manual_html": html, "toc": toc})


@require
async def connection_page(request: Request):
    msg = request.query_params.get("c")
    return _connection(request, cert_msg=msg if msg in ("cert_uploaded", "cert_removed") else None)


def _connection(request: Request, cert_msg: str | None = None, cert_err: str | None = None, status: int = 200):
    from . import webcert
    return render(request, "connection.html", {"pins": db.list_pins(), "webcert": webcert.INFO,
                                               "cert_msg": cert_msg, "cert_err": cert_err}, status=status)


@require
async def cert_upload(request: Request):
    from . import webcert
    fields, files = await multipart_of(request)
    if not await check_csrf(request, fields):
        return _connection(request, cert_err=t("err_csrf", lang_of(request)), status=400)
    if not settings.tls_enabled:
        return _connection(request, cert_err="TLS_ENABLED=false")
    user = request.state.sess.user
    try:
        info = await run_in_threadpool(webcert.install_upload, files, fields.get("password") or None, user)
    except webcert.CertError as e:
        db.audit("act_cert_failed", user, client_ip(request), str(e)[:200])
        return _connection(request, cert_err=str(e), status=400)
    db.audit("act_cert_upload", user, client_ip(request), f"{info.get('subject')} bis {(info.get('not_after') or '')[:10]}")
    return RedirectResponse("/connection?c=cert_uploaded#webcert", status_code=303)


@require
async def cert_remove(request: Request):
    from . import webcert
    form = await form_of(request)
    if await check_csrf(request, form):
        await run_in_threadpool(webcert.remove_upload)
        db.audit("act_cert_removed", request.state.sess.user, client_ip(request), "")
        return RedirectResponse("/connection?c=cert_removed#webcert", status_code=303)
    return RedirectResponse("/connection", status_code=303)


@require
async def pin_reset(request: Request):
    form = await form_of(request)
    if await check_csrf(request, form):
        host = (form.get("host") or "").strip()
        if host:
            db.delete_pins(host)
            db.audit("act_pin_reset", request.state.sess.user, client_ip(request), host)
    return RedirectResponse("/connection", status_code=303)


# ---------------------------------------------------------------------------
# Middleware & App
# ---------------------------------------------------------------------------

class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        h = resp.headers
        h["X-Frame-Options"] = "DENY"
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                        "script-src 'self'; font-src 'self'; frame-ancestors 'none'; "
                                        "form-action 'self'; base-uri 'none'")
        if settings.cookie_secure:
            h["Strict-Transport-Security"] = "max-age=31536000"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"  # Berichte, Protokoll, Verbindungsdaten nie im Browser-Cache
        return resp


def _purge():
    res = db.purge_expired(settings.report_retention_days, settings.audit_retention_days)
    if res["scans"] or res["audit"]:
        log.info("Löschfristen: %s Berichte und %s Protokolleinträge gelöscht", res["scans"], res["audit"])
        db.audit("act_purge", detail=f"{res['scans']} Berichte, {res['audit']} Protokolleinträge")


async def _janitor():
    last_purge = 0.0
    while True:
        auth.cleanup()
        if time.time() - last_purge > 6 * 3600:
            last_purge = time.time()
            try:
                await run_in_threadpool(_purge)
            except Exception:  # noqa: BLE001
                log.exception("Löschfristen konnten nicht angewendet werden")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app):
    db.init()
    task = asyncio.create_task(_janitor())
    problems = settings.validate()
    for p in problems:
        log.error("Konfiguration: %s", p)
    if settings.demo_mode:
        log.warning("DEMO_MODE ist aktiv – Anmeldung mit demo/demo, keine echte Domäne!")
    yield
    task.cancel()


routes = [
    Route("/login", login_page, methods=["GET"]),
    Route("/login", login_submit, methods=["POST"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/lang/{code}", set_lang),
    Route("/", dashboard),
    Route("/scan", scan_start, methods=["POST"]),
    Route("/scan/{id:int}", scan_view),
    Route("/api/scan/{id:int}", scan_status),
    Route("/scans", scans_page),
    Route("/report/{id:int}", report_page),
    Route("/report/{id:int}/pdf", report_pdf),
    Route("/report/{id:int}/delete", scan_delete, methods=["POST"]),
    Route("/rules", rules_page),
    Route("/audit", audit_page),
    Route("/healthz", health),
    Route("/connection", connection_page),
    Route("/privacy", privacy_page),
    Route("/help", help_page),
    Route("/connection/reset", pin_reset, methods=["POST"]),
    Route("/connection/cert", cert_upload, methods=["POST"]),
    Route("/connection/cert/remove", cert_remove, methods=["POST"]),
    Mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static"),
]

app = Starlette(routes=routes, middleware=[Middleware(SecurityHeaders)], lifespan=lifespan)
