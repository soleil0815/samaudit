# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Startpunkt: richtet das HTTPS-Zertifikat ein (eigenes oder selbstsigniert) und startet den Webserver."""
from __future__ import annotations

import logging
import os

import uvicorn

from app.config import settings

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("samaudit")


def main() -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    # vor allem anderen: nur eine Instanz, Rückschritt erkennen, vor einem Versionswechsel sichern
    from app import datastate
    try:
        datastate.prepare()
    except datastate.StartRefused as e:
        log.error("START ABGEBROCHEN: %s", e)
        raise SystemExit(78) from None
    kwargs = {"host": "0.0.0.0", "port": settings.port, "log_level": "info", "access_log": False,
              "proxy_headers": bool(settings.trusted_proxies), "server_header": False}
    if settings.trusted_proxies:
        kwargs["forwarded_allow_ips"] = settings.trusted_proxies
    from app import webcert
    if settings.tls_enabled:
        cert_file, key_file = webcert.prepare()
        kwargs.update(ssl_certfile=cert_file, ssl_keyfile=key_file)
    from app import egress
    egress.install()
    from app.version import APP_NAME, VERSION
    log.info("%s v%s startet auf Port %s (%s), Domäne %s (%s), Zeitzone %s%s", APP_NAME, VERSION, settings.port,
             "HTTPS" if settings.tls_enabled else "HTTP", settings.domain_fqdn or "–", settings.domain_type, settings.tz,
             " – DEMO" if settings.demo_mode else "")
    config = uvicorn.Config("app.main:app", **kwargs)
    config.load()
    if settings.tls_enabled:
        # Kontext merken: ein über die Weboberfläche hochgeladenes Zertifikat wird ohne Neustart aktiv
        webcert.attach(config.ssl)
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
