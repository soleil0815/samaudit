# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMAUDIT-Autoren
"""Entry point: sets up the HTTPS certificate (your own or self-signed) and starts the web server."""
from __future__ import annotations

import logging
import os
from typing import Any

import uvicorn

from app.config import settings

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("samaudit")


def main() -> None:
    os.makedirs(settings.data_dir, exist_ok=True)
    # before anything else: only one instance, detect a downgrade, back up before a version change
    from app import datastate
    try:
        datastate.prepare()
        from app import db
        db.init()          # adapt the schema and record the version – right away, not only when the web server starts
    except datastate.StartRefused as e:
        log.error("START REFUSED: %s", e)
        raise SystemExit(78) from None
    # inside the container: listen on all interfaces; the host decides via the port mapping what is reachable
    kwargs: dict[str, Any] = {"host": "0.0.0.0",  # noqa: S104
                              "port": settings.port, "log_level": "info", "access_log": False,
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
    log.info("%s v%s starting on port %s (%s), domain %s (%s), time zone %s%s", APP_NAME, VERSION, settings.port,
             "HTTPS" if settings.tls_enabled else "HTTP", settings.domain_fqdn or "–", settings.domain_type, settings.tz,
             " – DEMO" if settings.demo_mode else "")
    config = uvicorn.Config("app.main:app", **kwargs)
    config.load()
    if settings.tls_enabled and config.ssl is not None:   # always set with ssl_certfile
        # keep the context: a certificate uploaded via the web interface becomes active without a restart
        webcert.attach(config.ssl)
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
