#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Runs as root only until the data folder (./data on the host) belongs to the
# program user and your own certificates (./certs) are available readable,
# then switches permanently to the program user.
set -e
APP_UID=10001
APP_GID=10001
DATA="${DATA_DIR:-/app/data}"
CERTS_SRC=/app/certs
CERTS_RUN=/tmp/certs

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA"
  chown -R "$APP_UID:$APP_GID" "$DATA"
  chmod 700 "$DATA"
  # Own certificates: in-memory copy (/tmp), readable only by the program user.
  # This way the files on the host do not need to be readable by UID 10001.
  if [ -d "$CERTS_SRC" ]; then
    rm -rf "$CERTS_RUN"; mkdir -p "$CERTS_RUN"
    find "$CERTS_SRC" -maxdepth 1 -type f ! -name 'README*' -exec cp {} "$CERTS_RUN"/ \;
    chown -R "$APP_UID:$APP_GID" "$CERTS_RUN"
    chmod 700 "$CERTS_RUN"; find "$CERTS_RUN" -type f -exec chmod 600 {} \;
    export CERTS_DIR="$CERTS_RUN"
  fi
  # Switch user: changing from root to another UID drops all root privileges
  exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups "$@"
fi
exec "$@"
