# SAMAUDIT – container image, reproducible build
#
# Everything that ends up in the image is pinned (computed by tools/update-locks.sh):
#   PYTHON_IMAGE     base image: Python series 3.13 on Debian 13 "trixie" – tag AND digest
#   DEBIAN_SNAPSHOT  point in time on snapshot.debian.org: every Debian package of the image
#                    (including those of the base image) is upgraded to exactly this state
#   requirements.txt every Python package incl. sub-dependencies, exact version + SHA-256 hashes
# The resulting package lists are written to /app/os-packages.txt and /app/package-versions.txt
# and checked against locks/os-packages.txt in CI. Package managers (pip, apt) are removed.
ARG PYTHON_IMAGE=python:3.13.17-slim-trixie@sha256:0000000000000000000000000000000000000000000000000000000000000000
FROM ${PYTHON_IMAGE}

ARG DEBIAN_SNAPSHOT=20261025T000000Z
ARG DEBIAN_CODENAME=trixie
ARG APP_VERSION=1.9.7
# version of this image: program version, or "<program version>-s<n>" for a security update
ARG IMAGE_VERSION=
LABEL org.opencontainers.image.title="SAMAUDIT" \
      org.opencontainers.image.version="${IMAGE_VERSION:-$APP_VERSION}" \
      org.opencontainers.image.description="Security assessment for Active Directory (Windows AD / Samba AD)" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/soleil0815/samaudit"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data \
    TZ=Europe/Berlin \
    PORT=9400 \
    SAMAUDIT_IMAGE_VERSION=${IMAGE_VERSION:-$APP_VERSION}

WORKDIR /app

# 1) Debian: stay on the pinned release and upgrade ALL packages to the pinned snapshot.
RUN set -eu; \
    . /etc/os-release; \
    [ "$VERSION_CODENAME" = "$DEBIAN_CODENAME" ] || { echo "Base image is Debian $VERSION_CODENAME, expected $DEBIAN_CODENAME" >&2; exit 1; }; \
    sed -i -e "s#http://deb.debian.org/debian-security#https://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT#g" \
           -e "s#http://deb.debian.org/debian#https://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT#g" \
           /etc/apt/sources.list.d/debian.sources; \
    grep -q "snapshot.debian.org" /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=5 update; \
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=5 \
      -y --no-install-recommends upgrade; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

# 2) Python packages: exactly the lock file (hashes required, nothing resolved), then consistency
#    check and the list of installed versions. Time zone data comes from the tzdata package.
COPY requirements.txt .
RUN set -eu; \
    pip install --no-deps --require-hashes --only-binary=:all: --no-cache-dir -r requirements.txt; \
    pip check; \
    pip freeze --all --exclude pip > /app/package-versions.txt; \
    python -c "import os, shutil, tzdata; shutil.copytree(os.path.join(os.path.dirname(tzdata.__file__), 'zoneinfo'), '/usr/share/zoneinfo', dirs_exist_ok=True)"; \
    ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime; echo "$TZ" > /etc/timezone

# 3) Remove what is not needed at runtime: pip (and its bundled libraries) and apt.
#    The dpkg database stays so that vulnerability scanners can see the installed packages.
RUN set -eu; \
    python -m pip uninstall -y pip; \
    rm -rf /usr/local/lib/python3*/ensurepip /root/.cache; \
    dpkg --purge --force-remove-essential --force-remove-protected --force-depends apt; \
    rm -rf /etc/apt /var/lib/apt /var/cache/apt /var/log/apt; \
    dpkg-query -W -f '${Package} ${Version}\n' | sort > /app/os-packages.txt

COPY app ./app
COPY run.py entrypoint.sh ./
# Licence (AGPL-3.0-or-later) and third-party notices travel with the image
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.md /app/
# Shipped with the image so "update.sh --pull" can keep the local copies up to date
COPY update.sh .env.example /app/dist/
COPY certs/README.txt /app/dist/certs-README.txt

# Unprivileged program user. The container starts briefly as root so entrypoint.sh can take
# ownership of the data folder (bind mount ./data), and then runs as samaudit.
RUN groupadd --system --gid 10001 samaudit \
 && useradd --system --uid 10001 --gid 10001 --home /app samaudit \
 && mkdir -p /app/data /app/certs \
 && chown -R samaudit:samaudit /app/data \
 && chmod 755 /app/entrypoint.sh

EXPOSE 9400
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import os,ssl,urllib.request as u; s=os.environ.get('TLS_ENABLED','true').lower() in ('1','true','yes','ja','on'); p=os.environ.get('PORT','9400'); u.urlopen(('https' if s else 'http')+'://127.0.0.1:'+p+'/healthz', context=ssl._create_unverified_context() if s else None, timeout=4)" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "run.py"]
