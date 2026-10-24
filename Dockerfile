# SAMAUDIT – container image
# Base image: newest Python 3.13 patch release on the current Debian (slim). Every build pulls the
# current 3.13.x (weekly rebuild on GitHub) – bug and security fixes of Python itself. Moving to the
# next Python minor version ("lifting the base") is a deliberate step before 3.13 reaches end of life.
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

ARG APP_VERSION=1.9.6
LABEL org.opencontainers.image.title="SAMAUDIT" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.description="Security assessment for Active Directory (Windows AD / Samba AD)" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/soleil0815/samaudit"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data \
    TZ=Europe/Berlin \
    PORT=9400

WORKDIR /app

# Install all available Debian security updates of the base image. SECURITY_UPDATES changes every
# week in the GitHub build (calendar week), so this step really runs again on the weekly rebuild
# instead of being taken from the build cache.
ARG SECURITY_UPDATES=local
RUN echo "Debian updates: $SECURITY_UPDATES" \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends upgrade \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install the NEWEST version of every Python package (policy: nothing outdated in the image) and
# verify consistency. The resulting versions are recorded in /app/package-versions.txt.
# Time zone data comes from the tzdata package.
# pip itself is removed afterwards: it is not needed at runtime and carries its own bundled
# libraries (urllib3, certifi, msgpack, pkg_resources …) that show up in vulnerability scans.
COPY requirements.txt .
RUN pip install --upgrade --upgrade-strategy eager --only-binary=:all: --no-cache-dir -r requirements.txt \
 && pip check \
 && pip freeze --all --exclude pip > /app/package-versions.txt \
 && python -c "import os, shutil, tzdata; shutil.copytree(os.path.join(os.path.dirname(tzdata.__file__), 'zoneinfo'), '/usr/share/zoneinfo', dirs_exist_ok=True)" \
 && ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime && echo "$TZ" > /etc/timezone \
 && python -m pip uninstall -y pip \
 && rm -rf /usr/local/lib/python3*/ensurepip /root/.cache

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
