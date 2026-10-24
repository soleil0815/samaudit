# SAMAUDIT – pinned build (versions fixed; not bit-for-bit reproducible)
# Base image pinned by tag. On the first local build update.sh additionally pins it to its
# immutable digest (file base-image.lock), so later local builds use the same base.
ARG PYTHON_IMAGE=python:3.13.16-slim
FROM ${PYTHON_IMAGE}

ARG APP_VERSION=1.9.3
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

# Install exactly the pinned list (no re-resolution), then verify consistency.
# Time zone data comes from the pinned tzdata package (instead of apt, whose versions change).
COPY requirements.txt .
RUN pip install --no-deps --only-binary=:all: -r requirements.txt \
 && pip check \
 && python -c "import os, shutil, tzdata; shutil.copytree(os.path.join(os.path.dirname(tzdata.__file__), 'zoneinfo'), '/usr/share/zoneinfo', dirs_exist_ok=True)" \
 && ln -snf "/usr/share/zoneinfo/$TZ" /etc/localtime && echo "$TZ" > /etc/timezone

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
