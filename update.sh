#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SAMAUDIT – install, update and rebuild the container
#
#   sh update.sh --pull         update to the latest image built on GitHub (ghcr.io), no local build
#   sh update.sh --pull=1.7.6   … or to a specific version
#   sh update.sh samaudit-v*.zip  install a new version from the ZIP (asks first), then build locally
#   ./update.sh                 backup → build locally → start → health check → clean up
#   ./update.sh -y …            no questions (e.g. for scripts)
#   ./update.sh --restart       restart only (e.g. after changing .env), no rebuild
#   ./update.sh --no-backup     skip the backup
#   ./update.sh --no-cache      full rebuild (without Docker build cache)
#   ./update.sh --help
#
# Up to date: every build pulls the current Python 3.13 base image, installs all Debian security
# updates and the newest version of every Python package.
# Requires Docker only – no Docker Compose.
# Windows line endings (CRLF, e.g. after copying/editing on Windows) are repaired automatically.
# The trailing "#" on the next two lines keeps them working even while the file still has CRLF.
if grep -q "$(printf '\r')" "$0" 2>/dev/null; then echo "update.sh: converting Windows line endings (CRLF -> LF) …"; sed -i 's/\r$//' "$0" && exec bash "$0" "$@"; echo "Please run: sed -i 's/\r\$//' update.sh" >&2; exit 1; fi #
# Started with "sh update.sh"? Then re-run automatically with bash (the script needs bash).
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi #
set -euo pipefail
ORIG_ARGS=("$@")
ORIG_PWD="$PWD"
cd "$(dirname "$0")"
INSTALL_DIR="$(pwd -P)"
# Files that break with Windows line endings (shell scripts, Dockerfile, package lists)
for f in entrypoint.sh Dockerfile requirements.txt .env.example; do
  if [ -f "$f" ] && [ -w "$f" ] && grep -q $'\r' "$f"; then sed -i 's/\r$//' "$f"; echo "Converted Windows line endings in $f"; fi
done

SERVICE=samaudit
CONTAINER=samaudit
BACKUP_DIR=backups
KEEP_BACKUPS=5
KEEP_IMAGES=2
HEALTH_TIMEOUT=120

DO_BACKUP=1; NO_CACHE=""; REFRESH_BASE=0; DO_LOCK=0; YES=0; RESTART_ONLY=0
PULL=0; PULL_TAG=latest; SELF_UPDATED=0
DEFAULT_IMAGE_REPO=ghcr.io/soleil0815/samaudit   # override with SAMAUDIT_IMAGE in .env
NETWORK=samaudit-net; BRIDGE=br-samaudit
ZIPS=(); CLEANUP_ZIPS=(); FROM_VERSION=""; PASS=()
for a in "$@"; do
  case "$a" in
    --cleanup-zip=*) CLEANUP_ZIPS+=("${a#--cleanup-zip=}") ;;
    --from-version=*) FROM_VERSION="${a#--from-version=}" ;;
    -y|--yes) YES=1; PASS+=("$a") ;;
    --no-backup) DO_BACKUP=0; PASS+=("$a") ;;
    --no-cache) NO_CACHE="--no-cache"; PASS+=("$a") ;;
    --refresh-base) REFRESH_BASE=1; PASS+=("$a") ;;   # obsolete: the base image is always fetched fresh
    --lock) DO_LOCK=1 ;;
    --restart) RESTART_ONLY=1; DO_BACKUP=0 ;;
    --pull) PULL=1 ;;
    --pull=*) PULL=1; PULL_TAG="${a#--pull=}"; PULL_TAG="${PULL_TAG#v}" ;;
    --skip-self-update) SELF_UPDATED=1 ;;
    *.zip|*.ZIP|*.Zip)
      z="$a"; case "$z" in /*) ;; *) z="$ORIG_PWD/$z" ;; esac
      if [ -f "$z" ]; then ZIPS+=("$z")
      else  # e.g. "samaudit-*.zip" while the file is "SAMAUDIT-v1.7.1.zip": match case-insensitively
        shopt -s nullglob nocaseglob; m=($z); shopt -u nullglob nocaseglob
        [ ${#m[@]} -gt 0 ] || { echo "ZIP file not found: $a"; exit 2; }
        ZIPS+=("${m[@]}")
      fi ;;
    -h|--help) sed -n '3,19p' "$INSTALL_DIR/update.sh" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $a (see --help)"; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_dim=$'\e[2m'; c_off=$'\e[0m'
[ -t 1 ] || { c_ok=""; c_warn=""; c_err=""; c_dim=""; c_off=""; }
step() { printf '\n%s==>%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%sWARNING:%s %s\n' "$c_warn" "$c_off" "$*"; }
die()  { printf '%sERROR:%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }
ask()  {  # ask "question" Y|N (default)  → 0 = yes
  local def="$2" a
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "Cannot ask (no terminal input). Run with -y to skip questions."
  if [ "$def" = Y ]; then read -r -p "$1 [Y/n] " a; [ -z "$a" ] || [[ "$a" =~ ^[yYjJ] ]]
  else read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[yYjJ] ]]; fi
}

ask_strict() {  # like ask, but -y does NOT answer it (security-relevant questions) → 0 = yes
  local a
  [ -t 0 ] || return 1
  read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[yYjJ] ]]
}
safe_rel() {  # safe_rel PATH → 0 if PATH is a plain relative path inside the SAMAUDIT folder
  local p="$1"
  [[ -n "$p" && "$p" != /* && ! "$p" =~ (^|/)\.\.(/|$) && ! "$p" =~ [[:cntrl:]] ]] || return 1
  local d; d="$(cd "$(dirname "$p")" 2>/dev/null && pwd -P)" || return 0   # folder does not exist yet: fine
  [[ "$d/" == "$INSTALL_DIR/"* || "$d" == "$INSTALL_DIR" ]]
}

command -v docker >/dev/null || die "docker is not installed."
docker info >/dev/null 2>&1 || die "Cannot access Docker – run with sudo or add the user to the 'docker' group."

# ---------------------------------------------------------------------------
# Install a new version from a ZIP
# ---------------------------------------------------------------------------
# These files/folders belong to the operator and are NEVER overwritten or deleted:
PROTECTED_RE='^(\.env|data/.*|backups/.*|certs/.*|base-image\.lock|docker-compose\.override\.yml|\.firewall-targets|\.samaudit-manifest|\.env\.run)$'
MANIFEST=.samaudit-manifest

ver_of() { sed -n 's/^VERSION = "\(.*\)"/\1/p' "$1" 2>/dev/null | head -1; }

extract_zip() {  # extract_zip ZIP TARGET_DIR
  if command -v unzip >/dev/null; then unzip -q -o "$1" -d "$2"
  elif command -v bsdtar >/dev/null; then bsdtar -xf "$1" -C "$2"
  elif command -v python3 >/dev/null; then python3 -m zipfile -e "$1" "$2"
  else
    docker run --rm -v "$1:/p.zip:ro" -v "$2:/out" "$(sed -n 's/^ARG PYTHON_IMAGE=//p' Dockerfile | head -1)" \
      python -m zipfile -e /p.zip /out
  fi
}

install_package() {
  local zip="" best="" v
  # several ZIPs given (e.g. via *): take the one with the highest version
  for z in "${ZIPS[@]}"; do
    v="$(basename "$z" | sed -n 's/.*[vV]\([0-9][0-9.]*[0-9]\).*/\1/p')"
    if [ -z "$best" ] || [ "$(printf '%s\n%s\n' "$best" "$v" | sort -V | tail -1)" = "$v" ]; then best="$v"; zip="$z"; fi
  done
  [ -n "$zip" ] || zip="${ZIPS[0]}"

  step "Checking package: $(basename "$zip")"
  local tmp; tmp="$(mktemp -d "$INSTALL_DIR/.update-XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  extract_zip "$zip" "$tmp" >/dev/null 2>&1 || die "ZIP file is damaged or unreadable: $zip"
  # never trust links or odd names from a package
  [ -z "$(find "$tmp" -type l | head -1)" ] || die "The ZIP contains symbolic links – refusing to install it."
  local src; src="$(dirname "$(find "$tmp" -maxdepth 3 -path '*/app/version.py' | head -1)")"
  src="${src%/app}"
  [ -n "$src" ] && [ -f "$src/app/version.py" ] && [ -f "$src/Dockerfile" ] && [ -f "$src/update.sh" ] \
    || die "The ZIP does not contain a SAMAUDIT package."
  local new_ver old_ver; new_ver="$(ver_of "$src/app/version.py")"; old_ver="$(ver_of app/version.py)"
  [ -n "$new_ver" ] || die "Cannot read the version in the package."

  echo "   installed:   ${old_ver:-–}"
  echo "   in package:  $new_ver"
  if [ -n "$old_ver" ] && [ "$old_ver" != "$new_ver" ] && \
     [ "$(printf '%s\n%s\n' "$old_ver" "$new_ver" | sort -V | tail -1)" = "$old_ver" ]; then
    warn "The package is OLDER than the installed version (downgrade)."
  elif [ "$old_ver" = "$new_ver" ]; then
    echo "   (same version – will be installed again)"
  fi
  echo "   Your data and settings stay unchanged: .env, data/, certs/, backups/"
  ask "Update SAMAUDIT ${old_ver:-} → $new_ver now?" N || { echo "Cancelled – nothing changed."; exit 0; }

  # list of package files (relative)
  local list; list="$(cd "$src" && find . -type f | sed 's#^\./##' | grep -Ev "$PROTECTED_RE" | grep -Ev '^certs/' | sort)"
  local bad; bad="$(grep -E '(^/|(^|/)\.\.(/|$)|[[:cntrl:]])' <<< "$list" | head -3 || true)"
  [ -z "$bad" ] || die "The ZIP contains unsafe file names: $bad"
  # certs/README.txt may be updated
  [ -f "$src/certs/README.txt" ] && list="$(printf '%s\ncerts/README.txt\n' "$list" | sort -u)"

  # back up the current program files (for a rollback)
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  local prog="$BACKUP_DIR/program-${old_ver:-old}-$(date +%Y%m%d-%H%M%S).tgz"
  if [ -f "$MANIFEST" ]; then
    (umask 077; tar czf "$prog" -T <(grep -Ev "$PROTECTED_RE" "$MANIFEST" | while read -r f; do [ -e "$f" ] && echo "$f"; done) 2>/dev/null) || true
  else
    (umask 077; tar czf "$prog" --exclude=./data --exclude=./backups --exclude=./certs --exclude=./.env \
       --exclude='./.update-*' --exclude='*.zip' --exclude='*.ZIP' . 2>/dev/null) || true
  fi
  [ -s "$prog" ] && echo "   previous program files backed up: $prog"

  step "Installing files"
  local n=0 f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    safe_rel "$f" || die "Unsafe path in package: $f"
    mkdir -p "$(dirname "$f")"
    # copy first, then rename: this safely replaces even the currently running update.sh
    cp -p "$src/$f" "$f.new.$$" && mv -f "$f.new.$$" "$f"
    n=$((n + 1))
  done <<< "$list"
  echo "   $n files updated"

  # clean-up: files that no longer exist in the new version
  local removed=0
  if [ -f "$MANIFEST" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      safe_rel "$f" || { warn "skipping unsafe manifest entry: $f"; continue; }
      if [[ ! "$f" =~ $PROTECTED_RE ]] && ! grep -qxF "$f" <<< "$list" && [ -f "$f" ] && [ ! -L "$f" ]; then
        rm -f "$f"; removed=$((removed + 1)); echo "   removed (no longer included): $f"
      fi
    done < "$MANIFEST"
  else
    # first install with a manifest: remove everything in app/ that is not in the package
    while IFS= read -r f; do
      if ! grep -qxF "$f" <<< "$list"; then rm -f "$f"; removed=$((removed + 1)); echo "   removed: $f"; fi
    done < <(find app -type f ! -path '*/__pycache__/*' 2>/dev/null | sort)
  fi
  find app -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  find app -type d -empty -delete 2>/dev/null || true
  printf '%s\n' "$list" > "$MANIFEST"
  chmod 755 update.sh entrypoint.sh 2>/dev/null || true
  [ "$removed" -gt 0 ] && echo "   $removed obsolete file(s) removed"
  { ls -1t "$BACKUP_DIR"/program-*.tgz "$BACKUP_DIR"/programm-*.tgz 2>/dev/null || true; } | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f

  rm -rf "$tmp"; trap - EXIT
  # continue with the NEW update.sh (build, start, check, clean up)
  local cz=(); for z in "${ZIPS[@]}"; do cz+=("--cleanup-zip=$z"); done
  exec bash ./update.sh -y "${PASS[@]}" "--from-version=${old_ver:-}" "${cz[@]}"
}

[ ${#ZIPS[@]} -gt 0 ] && install_package

APP_VERSION="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' app/version.py 2>/dev/null || true)"
BASE_TAG="$(sed -n 's/^ARG PYTHON_IMAGE=//p' Dockerfile 2>/dev/null | head -1 || true)"
if [ "$PULL" = 0 ] && [ "$RESTART_ONLY" = 0 ]; then
  [ -n "$APP_VERSION" ] && [ -n "$BASE_TAG" ] \
    || die "Cannot determine version or base image (app/version.py, Dockerfile). Without the source code use: sh update.sh --pull"
fi

# ---------------------------------------------------------------------------
# Pin the base image to its digest
# ---------------------------------------------------------------------------
resolve_base() {
  # policy: always the current base image (no pinning) – base-image.lock of older versions is removed
  rm -f base-image.lock
  step "Fetching current base image $BASE_TAG"
  docker pull "$BASE_TAG" >/dev/null || die "Could not pull base image $BASE_TAG (check internet access / tag)."
  local digest
  digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$BASE_TAG" | grep -m1 '@sha256:' | sed 's/.*@//')"
  [ -n "$digest" ] || die "Cannot determine the digest of $BASE_TAG."
  BASE_IMAGE="$BASE_TAG@$digest"
  echo "   using: $BASE_IMAGE"
}

# ---------------------------------------------------------------------------
# --lock: obsolete (kept so old calls do not fail)
# ---------------------------------------------------------------------------
if [ "$DO_LOCK" = 1 ]; then
  echo "--lock is no longer needed: every build installs the newest package versions."
  exit 0
fi

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------
if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
  die ".env was missing and has been created from .env.example. Please set at least DOMAIN_FQDN and run again."
fi
sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' .env | grep -Eq '^[[:space:]]*DOMAIN_FQDN[[:space:]]*=[[:space:]]*[^[:space:]#]' \
  || warn "DOMAIN_FQDN is not set in .env."
mkdir -p data certs

# ---------------------------------------------------------------------------
# Run the container with plain Docker (no Docker Compose needed)
# ---------------------------------------------------------------------------
# .env may be saved with Windows line endings (CRLF) or a BOM (e.g. edited via WinSCP/Notepad)
env_clean() { sed -e '1s/^\xEF\xBB\xBF//' -e 's/\r$//' .env; }
env_get() { env_clean | sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" | tail -1 | sed 's/[[:space:]]#.*$//' | tr -d "\"'" | xargs; }

# Prepare .env for "docker run --env-file": strip comments and quotes
# (docker run would otherwise keep quotes as part of the value).
make_runenv() {
  (umask 077; : > .env.run)
  local line key val
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"; key="${key%"${key##*[![:space:]]}"}"
    val="${line#*=}"; val="${val#"${val%%[![:space:]]*}"}"
    if [[ "$val" == \"*\"* ]]; then val="${val#\"}"; val="${val%%\"*}"
    elif [[ "$val" == \'*\'* ]]; then val="${val#\'}"; val="${val%%\'*}"
    else val="${val%%[[:space:]]#*}"; val="${val%"${val##*[![:space:]]}"}"; fi
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && printf '%s=%s\n' "$key" "$val" >> .env.run
  done < <(env_clean)
}

ensure_network() {
  docker network inspect "$NETWORK" >/dev/null 2>&1 && return 0
  docker network create --driver bridge --ipv6=false \
    -o "com.docker.network.bridge.name=$BRIDGE" "$NETWORK" >/dev/null \
    || die "Could not create Docker network $NETWORK."
}

start_container() {  # start_container IMAGE
  local image="$1" port extra=() h dns=() hosts=()
  port="$(env_get PORT)"; port="${port:-9400}"
  [[ "$port" =~ ^[0-9]+$ ]] || die "PORT in .env is not a number: $port"
  # optional: DNS servers and fixed host entries for the DCs (DOCKER_DNS / DOCKER_EXTRA_HOSTS in .env)
  read -r -a dns <<< "$(env_get DOCKER_DNS | tr ',;' '  ')"
  read -r -a hosts <<< "$(env_get DOCKER_EXTRA_HOSTS | tr ',;' '  ')"
  for h in "${dns[@]}"; do extra+=(--dns "$h"); done
  for h in "${hosts[@]}"; do extra+=(--add-host "$h"); done
  make_runenv
  ensure_network
  # Do not delete the current container, set it aside – for a rollback if the new one does not run
  docker rm -f "$CONTAINER-alt" >/dev/null 2>&1 || true
  if docker inspect "$CONTAINER" >/dev/null 2>&1; then
    # rename first (works while running), then stop – a failed rename leaves the service untouched
    docker rename "$CONTAINER" "$CONTAINER-old" || die "Could not set the current container aside – nothing changed."
    HAVE_OLD=1
    trap 'echo; warn "interrupted – restoring the previous version"; rollback; rm -f "$INSTALL_DIR/.env.run"; exit 130' INT TERM HUP
    docker update --restart=no "$CONTAINER-old" >/dev/null 2>&1 || true
    docker stop "$CONTAINER-old" >/dev/null 2>&1 || true
  fi
  docker run -d --name "$CONTAINER" --hostname "$CONTAINER" \
    --restart unless-stopped \
    --env-file .env.run \
    -p "$port:$port" \
    -v "$INSTALL_DIR/data:/app/data" \
    -v "$INSTALL_DIR/certs:/app/certs:ro" \
    --network "$NETWORK" \
    --log-driver json-file --log-opt max-size=5m --log-opt max-file=3 \
    --read-only --tmpfs /tmp \
    --security-opt no-new-privileges:true \
    --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID \
    "${extra[@]}" \
    "$image" >/dev/null \
    || { rm -f .env.run; rollback; die "Container could not be started (see above) – the previous version keeps running."; }
  rm -f .env.run
}

HAVE_OLD=0
rollback() {  # discard the new container, start the previous one again
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "$HAVE_OLD" = 1 ] && docker inspect "$CONTAINER-old" >/dev/null 2>&1; then
    docker rename "$CONTAINER-old" "$CONTAINER"
    docker update --restart=unless-stopped "$CONTAINER" >/dev/null 2>&1 || true
    docker start "$CONTAINER" >/dev/null 2>&1 && echo "   previous version started again."
  fi
}
trap 'rm -f "$INSTALL_DIR/.env.run"' EXIT

# An earlier run was interrupted while switching containers? Then "samaudit-old" may be the last working
# version – restore it instead of throwing it away.
recover_interrupted() {
  docker inspect "$CONTAINER-old" >/dev/null 2>&1 || return 0
  local health
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)"
  if [ "$health" = healthy ]; then
    docker rm -f "$CONTAINER-old" >/dev/null 2>&1 || true      # left over, current one works
    return 0
  fi
  warn "Found the previous version ($CONTAINER-old) from an interrupted update – restoring it."
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker rename "$CONTAINER-old" "$CONTAINER" || die "Could not restore $CONTAINER-old – please check: docker ps -a"
  docker update --restart=unless-stopped "$CONTAINER" >/dev/null 2>&1 || true
  docker start "$CONTAINER" >/dev/null 2>&1 || true
  echo "   previous version restored."
}
recover_interrupted

running_version() {
  docker inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$CONTAINER" 2>/dev/null || true
}
image_version() { docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true; }

# Image that will be started: local build, pulled from GitHub, or (restart) the current one
if [ "$PULL" = 1 ]; then
  repo="$(env_get SAMAUDIT_IMAGE)"; repo="${repo:-$DEFAULT_IMAGE_REPO}"
  case "${repo##*/}" in *:*) IMAGE="$repo" ;; *) IMAGE="$repo:$PULL_TAG" ;; esac
  step "Pulling image $IMAGE"
  docker pull "$IMAGE" || die "Could not pull $IMAGE.
       Private repository/package? Log in once:  docker login ghcr.io -u <github-user>
       (password: a personal access token with the scope read:packages)"
  # update.sh and .env.example ship inside the image – keep the local copies in sync
  self_update_from_image() {
    [ "$SELF_UPDATED" = 1 ] && return 0
    local cid tmpd; tmpd="$(mktemp -d)"
    cid="$(docker create "$IMAGE" 2>/dev/null)" || { rm -rf "$tmpd"; return 0; }
    docker cp "$cid:/app/dist/." "$tmpd/" >/dev/null 2>&1 || true
    docker rm -f "$cid" >/dev/null 2>&1 || true
    [ -f "$tmpd/.env.example" ] && cp "$tmpd/.env.example" ".env.example.new.$$" && mv -f ".env.example.new.$$" .env.example
    [ -f "$tmpd/certs-README.txt" ] && mkdir -p certs && cp "$tmpd/certs-README.txt" certs/README.txt
    if [ -f "$tmpd/update.sh" ] && ! cmp -s "$tmpd/update.sh" update.sh; then
      # update.sh runs with your rights on the host – never replace it unasked (not even with -y)
      cp "$tmpd/update.sh" update.sh.new && chmod 644 update.sh.new
      echo "   The image contains a newer update.sh (saved as update.sh.new; changes: diff update.sh update.sh.new)."
      if ask_strict "   Use the new update.sh now?"; then
        chmod 755 update.sh.new && mv -f update.sh.new update.sh
        rm -rf "$tmpd"
        echo "   update.sh replaced – continuing with the new version"
        exec bash ./update.sh "${ORIG_ARGS[@]}" --skip-self-update
      fi
      echo "   keeping the current update.sh"
    fi
    rm -rf "$tmpd"
  }
  self_update_from_image
  APP_VERSION="$(image_version "$IMAGE")"
  if [ "$RESTART_ONLY" = 0 ] && docker inspect "$CONTAINER" >/dev/null 2>&1 && \
     [ "$(docker inspect --format '{{.Image}}' "$CONTAINER")" = "$(docker image inspect --format '{{.Id}}' "$IMAGE")" ]; then
    echo "   SAMAUDIT ${APP_VERSION:-} is already up to date – nothing to do. (Restart anyway: sh update.sh --pull --restart)"
    exit 0
  fi
elif [ "$RESTART_ONLY" = 1 ]; then
  IMAGE="$(docker inspect --format '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true)"
  IMAGE="${IMAGE:-samaudit:$APP_VERSION}"
  APP_VERSION="$(image_version "$IMAGE")"
else
  IMAGE="samaudit:$APP_VERSION"
fi

OLD_VERSION="$(running_version | tr -cd '0-9A-Za-z.-')"
APP_VERSION="$(printf '%s' "${APP_VERSION:-}" | tr -cd '0-9A-Za-z.-')"
echo "SAMAUDIT: installed ${OLD_VERSION:-–}  →  new ${APP_VERSION:-?}"

# ---------------------------------------------------------------------------
# Backup (consistent copy of the database via the SQLite backup API)
# ---------------------------------------------------------------------------
if [ "$DO_BACKUP" = 1 ]; then
  if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" = "true" ]; then
    step "Creating backup"
    ts="$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    out="$BACKUP_DIR/samaudit-${OLD_VERSION:-old}-$ts.tgz"
    # The backup is built in memory inside the container and streamed out directly as .tgz
    # (docker cp cannot read /tmp inside the container because it is a tmpfs there).
    (umask 077; docker exec -u 10001:10001 "$CONTAINER" python -c "
import io, os, sqlite3, sys, tarfile, time
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w:gz') as tar:
    def add(name, data):
        ti = tarfile.TarInfo(name); ti.size = len(data); ti.mtime = int(time.time()); ti.mode = 0o600
        tar.addfile(ti, io.BytesIO(data))
    for db in ('/app/data/samaudit.db', '/app/data/adaudit.db'):
        if os.path.exists(db):
            src = sqlite3.connect(db); mem = sqlite3.connect(':memory:')
            src.backup(mem)                      # consistent copy, even while running
            add('samaudit.db', mem.serialize()); mem.close(); src.close()
            break
    if os.path.isdir('/app/data/tls'):
        tar.add('/app/data/tls', arcname='tls')
sys.stdout.buffer.write(buf.getvalue())
" > "$out") || { rm -f "$out"; die "Backup failed – aborting (without backup: ./update.sh --no-backup)."; }
    tar tzf "$out" >/dev/null 2>&1 || { rm -f "$out"; die "Backup is unreadable – aborting (without backup: ./update.sh --no-backup)."; }
    echo "   $out ($(du -h "$out" | cut -f1)) – contains reports and certificate keys, treat as confidential."
    # keep only the most recent backups
    { ls -1t "$BACKUP_DIR"/samaudit-*.tgz 2>/dev/null || true; } | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f
  else
    echo "${c_dim}(container not running – no backup needed/possible)${c_off}"
  fi
fi

# ---------------------------------------------------------------------------
# Build and start
# ---------------------------------------------------------------------------
if [ "$RESTART_ONLY" = 1 ] || [ "$PULL" = 1 ]; then
  docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || die "Image $IMAGE is missing – run sh update.sh (or sh update.sh --pull) first."
else
  resolve_base
  step "Building image samaudit:$APP_VERSION"
  docker build $NO_CACHE --build-arg "PYTHON_IMAGE=$BASE_IMAGE" --build-arg "APP_VERSION=$APP_VERSION" \
    --build-arg "SECURITY_UPDATES=$(date +%Y%m%d)" \
    -t "samaudit:$APP_VERSION" . \
    || die "Build failed (see above). The running container is unchanged."
fi

# ---------------------------------------------------------------------------
# Remove the host firewall of earlier versions (samaudit-firewall.sh no longer exists)
# ---------------------------------------------------------------------------
remove_old_firewall() {
  local SUDO=""
  if [ "$(id -u)" != 0 ]; then command -v sudo >/dev/null && SUDO=sudo || return 0; fi
  local found=0
  if [ -f /etc/systemd/system/samaudit-firewall.service ]; then
    found=1
    $SUDO systemctl disable samaudit-firewall >/dev/null 2>&1 || true
    $SUDO systemctl stop samaudit-firewall >/dev/null 2>&1 || true
    $SUDO rm -f /etc/systemd/system/samaudit-firewall.service
    $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
    $SUDO systemctl reset-failed samaudit-firewall >/dev/null 2>&1 || true
  fi
  if command -v iptables >/dev/null; then
    local ch tbl
    for ch in DOCKER-USER FORWARD; do
      while $SUDO iptables -C "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS 2>/dev/null; do found=1; $SUDO iptables -D "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS; done
    done
    while $SUDO iptables -C INPUT -i "$BRIDGE" -j SAMAUDIT-HOST 2>/dev/null; do found=1; $SUDO iptables -D INPUT -i "$BRIDGE" -j SAMAUDIT-HOST; done
    for tbl in SAMAUDIT-EGRESS SAMAUDIT-HOST; do
      if $SUDO iptables -L "$tbl" -n >/dev/null 2>&1; then found=1; $SUDO iptables -F "$tbl" 2>/dev/null || true; $SUDO iptables -X "$tbl" 2>/dev/null || true; fi
    done
  fi
  if command -v ip6tables >/dev/null; then
    for ch in DOCKER-USER FORWARD; do
      while $SUDO ip6tables -C "$ch" -i "$BRIDGE" -j DROP 2>/dev/null; do found=1; $SUDO ip6tables -D "$ch" -i "$BRIDGE" -j DROP; done
    done
  fi
  rm -f .firewall-targets
  [ "$found" = 1 ] && echo "   Host firewall of earlier versions removed (rules and systemd unit samaudit-firewall)."
  return 0
}
remove_old_firewall

step "Starting container"
start_container "$IMAGE"

step "Health check"
status=""
for ((i = 0; i < HEALTH_TIMEOUT; i += 3)); do
  status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)"
  case "$status" in
    healthy) break ;;
    unhealthy|exited|dead|missing|restarting) break ;;
    running) [ "$i" -ge 15 ] && { status=healthy; break; } ;;   # image without health check
  esac
  sleep 3
done
if [ "$status" != "healthy" ]; then
  docker logs --tail 40 "$CONTAINER" || true
  rollback
  [ -n "$(ls -1 data/samaudit.db.vor-*.bak 2>/dev/null | head -1)" ] && \
    echo "   Note: if the new version changed the database, a copy from before is in data/samaudit.db.vor-*.bak"
  die "New container is not ready (status: $status, log above). The previous version keeps running."
fi
NEW_VERSION="$(running_version)"
echo "   ${c_ok}running${c_off} – version $NEW_VERSION"
# app log messages that are worth showing (the app logs in German)
docker logs --since 5m "$CONTAINER" 2>&1 | grep -E "ERROR|Konfiguration:|Zertifikat" | tail -5 || true

trap - INT TERM HUP
docker rm -f "$CONTAINER-old" >/dev/null 2>&1 || true   # previous version no longer needed

# ---------------------------------------------------------------------------
# Clean-up: keep only the most recent image versions (for a rollback)
# ---------------------------------------------------------------------------
if [ "$RESTART_ONLY" = 0 ] && [ "$PULL" = 0 ]; then
step "Removing old images"
mapfile -t old < <(docker image ls samaudit --format '{{.CreatedAt}}\t{{.Repository}}:{{.Tag}}' | grep -v '<none>' \
                   | sort -r | cut -f2 | tail -n +$((KEEP_IMAGES + 1)))
for img in "${old[@]}"; do
  [ "$img" = "samaudit:$APP_VERSION" ] && continue
  docker image rm "$img" >/dev/null 2>&1 && echo "   removed: $img" || true
done
docker image prune -f --filter "label=org.opencontainers.image.title=SAMAUDIT" >/dev/null 2>&1 || true
elif [ "$PULL" = 1 ]; then
  # older pulled versions become untagged ("dangling") – remove them
  docker image prune -f --filter "label=org.opencontainers.image.title=SAMAUDIT" >/dev/null 2>&1 || true
fi

host="$(env_get PUBLIC_HOSTNAME)"; port="$(env_get PORT)"
scheme=https; [ "$(env_get TLS_ENABLED | tr 'A-Z' 'a-z')" = "false" ] && scheme=http
echo
echo "${c_ok}Done.${c_off} SAMAUDIT $NEW_VERSION is running: $scheme://${host:-<server>}:${port:-9400}"

# ---------------------------------------------------------------------------
# After a package update: confirm the result, clean up ZIP files
# ---------------------------------------------------------------------------
if [ ${#CLEANUP_ZIPS[@]} -gt 0 ]; then
  echo
  echo "Update ${FROM_VERSION:-} → $NEW_VERSION completed and verified."
  YES=0  # always ask here if someone is at the terminal
  if [ -t 0 ]; then
    if ask "Delete the uploaded ZIP file(s) now?" Y; then
      for z in "${CLEANUP_ZIPS[@]}"; do [ -f "$z" ] && rm -f "$z" && echo "   deleted: $(basename "$z")"; done
    else
      echo "   ZIP file(s) kept."
    fi
  fi
  rm -rf "$INSTALL_DIR"/.update-* 2>/dev/null || true
  echo "Rollback if needed: restore the program files from backups/program-*.tgz and run ./update.sh."
fi
