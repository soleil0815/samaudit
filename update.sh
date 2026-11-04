#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SAMAUDIT – manual update. Not needed with a container manager (Dockhand, Watchtower, Tugtainer …)
# or with "docker compose pull && docker compose up -d".
#
#   sh update.sh                   get the newest version (or the one set in SAMAUDIT_VERSION) and start it
#   sh update.sh --version=2.0.1   pin a specific version (written to .env); --version=latest = newest again
#   sh update.sh --load FILE       without internet: load the image file from the GitHub release (docker load) and start it
#   sh update.sh --restore [FILE]  restore a database backup (list and selection);
#                                  with --version=… start that version afterwards (going back to an older version)
#   sh update.sh --cleanup         list files of earlier versions and remove them after confirmation
#   -y                             no questions (falling back to the previous version then happens automatically)
#
# Steps: get new version → remember running image as "previous" → docker compose up -d → health check.
# If the new version does not start, the previous one runs again (a database changed in the process is
# restored from the backup "vor-<version>"). SAMAUDIT backs up the database itself when the version changes.
# Runs with /bin/sh (dash, busybox – e.g. Synology), needs Docker with Compose v2.
#
# Windows line endings (CRLF) are repaired; the "#" at the end of the line keeps the next line working even with CRLF.
if grep -q "$(printf '\r')" "$0" 2>/dev/null; then tr -d '\r' < "$0" > "$0.lf.$$" && cat "$0.lf.$$" > "$0" && rm -f "$0.lf.$$" && exec sh "$0" "$@"; echo "Please save update.sh with Unix line endings (LF)." >&2; exit 1; fi #
set -eu

YES=0; MODE=update; NEW_VERSION=""; LOAD_FILE=""; RESTORE_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1 ;;
    --version=*) NEW_VERSION="${1#--version=}"; NEW_VERSION="${NEW_VERSION#v}" ;;
    --load) shift; [ $# -gt 0 ] || { echo "--load needs a file" >&2; exit 2; }; LOAD_FILE="$1"; MODE=load ;;
    --load=*) LOAD_FILE="${1#--load=}"; MODE=load ;;
    --restore) MODE=restore; if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then shift; RESTORE_FILE="$1"; fi ;;
    --restore=*) MODE=restore; RESTORE_FILE="${1#--restore=}" ;;
    --cleanup) MODE=cleanup ;;
    -h|--help) sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --pull) ;;                                    # earlier invocation – now the same as the default
    --pull=*) NEW_VERSION="${1#--pull=}"; NEW_VERSION="${NEW_VERSION#v}" ;;
    *.zip|*.ZIP) echo "ZIP packages no longer exist – SAMAUDIT comes as a ready-made image. Simply run: sh update.sh" >&2; exit 2 ;;
    *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
# relative path to the image file: relative to where the script was called from
case "$LOAD_FILE" in ""|/*) ;; *) LOAD_FILE="$PWD/$LOAD_FILE" ;; esac

cd "$(dirname "$0")"
INSTALL_DIR="$(pwd -P)"
CONTAINER=samaudit
SERVICE=samaudit
NETWORK=samaudit-net
BRIDGE=br-samaudit
DEFAULT_REPO=ghcr.io/soleil0815/samaudit
HEALTH_TIMEOUT="${SAMAUDIT_HEALTH_TIMEOUT:-180}"
ROOT="${SAMAUDIT_TEST_ROOT:-}"        # self-tests only: stand-in for "/" (never the real /etc)
NL='
'

# --------------------------------------------------------------------------- helpers
if [ -t 1 ]; then c_ok="$(printf '\033[32m')"; c_warn="$(printf '\033[33m')"; c_err="$(printf '\033[31m')"; c_off="$(printf '\033[0m')"
else c_ok=""; c_warn=""; c_err=""; c_off=""; fi
step() { printf '\n%s==>%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%sNOTE:%s %s\n' "$c_warn" "$c_off" "$*"; }
die()  { printf '%sERROR:%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }
ask() {  # ask "question" Y|N (default answer) → 0 = yes; with -y always yes
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "Cannot ask (no terminal). Run with -y to skip questions."
  if [ "$2" = Y ]; then printf '%s [Y/n] ' "$1"; else printf '%s [y/N] ' "$1"; fi
  read -r a || a=""
  case "$a" in [jJyY]*) return 0 ;; "") [ "$2" = Y ] ;; *) return 1 ;; esac
}
ask_strict() {  # security-relevant: -y does not answer this
  [ -t 0 ] || return 1
  printf '%s [y/N] ' "$1"; read -r a || a=""
  case "$a" in [jJyY]*) return 0 ;; *) return 1 ;; esac
}
valid_tag() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; }

strip_cr() {  # strip_cr FILE – remove Windows line endings (file/link stays the same, permissions stay)
  tmp="$(mktemp "$INSTALL_DIR/.cr.XXXXXX")"
  tr -d '\r' < "$1" > "$tmp" && cat "$tmp" > "$1"; rm -f "$tmp"
}
env_get() {  # env_get NAME → value from .env (without comment, without quotes)
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | tail -n 1 \
    | sed -e 's/[[:space:]]#.*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/" -e 's/[[:space:]]*$//'
}
env_set() {  # env_set NAME VALUE – replace or append line(s); .env stays the same file (also as a link)
  tmp="$(mktemp "$INSTALL_DIR/.env.tmp.XXXXXX")"
  awk -v k="$1" -v v="$2" '
    { line = $0; sub(/^[ \t]*#?[ \t]*/, "", line)
      if (index(line, k) == 1) { rest = substr(line, length(k) + 1); sub(/^[ \t]*/, "", rest)
        if (substr(rest, 1, 1) == "=") { print k "=" v; done = 1; next } }
      print }
    END { if (!done) { print ""; print k "=" v } }' .env > "$tmp" && cat "$tmp" > .env
  rm -f "$tmp"
}

command -v docker >/dev/null 2>&1 || die "docker is not installed."
docker info >/dev/null 2>&1 || die "No access to Docker – run with sudo or add the user to the 'docker' group."
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  cv="$(docker-compose version --short 2>/dev/null || true)"
  case "$cv" in 1.*|"") die "docker-compose ${cv:-?} is too old – Docker Compose v2 (docker compose) is required." ;; esac
  COMPOSE="docker-compose"
else die "Docker Compose is missing (docker compose or docker-compose)."; fi
compose() { $COMPOSE "$@"; }

if [ -f .env ] && grep -q "$(printf '\r')" .env; then strip_cr .env; echo "Windows line endings in .env repaired."; fi

REPO="$(env_get SAMAUDIT_IMAGE)"; REPO="${REPO:-$DEFAULT_REPO}"
container_exists() { docker inspect "$CONTAINER" >/dev/null 2>&1; }
label_of() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true; }
health_of() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing; }
image_version() { docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true; }
compose_file_version() { sed -n 's/^[[:space:]]*SAMAUDIT_COMPOSE:[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}.*/\1/p' "$1" 2>/dev/null | head -n 1; }
volume_lines() { grep -E '^[[:space:]]*-[[:space:]].*:/app/(data|certs)' "$1" 2>/dev/null | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//' || true; }

wait_healthy() {  # 0 = healthy
  i=0
  while [ "$i" -lt "$HEALTH_TIMEOUT" ]; do
    st="$(health_of)"
    case "$st" in
      healthy) return 0 ;;
      unhealthy|exited|dead|missing) return 1 ;;
    esac
    sleep 3; i=$((i + 3))
  done
  return 1
}

realpath_of() {  # fully resolved path (links, ..), even without read permission on the target; empty = unknown
  r="$(readlink -f "$1" 2>/dev/null || true)"
  if [ -z "$r" ]; then
    if [ -d "$1" ]; then r="$( (cd -P "$1" 2>/dev/null && pwd -P) || true)"
    else d="$( (cd -P "$(dirname "$1")" 2>/dev/null && pwd -P) || true)"; [ -n "$d" ] && r="$d/$(basename "$1")"; fi
  fi
  printf '%s\n' "$r"
}

# Who owns the container? Do not touch another Compose installation (e.g. a stack in Dockhand).
check_owner() {
  container_exists || return 0
  wd="$(label_of "$CONTAINER" com.docker.compose.project.working_dir)"
  if [ -n "$wd" ] && [ "$(realpath_of "$wd")" != "$INSTALL_DIR" ] && [ "$wd" != "$INSTALL_DIR" ]; then
    die "The container $CONTAINER belongs to another Compose installation ($wd), e.g. a stack in
       Dockhand/Portainer. Please update it there – or run this script in that folder."
  fi
}

# --------------------------------------------------------------------------- cleanup (--cleanup)
# Files of earlier versions (ZIP route, building on the host, host firewall). Only in a SAMAUDIT folder, only
# known names. Data, backups, settings, Compose files and everything a container mounts from the
# folder are protected – also via links and mount points. When in doubt, nothing is deleted.
CLEAN_FILES="Dockerfile entrypoint.sh run.py requirements.txt requirements.in requirements-dev.txt requirements-dev.in
requirements.txt.new .dockerignore .gitattributes .gitignore .trivyignore README.md README.en.md LICENSE NOTICE
THIRD-PARTY-NOTICES.md DATENSCHUTZ.md SECURITY.md CHANGELOG-SECURITY.md .samaudit-manifest base-image.lock .env.run
.firewall-targets samaudit-firewall.sh docker-compose.override.example.yml docker-compose.example.yml"

is_samaudit_dir() {  # subfolder with program files, recognised by its content
  case "$1" in
    app) grep -qs 'APP_NAME = "SAMAUDIT"' app/version.py ;;
    tools) [ -f tools/clean-history.sh ] || [ -f tools/lockutil.py ] || [ -f tools/update-locks.sh ] ;;
    tests) [ -f tests/smoke.py ] ;;
    locks) [ -f locks/os-packages.txt ] ;;
    .github) [ -f .github/workflows/docker-image.yml ] ;;
    *) return 1 ;;
  esac
}

protected_paths() {  # one line per protected path (resolved AND as written in the folder)
  for p in data backups certs .env .env.example docker-compose.yml docker-compose.override.yml docker-compose.yml.alt update.sh; do
    printf '%s/%s\n' "$INSTALL_DIR" "$p"
    if [ -e "$p" ] || [ -L "$p" ]; then r="$(realpath_of "$p")"; [ -n "$r" ] && printf '%s\n' "$r"; fi
  done
  # folders that containers (also stopped ones) mount from this folder
  ids="$(docker ps -aq)" || return 1
  for c in $ids; do
    docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null || true
  done | while IFS= read -r m; do
    [ -n "$m" ] || continue
    r="$(realpath_of "$m")"; [ -n "$r" ] || r="$m"
    case "$r" in "$INSTALL_DIR"|"$INSTALL_DIR"/*) printf '%s\n' "$r" ;; esac
  done
  # mount points below the folder (rm -r would otherwise descend into them); /proc/mounts encodes spaces as \040
  if [ -r "${ROOT}/proc/mounts" ]; then
    awk '{ p = $2
           while (match(p, /\\[0-7][0-7][0-7]/)) {
             o = substr(p, RSTART + 1, 3); c = (substr(o,1,1) * 64) + (substr(o,2,1) * 8) + substr(o,3,1)
             p = substr(p, 1, RSTART - 1) sprintf("%c", c) substr(p, RSTART + 4) }
           print p }' "${ROOT}/proc/mounts" | while IFS= read -r m; do
      case "$m" in "$INSTALL_DIR"/*) printf '%s\n' "$m" ;; esac
    done
  fi
}

overlaps() {  # overlaps A B → 0 if A equals B or one lies inside the other
  case "$1/" in "$2"/*) return 0 ;; esac
  case "$2/" in "$1"/*) return 0 ;; esac
  return 1
}

cleanup() {
  { [ -e .git ] || [ -L .git ]; } && die "This is a Git working copy (.git) – a developer folder; --cleanup does not clean up anything here."
  if ! grep -qs 'SAMAUDIT_COMPOSE' docker-compose.yml && [ ! -f .samaudit-manifest ] \
     && ! grep -qs 'APP_NAME = "SAMAUDIT"' app/version.py; then
    die "This is not a SAMAUDIT folder (no SAMAUDIT docker-compose.yml, no program files) – nothing cleaned up."
  fi
  prot="$(protected_paths)" || die "Could not fully determine the protected paths (is Docker reachable?) – nothing deleted."
  case "$NL$prot$NL" in *"$NL$INSTALL_DIR/data$NL"*) ;; *) die "Protection list incomplete – nothing deleted." ;; esac

  list=""; skipped=""
  add() { list="$list$1$NL"; }
  for f in $CLEAN_FILES; do { [ -e "$f" ] || [ -L "$f" ]; } && add "$f"; done
  for d in app tools tests locks .github; do
    if [ -L "$d" ]; then add "$d"
    elif [ -d "$d" ]; then
      if is_samaudit_dir "$d"; then add "$d"; else skipped="$skipped  $d/ (not recognised as a SAMAUDIT folder)$NL"; fi
    fi
  done
  for f in .update-* update.sh.new.[0-9]* docker-compose.yml.new.[0-9]* .env.example.new.[0-9]* \
           samaudit*.zip SAMAUDIT*.zip Samaudit*.zip samaudit*.ZIP SAMAUDIT*.ZIP; do
    { [ -e "$f" ] || [ -L "$f" ]; } || continue
    case "$f" in *"$NL"*) skipped="$skipped  (name with a line break skipped)$NL"; continue ;; esac
    add "$f"
  done
  # version folders: unpacked packages of earlier versions (recognised by app/version.py) – never with data inside
  for d in samaudit* SAMAUDIT* Samaudit*; do
    [ -d "$d" ] && [ ! -L "$d" ] && grep -qs 'APP_NAME = "SAMAUDIT"' "$d/app/version.py" || continue
    case "$d" in *"$NL"*) continue ;; esac
    if [ -e "$d/data" ] || [ -n "$(find "$d" \( -name '*.db' -o -name '*.tgz' -o -name '.env' \) 2>/dev/null | head -n 1)" ]; then
      skipped="$skipped  $d/ (contains data or settings)$NL"; continue
    fi
    add "$d"
  done
  list="$(printf '%s' "$list" | sort -u)"

  ok=""
  set -f; OLDIFS="$IFS"; IFS="$NL"
  for f in $list; do
    [ -n "$f" ] || continue
    case "$f" in */*|..|.|-*) skipped="$skipped  $f (unsafe name)$NL"; continue ;; esac
    if [ -L "$f" ]; then ok="$ok$f$NL"; continue; fi            # link: only the link itself is removed, never the target
    r="$(realpath_of "$f")"
    case "$r" in "$INSTALL_DIR"/*) ;; *) skipped="$skipped  $f (path cannot be determined safely)$NL"; continue ;; esac
    hit=""
    for p in $prot; do [ -n "$p" ] && overlaps "$r" "$p" && { hit="$p"; break; }; done
    if [ -n "$hit" ]; then skipped="$skipped  $f (protected: contains or is $hit)$NL"; continue; fi
    if [ -d "$f" ] && [ "$(find "$f" -xdev 2>/dev/null | wc -l)" != "$(find "$f" 2>/dev/null | wc -l)" ]; then
      skipped="$skipped  $f (contains a mounted drive)$NL"; continue
    fi
    ok="$ok$f$NL"
  done
  IFS="$OLDIFS"; set +f

  unit="${ROOT}/etc/systemd/system/samaudit-firewall.service"
  [ -f "$unit" ] && has_unit=1 || has_unit=0
  old_containers="$(for c in samaudit-old samaudit-alt; do docker inspect "$c" >/dev/null 2>&1 && echo "$c"; done; true)"
  old_images="$(docker image ls --format '{{.Repository}}:{{.Tag}}' samaudit 2>/dev/null | grep -v '<none>' || true)"

  if [ -z "$ok" ] && [ "$has_unit" = 0 ] && [ -z "$old_containers" ] && [ -z "$old_images" ]; then
    echo "Nothing to clean up – only docker-compose.yml, .env and the data are left here."
    [ -n "$skipped" ] && printf 'Left untouched:\n%s' "$skipped"
    return 0
  fi
  echo "No longer needed (program files of earlier versions):"
  printf '%s' "$ok" | sed 's/^/  /'
  [ "$has_unit" = 1 ] && echo "  system service samaudit-firewall (host firewall of earlier versions, may need sudo)"
  [ -n "$old_containers" ] && printf '%s\n' "$old_containers" | sed 's/^/  container /'
  [ -n "$old_images" ] && printf '%s\n' "$old_images" | sed 's/^/  locally built image /'
  [ -n "$skipped" ] && printf '\nLeft untouched:\n%s' "$skipped"
  echo
  echo "Always kept: .env, docker-compose.yml (+ .override/.alt), data/, backups/, certs/, update.sh."
  ask "Delete these entries now?" N || { echo "Cancelled – nothing deleted."; return 0; }

  printf '%s' "$ok" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ -L "$f" ]; then rm -f -- "$f"; else rm -rf -- "$f"; fi
    echo "  removed: $f"
  done
  for c in $old_containers; do docker rm -f "$c" >/dev/null 2>&1 && echo "  removed: container $c"; done
  for i in $old_images; do docker image rm "$i" >/dev/null 2>&1 && echo "  removed: image $i" || echo "  not removed (in use): $i"; done
  if [ "$has_unit" = 1 ]; then
    SUDO=""; [ "$(id -u)" = 0 ] || { command -v sudo >/dev/null 2>&1 && SUDO=sudo; }
    if [ -n "$ROOT" ]; then rm -f "$unit"
    else
      $SUDO systemctl disable --now samaudit-firewall >/dev/null 2>&1 || true
      $SUDO rm -f "$unit" && $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
      if command -v iptables >/dev/null 2>&1; then
        for ch in DOCKER-USER FORWARD; do
          while $SUDO iptables -C "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS 2>/dev/null; do $SUDO iptables -D "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS; done
        done
        while $SUDO iptables -C INPUT -i "$BRIDGE" -j SAMAUDIT-HOST 2>/dev/null; do $SUDO iptables -D INPUT -i "$BRIDGE" -j SAMAUDIT-HOST; done
        for t in SAMAUDIT-EGRESS SAMAUDIT-HOST; do $SUDO iptables -F "$t" 2>/dev/null || true; $SUDO iptables -X "$t" 2>/dev/null || true; done
      fi
    fi
    echo "  removed: system service samaudit-firewall"
  fi
  echo "Done."
}

# --------------------------------------------------------------------------- files from the image
# The image ships docker-compose.yml, .env.example and update.sh (/app/dist).
take_files_from_image() {  # take_files_from_image IMAGE
  tmpd="$(mktemp -d)"
  cid="$(docker create "$1" 2>/dev/null)" || { rm -rf "$tmpd"; return 0; }
  docker cp "$cid:/app/dist/." "$tmpd/" >/dev/null 2>&1 || true
  docker rm -f "$cid" >/dev/null 2>&1 || true
  if [ -f "$tmpd/docker-compose.yml" ]; then
    new_v="$(compose_file_version "$tmpd/docker-compose.yml")"
    if [ ! -f docker-compose.yml ]; then
      cp "$tmpd/docker-compose.yml" docker-compose.yml
      echo "   docker-compose.yml created (version $new_v)"
    else
      old_v="$(compose_file_version docker-compose.yml)"
      if [ "${new_v:-0}" -gt "${old_v:-0}" ]; then
        if [ "$(volume_lines docker-compose.yml)" != "$(volume_lines "$tmpd/docker-compose.yml")" ]; then
          # the current file mounts other folders – do not replace it, or SAMAUDIT would run on empty data
          cp "$tmpd/docker-compose.yml" docker-compose.yml.neu
          warn "The image contains a newer docker-compose.yml (version $new_v), but your file mounts other folders.
         It was NOT replaced; the new one is saved next to it as docker-compose.yml.neu. Please move your own
         paths into a docker-compose.override.yml, then rename docker-compose.yml.neu → docker-compose.yml."
        else
          cp -p docker-compose.yml docker-compose.yml.alt
          cp "$tmpd/docker-compose.yml" docker-compose.yml.new.$$ && mv -f docker-compose.yml.new.$$ docker-compose.yml
          warn "New docker-compose.yml (version ${old_v:-none} → $new_v) installed; the previous one is kept as docker-compose.yml.alt.
         Please move your own changes into docker-compose.override.yml."
        fi
      fi
    fi
  fi
  [ -f "$tmpd/.env.example" ] && cp "$tmpd/.env.example" .env.example.new.$$ && mv -f .env.example.new.$$ .env.example
  if [ -f "$tmpd/update.sh" ] && ! cmp -s "$tmpd/update.sh" update.sh; then
    cp "$tmpd/update.sh" update.sh.new && chmod 644 update.sh.new
    echo "   The image contains a newer update.sh (saved as update.sh.new; differences: diff update.sh update.sh.new)."
    # update.sh runs with your permissions on the host – never replace it without asking (not even with -y)
    if ask_strict "   Use the new update.sh now (takes effect from the next run)?"; then
      mv -f update.sh.new update.sh && chmod 755 update.sh && echo "   update.sh replaced."
    fi
  fi
  rm -rf "$tmpd"
}

# --------------------------------------------------------------------------- migration from update.sh ≤ 1.9
# update.sh used to start the container with "docker run". Once: create the Compose file, move
# DOCKER_DNS/DOCKER_EXTRA_HOSTS into the override file, set the old container aside (for falling
# back) and detach it from its network definition (Compose creates the network itself).
legacy_check_mount() {
  src="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null || true)"
  [ -n "$src" ] || return 0
  if [ "$(realpath_of "$src")" != "$INSTALL_DIR/data" ] && [ "$src" != "$INSTALL_DIR/data" ]; then
    die "The running container $CONTAINER uses the data from $src, not from $INSTALL_DIR/data.
       Please run update.sh in the folder of the existing installation – nothing is changed here."
  fi
}
migrate_legacy() {
  if [ ! -f docker-compose.override.yml ]; then
    dns="$(env_get DOCKER_DNS | tr ',;' '  ')"; hosts="$(env_get DOCKER_EXTRA_HOSTS | tr ',;' '  ')"
    if [ -n "$dns$hosts" ]; then
      {
        echo "# Your own additions to docker-compose.yml (taken over from DOCKER_DNS / DOCKER_EXTRA_HOSTS in .env)"
        echo "services:"
        echo "  $SERVICE:"
        if [ -n "$dns" ]; then echo "    dns:"; for d in $dns; do echo "      - \"$d\""; done; fi
        if [ -n "$hosts" ]; then echo "    extra_hosts:"; for h in $hosts; do echo "      - \"$h\""; done; fi
      } > docker-compose.override.yml
      echo "   DOCKER_DNS/DOCKER_EXTRA_HOSTS → moved to docker-compose.override.yml"
    fi
  fi
  if grep -Eq "^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^'[:space:]][^#]*[\$]" .env 2>/dev/null; then
    warn "A value in .env contains a \$ sign. Docker Compose would read it as a variable –
         please put such values in single quotes, e.g. TLS_PFX_PASSWORD='ab\$cd'."
  fi
  for c in "$CONTAINER-old" "$CONTAINER-alt"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker stop "$CONTAINER" >/dev/null 2>&1 || true
  docker rename "$CONTAINER" "$CONTAINER-alt" || die "Could not set the existing container aside – nothing changed."
  docker update --restart=no "$CONTAINER-alt" >/dev/null 2>&1 || true
  docker network disconnect -f "$NETWORK" "$CONTAINER-alt" >/dev/null 2>&1 || true
  LEGACY_ASIDE=1
  echo "   existing container (started with docker run) set aside – data stays"
}
legacy_back() {  # migration failed: start the old container again as before
  [ "${LEGACY_ASIDE:-0}" = 1 ] || return 1
  step "Starting the existing installation again"
  compose down >/dev/null 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network inspect "$NETWORK" >/dev/null 2>&1 || \
    docker network create --driver bridge -o "com.docker.network.bridge.name=$BRIDGE" "$NETWORK" >/dev/null 2>&1 || true
  docker network connect "$NETWORK" "$CONTAINER-alt" >/dev/null 2>&1 || true
  docker rename "$CONTAINER-alt" "$CONTAINER" && docker update --restart=unless-stopped "$CONTAINER" >/dev/null 2>&1 || true
  docker start "$CONTAINER" >/dev/null 2>&1 || true
  LEGACY_ASIDE=0
  wait_healthy && { echo "   the existing installation is running again."; return 0; }
  warn "The existing installation does not start either – please check: docker ps -a"
  return 1
}
drop_foreign_network() {  # network created by update.sh ≤ 1.9: Compose wants to manage it itself
  docker network inspect "$NETWORK" >/dev/null 2>&1 || return 0
  [ -n "$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$NETWORK" 2>/dev/null || true)" ] && return 0
  docker network rm "$NETWORK" >/dev/null 2>&1 || warn "Could not remove Docker network $NETWORK (still in use?)."
}

# --------------------------------------------------------------------------- rollback
# Afterwards the previous version runs under its own version number (pinned in .env) –
# so a later "docker compose up -d" or a container manager does not start the broken one either.
rollback() {
  step "Starting the previous version again"
  [ -n "$OLD_ID" ] || { warn "No previous version available."; return 1; }
  compose stop "$SERVICE" >/dev/null 2>&1 || true
  # has the new version already taken over the database? then restore its backup "vor-…"
  SAMAUDIT_VERSION="$TAG" compose run --rm --no-deps -T --name "$CONTAINER-restore" "$SERVICE" restore --rollback "$START" \
    || warn "Could not restore the database automatically (see above) – if needed: sh update.sh --restore."
  back_tag="$OLD_VER"; valid_tag "$back_tag" || back_tag="${ENV_TAG_BEFORE:-latest}"
  [ "$back_tag" = previous ] && back_tag=latest
  docker tag "$OLD_ID" "$REPO:$back_tag"
  env_set SAMAUDIT_VERSION "$back_tag"
  ROLLED_BACK=1
  compose up -d >/dev/null 2>&1 || true
  if wait_healthy; then
    echo "   previous version $back_tag is running again."
    [ "$back_tag" != "${ENV_TAG_BEFORE:-latest}" ] && \
      echo "   SAMAUDIT_VERSION=$back_tag is now pinned in .env – once the problem is fixed, set it back to ${ENV_TAG_BEFORE:-latest}."
    return 0
  fi
  warn "The previous version does not start either – please check the log: docker logs $CONTAINER"
  return 1
}

# On abort leave nothing half-done: restore .env, start the stopped service again
ENV_CHANGED=0; STOPPED=0; ROLLED_BACK=0; LEGACY_ASIDE=0
on_exit() {
  rc=$?
  [ "$rc" = 0 ] && return 0
  if [ "$ENV_CHANGED" = 1 ] && [ "$ROLLED_BACK" = 0 ]; then
    env_set SAMAUDIT_VERSION "${ENV_TAG_BEFORE:-latest}"
    echo "   SAMAUDIT_VERSION in .env set back to ${ENV_TAG_BEFORE:-latest}."
  fi
  if [ "$LEGACY_ASIDE" = 1 ]; then legacy_back || true
  elif [ "$STOPPED" = 1 ] && [ "$ROLLED_BACK" = 0 ] && [ "$(health_of)" != healthy ]; then
    echo "   starting the previous version again …"; compose up -d >/dev/null 2>&1 || true
  fi
  exit "$rc"
}

# --------------------------------------------------------------------------- main flow
if [ "$MODE" = cleanup ]; then cleanup; exit 0; fi

if [ ! -f .env ]; then
  if [ -f .env.example ]; then cp .env.example .env; chmod 600 .env
    die ".env was missing and has been created from .env.example. Please set at least DOMAIN_FQDN and run again."
  fi
  die ".env is missing. Please download .env.example, save it as .env and fill it in (at least DOMAIN_FQDN)."
fi
grep -Eq '^[[:space:]]*DOMAIN_FQDN[[:space:]]*=[[:space:]]*[^[:space:]#]' .env || warn "DOMAIN_FQDN is not set in .env."
mkdir -p data certs

check_owner
trap on_exit EXIT

ENV_TAG_BEFORE="$(env_get SAMAUDIT_VERSION)"
if [ -n "$NEW_VERSION" ]; then valid_tag "$NEW_VERSION" || die "Invalid version: $NEW_VERSION"; TAG="$NEW_VERSION"
else TAG="${ENV_TAG_BEFORE:-latest}"; fi
valid_tag "$TAG" || die "Invalid SAMAUDIT_VERSION in .env: $TAG"
[ "$TAG" = previous ] && die "The version 'previous' is reserved – please enter a version number or latest."

restore_now() {  # restore with the current image (the newer one certainly knows "restore")
  [ -f docker-compose.yml ] || die "docker-compose.yml is missing – run sh update.sh once first."
  step "Restoring backup"
  compose stop "$SERVICE" || true
  STOPPED=1
  if [ -n "$RESTORE_FILE" ]; then
    SAMAUDIT_VERSION="${ENV_TAG_BEFORE:-latest}" compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore "$(basename "$RESTORE_FILE")"
  else
    SAMAUDIT_VERSION="${ENV_TAG_BEFORE:-latest}" compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore
  fi || die "Nothing was restored (see above)."
}

if [ "$MODE" = restore ] && [ -z "$NEW_VERSION" ]; then
  restore_now
  compose up -d
  wait_healthy && echo "${c_ok}SAMAUDIT is running.${c_off}" || die "SAMAUDIT is not ready (status: $(health_of)) – docker logs $CONTAINER"
  STOPPED=0
  exit 0
fi

OLD_ID=""; OLD_VER=""
if container_exists; then
  OLD_ID="$(docker inspect -f '{{.Image}}' "$CONTAINER")"
  OLD_VER="$(image_version "$OLD_ID")"
fi

# 1) get the new version – .env is only changed once the image is there
if [ "$MODE" = load ]; then
  [ -f "$LOAD_FILE" ] || die "File not found: $LOAD_FILE"
  sums="$(dirname "$LOAD_FILE")/SHA256SUMS"
  if [ -f "$sums" ]; then
    want="$(grep -F " $(basename "$LOAD_FILE")" "$sums" | awk '{print $1}' | head -n 1)"
    if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$LOAD_FILE" | awk '{print $1}')"
    else have="$(openssl dgst -sha256 "$LOAD_FILE" 2>/dev/null | awk '{print $NF}')"; fi
    [ -n "$want" ] && [ "$want" = "$have" ] || die "Checksum mismatch (SHA256SUMS) – file damaged or wrong."
    echo "   checksum OK"
  else
    warn "No SHA256SUMS next to the file – checksum not verified."
  fi
  step "Loading image: $(basename "$LOAD_FILE")"
  out="$(docker load -i "$LOAD_FILE")" || die "Could not load the image."
  printf '%s\n' "$out"
  loaded="$(printf '%s\n' "$out" | sed -n 's/^Loaded image: //p' | grep -F "$REPO:" | head -n 1)"
  [ -n "$loaded" ] || die "The file does not contain an image of $REPO."
  TAG="${loaded##*:}"
  valid_tag "$TAG" && [ "$TAG" != previous ] || die "Invalid version in the image file: $TAG"
else
  step "Pulling image: $REPO:$TAG"
  docker pull "$REPO:$TAG" || die "Could not pull image $REPO:$TAG (does the version exist? private repository? Then once:
       docker login ghcr.io -u <GitHub user> – password: token with read:packages, not shown while typing)."
fi
NEW_ID="$(docker image inspect -f '{{.Id}}' "$REPO:$TAG")"
NEW_VER="$(image_version "$REPO:$TAG")"
echo "SAMAUDIT: current ${OLD_VER:-–}  →  new ${NEW_VER:-$TAG}"

# 2) with --restore --version=…: restore now (the new image is already there)
[ "$MODE" = restore ] && restore_now

# 3) version into .env
if [ "$TAG" != "${ENV_TAG_BEFORE:-latest}" ] || { [ -n "$NEW_VERSION$LOAD_FILE" ] && [ -z "$ENV_TAG_BEFORE" ]; }; then
  env_set SAMAUDIT_VERSION "$TAG"; ENV_CHANGED=1
  echo "   SAMAUDIT_VERSION=$TAG (in .env)"
fi

# 4) Compose file (and templates) from the image
take_files_from_image "$REPO:$TAG"
[ -f docker-compose.yml ] || die "docker-compose.yml is missing and is not contained in the image either."

LEGACY=0
if container_exists && [ -z "$(label_of "$CONTAINER" com.docker.compose.project)" ]; then LEGACY=1; fi
if [ "$LEGACY" = 0 ] && [ "$MODE" != restore ] && [ "$OLD_ID" = "$NEW_ID" ] && [ "$(health_of)" = healthy ]; then
  echo "SAMAUDIT ${NEW_VER:-} is up to date – nothing to do."
  ENV_CHANGED=0
  exit 0
fi

# 5) remember the running image as "previous", start
[ -n "$OLD_ID" ] && docker tag "$OLD_ID" "$REPO:previous"
if [ "$LEGACY" = 1 ]; then
  step "Switching to Docker Compose (one-time)"
  legacy_check_mount
  migrate_legacy
fi
drop_foreign_network
step "Starting"
START="$(date +%s)"
STOPPED=1
if ! compose up -d; then
  if [ "$LEGACY" = 1 ]; then legacy_back || true; die "docker compose up failed (see above). The existing installation keeps running."; fi
  if [ -n "$OLD_ID" ] && rollback; then die "docker compose up failed (see above). The previous version is running again."; fi
  die "docker compose up failed (see above)."
fi

# 6) health check
step "Health check"
if ! wait_healthy; then
  docker logs --tail 40 "$CONTAINER" 2>&1 || true
  if [ "$LEGACY" = 1 ]; then
    legacy_back && die "New version ${NEW_VER:-$TAG} is not ready (log above). The existing installation is running again."
    die "New version ${NEW_VER:-$TAG} is not ready (log above)."
  fi
  if [ -n "$OLD_ID" ] && ask "The new version does not start. Start the previous version again?" Y; then
    rollback && die "New version ${NEW_VER:-$TAG} is not ready (log above). The previous version is running again."
    die "New version ${NEW_VER:-$TAG} is not ready, and the previous one does not start either (see above)."
  fi
  die "New version ${NEW_VER:-$TAG} is not ready (status: $(health_of), log above)."
fi
STOPPED=0; ENV_CHANGED=0
echo "   ${c_ok}running${c_off} – version ${NEW_VER:-$TAG}"
# notable log lines; the German patterns match images from before the switch to English logs (e.g. after --version=2.0.0)
docker logs --since 5m "$CONTAINER" 2>&1 | grep -E "ERROR|Configuration:|Konfiguration:|Note:|Hinweis:|backed up|gesichert" | tail -n 5 || true
if [ "$LEGACY" = 1 ]; then docker rm -f "$CONTAINER-alt" >/dev/null 2>&1 || true; LEGACY_ASIDE=0; fi

# 7) clean up: SAMAUDIT images without a name (previous stays for going back)
docker image prune -f --filter "label=org.opencontainers.image.title=SAMAUDIT" >/dev/null 2>&1 || true

host="$(env_get PUBLIC_HOSTNAME)"; port="$(env_get PORT)"
scheme=https; [ "$(env_get TLS_ENABLED | tr 'A-Z' 'a-z')" = "false" ] && scheme=http
echo
echo "${c_ok}Done.${c_off} SAMAUDIT ${NEW_VER:-$TAG} is running: $scheme://${host:-<server>}:${port:-9400}"
if [ "$LEGACY" = 1 ] || [ -d app ] || [ -f Dockerfile ]; then
  echo "Program files of earlier versions are no longer needed. To clean up: sh update.sh --cleanup"
fi
