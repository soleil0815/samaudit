#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SAMAUDIT – Update von Hand. Mit einer Container-Verwaltung (Dockhand, Watchtower, Tugtainer …)
# oder "docker compose pull && docker compose up -d" wird dieses Skript nicht gebraucht.
#
#   sh update.sh                   neueste Version holen (bzw. die in SAMAUDIT_VERSION festgelegte) und starten
#   sh update.sh --version=2.0.1   bestimmte Version festlegen (wird in die .env geschrieben); --version=latest = wieder neueste
#   sh update.sh --load DATEI      ohne Internet: Image-Datei aus dem GitHub-Release laden (docker load) und starten
#   sh update.sh --restore [DATEI] Sicherung der Datenbank zurückspielen (Liste und Auswahl);
#                                  mit --version=… danach diese Version starten (Rückschritt auf eine ältere Version)
#   sh update.sh --cleanup         Dateien früherer Versionen auflisten und nach Rückfrage entfernen
#   -y                             ohne Rückfragen (Rückfall auf die vorige Version erfolgt dann automatisch)
#
# Ablauf: laufendes Image als "previous" merken → Version holen → docker compose up -d → Gesundheitscheck.
# Startet die neue Version nicht, läuft wieder die vorige (eine dabei geänderte Datenbank wird aus der
# Sicherung "vor-<Version>" zurückgespielt). Die Datenbank sichert SAMAUDIT beim Versionswechsel selbst.
# Läuft mit /bin/sh (dash, busybox – z. B. Synology), braucht Docker mit Compose v2.
#
# Windows-Zeilenenden (CRLF) werden repariert; das "#" am Zeilenende hält die nächste Zeile auch mit CRLF lauffähig.
if grep -q "$(printf '\r')" "$0" 2>/dev/null; then sed -i 's/\r$//' "$0" && exec sh "$0" "$@"; echo "Bitte ausführen: sed -i 's/\r\$//' update.sh" >&2; exit 1; fi #
set -eu

cd "$(dirname "$0")"
INSTALL_DIR="$(pwd -P)"
CONTAINER=samaudit
SERVICE=samaudit
NETWORK=samaudit-net
DEFAULT_REPO=ghcr.io/soleil0815/samaudit
HEALTH_TIMEOUT="${SAMAUDIT_HEALTH_TIMEOUT:-180}"
ROOT="${SAMAUDIT_TEST_ROOT:-}"        # nur für die Selbsttests: Ersatz für "/" (nie das echte /etc)

YES=0; MODE=update; NEW_VERSION=""; LOAD_FILE=""; RESTORE_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1 ;;
    --version=*) NEW_VERSION="${1#--version=}"; NEW_VERSION="${NEW_VERSION#v}" ;;
    --load) shift; [ $# -gt 0 ] || { echo "--load braucht eine Datei" >&2; exit 2; }; LOAD_FILE="$1"; MODE=load ;;
    --load=*) LOAD_FILE="${1#--load=}"; MODE=load ;;
    --restore) MODE=restore; if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then shift; RESTORE_FILE="$1"; fi ;;
    --restore=*) MODE=restore; RESTORE_FILE="${1#--restore=}" ;;
    --cleanup) MODE=cleanup ;;
    -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --pull) ;;                                    # früherer Aufruf – entspricht jetzt dem Standard
    --pull=*) NEW_VERSION="${1#--pull=}"; NEW_VERSION="${NEW_VERSION#v}" ;;
    *.zip|*.ZIP) echo "ZIP-Pakete gibt es nicht mehr – SAMAUDIT kommt als fertiges Image. Einfach: sh update.sh" >&2; exit 2 ;;
    *) echo "Unbekannte Option: $1 (siehe --help)" >&2; exit 2 ;;
  esac
  shift
done

# --------------------------------------------------------------------------- Hilfsfunktionen
if [ -t 1 ]; then c_ok="$(printf '\033[32m')"; c_warn="$(printf '\033[33m')"; c_err="$(printf '\033[31m')"; c_off="$(printf '\033[0m')"
else c_ok=""; c_warn=""; c_err=""; c_off=""; fi
step() { printf '\n%s==>%s %s\n' "$c_ok" "$c_off" "$*"; }
warn() { printf '%sHINWEIS:%s %s\n' "$c_warn" "$c_off" "$*"; }
die()  { printf '%sFEHLER:%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }
ask() {  # ask "Frage" J|N  → 0 = ja; mit -y immer ja
  [ "$YES" = 1 ] && return 0
  [ -t 0 ] || die "Keine Eingabe möglich (kein Terminal). Mit -y ohne Rückfragen ausführen."
  if [ "$2" = J ]; then printf '%s [J/n] ' "$1"; else printf '%s [j/N] ' "$1"; fi
  read -r a || a=""
  case "$a" in [jJyY]*) return 0 ;; "") [ "$2" = J ] ;; *) return 1 ;; esac
}
ask_strict() {  # sicherheitsrelevant: -y beantwortet das nicht
  [ -t 0 ] || return 1
  printf '%s [j/N] ' "$1"; read -r a || a=""
  case "$a" in [jJyY]*) return 0 ;; *) return 1 ;; esac
}
valid_tag() { printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'; }

env_get() {  # env_get NAME → Wert aus der .env (ohne Kommentar, ohne Anführungszeichen)
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | tail -n 1 \
    | sed -e 's/[[:space:]]#.*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/" -e 's/[[:space:]]*$//'
}
env_set() {  # env_set NAME WERT – Zeile ersetzen oder anhängen, Rechte bleiben
  if grep -Eq "^[[:space:]]*#?[[:space:]]*$1[[:space:]]*=" .env; then
    sed -i "s|^[[:space:]]*#\{0,1\}[[:space:]]*$1[[:space:]]*=.*|$1=$2|" .env
  else
    printf '\n%s=%s\n' "$1" "$2" >> .env
  fi
}

command -v docker >/dev/null 2>&1 || die "docker ist nicht installiert."
docker info >/dev/null 2>&1 || die "Kein Zugriff auf Docker – mit sudo ausführen oder den Benutzer in die Gruppe 'docker' aufnehmen."
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then COMPOSE="docker-compose"
else die "Docker Compose fehlt (docker compose bzw. docker-compose)."; fi
compose() { $COMPOSE "$@"; }

[ -f .env ] && grep -q "$(printf '\r')" .env && sed -i 's/\r$//' .env && echo "Windows-Zeilenenden in .env repariert."

REPO="$(env_get SAMAUDIT_IMAGE)"; REPO="${REPO:-$DEFAULT_REPO}"
container_exists() { docker inspect "$CONTAINER" >/dev/null 2>&1; }
label_of() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true; }
health_of() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing; }
image_version() { docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true; }
compose_file_version() { sed -n 's/^[[:space:]]*SAMAUDIT_COMPOSE:[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}.*/\1/p' "$1" 2>/dev/null | head -n 1; }

wait_healthy() {  # 0 = gesund
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

# Wem gehört der Container? Eine andere Compose-Installation (z. B. Stack in Dockhand) nicht anfassen.
check_owner() {
  container_exists || return 0
  wd="$(label_of "$CONTAINER" com.docker.compose.project.working_dir)"
  if [ -n "$wd" ] && [ "$(cd "$wd" 2>/dev/null && pwd -P || echo "$wd")" != "$INSTALL_DIR" ]; then
    die "Der Container $CONTAINER gehört zu einer anderen Compose-Installation ($wd), z. B. einem Stack in
       Dockhand/Portainer. Bitte dort aktualisieren – oder dieses Skript in jenem Ordner ausführen."
  fi
}

# --------------------------------------------------------------------------- Aufräumen (--cleanup)
# Dateien früherer Versionen (ZIP-Weg, lokaler Bau, Host-Firewall). Daten, Sicherungen, Einstellungen,
# Compose-Dateien und alles, was ein laufender Container einbindet, sind geschützt – auch über Links.
CLEAN_FILES="Dockerfile entrypoint.sh run.py requirements.txt requirements.in requirements-dev.txt requirements-dev.in
requirements.txt.new .dockerignore .gitattributes .gitignore .trivyignore README.md README.en.md LICENSE NOTICE
THIRD-PARTY-NOTICES.md DATENSCHUTZ.md SECURITY.md CHANGELOG-SECURITY.md .samaudit-manifest base-image.lock .env.run
.firewall-targets samaudit-firewall.sh docker-compose.override.example.yml docker-compose.example.yml"
CLEAN_DIRS="app tools tests locks .github"

realpath_of() {  # vollständig aufgelöster Pfad (auch für Links); leer, wenn nicht ermittelbar
  if [ -d "$1" ]; then (cd -P "$1" 2>/dev/null && pwd -P)
  else
    d="$(cd -P "$(dirname "$1")" 2>/dev/null && pwd -P)" || return 0
    b="$(basename "$1")"
    if [ -L "$1" ]; then
      t="$(readlink -f "$1" 2>/dev/null || true)"; [ -n "$t" ] && { printf '%s\n' "$t"; return 0; }
    fi
    printf '%s/%s\n' "$d" "$b"
  fi
}

protected_paths() {
  for p in data backups certs .env .env.example docker-compose.yml docker-compose.override.yml docker-compose.yml.alt update.sh; do
    [ -e "$p" ] || [ -L "$p" ] || continue
    realpath_of "$p"
    [ -L "$p" ] && printf '%s/%s\n' "$INSTALL_DIR" "$p"
  done
  # eingebundene Ordner aller Container (auch gestoppter) – nie löschen, auch nicht über Umwege
  for c in $(docker ps -aq 2>/dev/null); do
    docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null || true
  done | while IFS= read -r m; do [ -n "$m" ] && { realpath_of "$m" 2>/dev/null || printf '%s\n' "$m"; }; done
  # Einhängepunkte unterhalb des Ordners (rm -r würde sonst hineinlaufen)
  if [ -r "${ROOT}/proc/mounts" ]; then
    awk '{print $2}' "${ROOT}/proc/mounts" | while IFS= read -r m; do
      case "$m" in "$INSTALL_DIR"/*) printf '%s\n' "$m" ;; esac
    done
  fi
}

overlaps() {  # overlaps A B → 0, wenn A gleich B ist oder einer im anderen liegt
  case "$1/" in "$2"/*) return 0 ;; esac
  case "$2/" in "$1"/*) return 0 ;; esac
  return 1
}

cleanup() {
  set -f; OLDIFS="$IFS"; IFS='
'                                                   # Namen mit Leerzeichen sicher behandeln, nichts expandieren
  [ -d .git ] && die "Hier liegt eine Git-Arbeitskopie (.git) – das ist ein Entwicklerordner, --cleanup räumt hier nichts auf."
  prot="$(protected_paths | sort -u)"
  list=""
  add() { list="${list}${1}
"; }
  IFS="$OLDIFS"; set +f
  for f in $CLEAN_FILES; do { [ -e "$f" ] || [ -L "$f" ]; } && add "$f"; done
  for d in $CLEAN_DIRS; do { [ -e "$d" ] || [ -L "$d" ]; } && add "$d"; done
  for f in .update-* *.new.* samaudit*.zip SAMAUDIT*.zip Samaudit*.zip samaudit*.ZIP SAMAUDIT*.ZIP; do
    { [ -e "$f" ] || [ -L "$f" ]; } && add "$f"
  done
  # Versionsordner: entpackte Pakete früherer Versionen (erkannt an app/version.py)
  for d in samaudit* SAMAUDIT* Samaudit*; do
    [ -d "$d" ] && [ ! -L "$d" ] && [ -f "$d/app/version.py" ] && add "$d"
  done
  list="$(printf '%s' "$list" | sort -u)"
  set -f; IFS='
'

  ok=""; skipped=""
  for f in $list; do
    case "$f" in */*|..|.) skipped="$skipped  $f (unsicherer Name)
"; continue ;; esac
    if [ -L "$f" ]; then ok="$ok$f
"; continue; fi                                  # Link: nur der Link selbst wird entfernt, nie das Ziel
    r="$(realpath_of "$f")"
    case "$r" in "$INSTALL_DIR"/*) ;; *) skipped="$skipped  $f (liegt nicht im SAMAUDIT-Ordner)
"; continue ;; esac
    hit=""
    for p in $prot; do overlaps "$r" "$p" && { hit="$p"; break; }; done
    if [ -n "$hit" ]; then skipped="$skipped  $f (geschützt: enthält oder ist $hit)
"; continue; fi
    ok="$ok$f
"
  done

  IFS="$OLDIFS"; set +f
  unit="${ROOT}/etc/systemd/system/samaudit-firewall.service"
  [ -f "$unit" ] && has_unit=1 || has_unit=0
  old_containers="$(for c in samaudit-old samaudit-alt; do docker inspect "$c" >/dev/null 2>&1 && echo "$c"; done; true)"
  old_images="$(docker image ls --format '{{.Repository}}:{{.Tag}}' samaudit 2>/dev/null | grep -v '<none>' || true)"

  if [ -z "$ok" ] && [ "$has_unit" = 0 ] && [ -z "$old_containers" ] && [ -z "$old_images" ]; then
    echo "Nichts aufzuräumen – hier liegen nur noch docker-compose.yml, .env und die Daten."
    [ -n "$skipped" ] && printf 'Nicht angefasst:\n%s' "$skipped"
    return 0
  fi
  echo "Nicht mehr gebraucht (Programmdateien früherer Versionen):"
  printf '%s' "$ok" | sed 's/^/  /'
  [ "$has_unit" = 1 ] && echo "  Systemdienst samaudit-firewall (Host-Firewall früherer Versionen, braucht ggf. sudo)"
  [ -n "$old_containers" ] && printf '%s\n' "$old_containers" | sed 's/^/  Container /'
  [ -n "$old_images" ] && printf '%s\n' "$old_images" | sed 's/^/  lokal gebautes Image /'
  [ -n "$skipped" ] && printf '\nNicht angefasst:\n%s' "$skipped"
  echo
  echo "Bleibt immer: .env, docker-compose.yml (+ .override/.alt), data/, backups/, certs/, update.sh."
  ask "Diese Einträge jetzt löschen?" N || { echo "Abgebrochen – nichts gelöscht."; return 0; }

  printf '%s' "$ok" | while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ -L "$f" ]; then rm -f -- "$f"; else rm -rf -- "$f"; fi
    echo "  entfernt: $f"
  done
  for c in $old_containers; do docker rm -f "$c" >/dev/null 2>&1 && echo "  entfernt: Container $c"; done
  for i in $old_images; do docker image rm "$i" >/dev/null 2>&1 && echo "  entfernt: Image $i" || echo "  nicht entfernt (in Gebrauch): $i"; done
  if [ "$has_unit" = 1 ]; then
    SUDO=""; [ "$(id -u)" = 0 ] || { command -v sudo >/dev/null 2>&1 && SUDO=sudo; }
    if [ -n "$ROOT" ]; then rm -f "$unit"
    else
      $SUDO systemctl disable --now samaudit-firewall >/dev/null 2>&1 || true
      $SUDO rm -f "$unit" && $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
      if command -v iptables >/dev/null 2>&1; then
        for ch in DOCKER-USER FORWARD; do
          while $SUDO iptables -C "$ch" -i br-samaudit -j SAMAUDIT-EGRESS 2>/dev/null; do $SUDO iptables -D "$ch" -i br-samaudit -j SAMAUDIT-EGRESS; done
        done
        while $SUDO iptables -C INPUT -i br-samaudit -j SAMAUDIT-HOST 2>/dev/null; do $SUDO iptables -D INPUT -i br-samaudit -j SAMAUDIT-HOST; done
        for t in SAMAUDIT-EGRESS SAMAUDIT-HOST; do $SUDO iptables -F "$t" 2>/dev/null || true; $SUDO iptables -X "$t" 2>/dev/null || true; done
      fi
    fi
    echo "  entfernt: Systemdienst samaudit-firewall"
  fi
  echo "Fertig."
}

# --------------------------------------------------------------------------- Dateien aus dem Image
# Das Image bringt docker-compose.yml, .env.example und update.sh mit (/app/dist).
take_files_from_image() {  # take_files_from_image IMAGE
  tmpd="$(mktemp -d)"
  cid="$(docker create "$1" 2>/dev/null)" || { rm -rf "$tmpd"; return 0; }
  docker cp "$cid:/app/dist/." "$tmpd/" >/dev/null 2>&1 || true
  docker rm -f "$cid" >/dev/null 2>&1 || true
  if [ -f "$tmpd/docker-compose.yml" ]; then
    new_v="$(compose_file_version "$tmpd/docker-compose.yml")"
    if [ ! -f docker-compose.yml ]; then
      cp "$tmpd/docker-compose.yml" docker-compose.yml
      echo "   docker-compose.yml angelegt (Version $new_v)"
    else
      old_v="$(compose_file_version docker-compose.yml)"
      if [ "${new_v:-0}" -gt "${old_v:-0}" ]; then
        cp -p docker-compose.yml docker-compose.yml.alt
        cp "$tmpd/docker-compose.yml" docker-compose.yml.new.$$ && mv -f docker-compose.yml.new.$$ docker-compose.yml
        warn "Neue docker-compose.yml (Version ${old_v:-ohne} → $new_v) abgelegt; die bisherige liegt als docker-compose.yml.alt daneben.
         Eigene Änderungen bitte in docker-compose.override.yml übernehmen."
      fi
    fi
  fi
  [ -f "$tmpd/.env.example" ] && cp "$tmpd/.env.example" .env.example.new.$$ && mv -f .env.example.new.$$ .env.example
  if [ -f "$tmpd/update.sh" ] && ! cmp -s "$tmpd/update.sh" update.sh; then
    cp "$tmpd/update.sh" update.sh.new && chmod 644 update.sh.new
    echo "   Im Image liegt eine neuere update.sh (gespeichert als update.sh.new; Unterschiede: diff update.sh update.sh.new)."
    # update.sh läuft mit Ihren Rechten auf dem Host – nie ungefragt ersetzen (auch nicht mit -y)
    if ask_strict "   Neue update.sh jetzt übernehmen (gilt ab dem nächsten Aufruf)?"; then
      mv -f update.sh.new update.sh && chmod 755 update.sh && echo "   update.sh ersetzt."
    fi
  fi
  rm -rf "$tmpd"
}

# --------------------------------------------------------------------------- Umstieg von update.sh ≤ 1.9
# Früher startete update.sh den Container mit "docker run". Einmalig: Compose-Datei anlegen,
# DOCKER_DNS/DOCKER_EXTRA_HOSTS in die Override-Datei übernehmen, alten Container und alte
# Netz-Definition entfernen (Compose legt beides neu an). Das alte Image bleibt als "previous".
migrate_legacy() {
  if [ ! -f docker-compose.override.yml ]; then
    dns="$(env_get DOCKER_DNS | tr ',;' '  ')"; hosts="$(env_get DOCKER_EXTRA_HOSTS | tr ',;' '  ')"
    if [ -n "$dns$hosts" ]; then
      {
        echo "# Eigene Ergänzungen zur docker-compose.yml (übernommen aus DOCKER_DNS / DOCKER_EXTRA_HOSTS der .env)"
        echo "services:"
        echo "  $SERVICE:"
        if [ -n "$dns" ]; then echo "    dns:"; for d in $dns; do echo "      - \"$d\""; done; fi
        if [ -n "$hosts" ]; then echo "    extra_hosts:"; for h in $hosts; do echo "      - \"$h\""; done; fi
      } > docker-compose.override.yml
      echo "   DOCKER_DNS/DOCKER_EXTRA_HOSTS → docker-compose.override.yml übernommen"
    fi
  fi
  for c in "$CONTAINER-old" "$CONTAINER-alt"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  if container_exists && [ -z "$(label_of "$CONTAINER" com.docker.compose.project)" ]; then
    docker rm -f "$CONTAINER" >/dev/null && echo "   bisherigen Container (gestartet mit docker run) entfernt – Daten bleiben"
  fi
}
drop_foreign_network() {  # von update.sh ≤ 1.9 angelegtes Netz: Compose möchte es selbst verwalten
  docker network inspect "$NETWORK" >/dev/null 2>&1 || return 0
  [ -n "$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$NETWORK" 2>/dev/null || true)" ] && return 0
  docker network rm "$NETWORK" >/dev/null 2>&1 || warn "Docker-Netz $NETWORK konnte nicht entfernt werden (noch in Gebrauch?)."
}

# --------------------------------------------------------------------------- Rückfall
rollback() {  # rollback NEUE_PROGRAMMVERSION STARTZEIT
  step "Vorige Version wird wieder gestartet"
  if docker image inspect "$REPO:previous" >/dev/null 2>&1; then
    # hat die neue Version die Datenbank schon umgestellt? dann die Sicherung "vor-<Version>" zurück
    if [ -n "$1" ]; then
      compose stop "$SERVICE" >/dev/null 2>&1 || true
      SAMAUDIT_VERSION="$TAG" compose run --rm --no-deps -T --name "$CONTAINER-restore" "$SERVICE" restore --rollback "$1" "$2" \
        || warn "Datenbank konnte nicht automatisch zurückgespielt werden – siehe oben (sh update.sh --restore)."
    fi
    if [ "$(env_get SAMAUDIT_VERSION)" != "$ENV_TAG_BEFORE" ]; then
      env_set SAMAUDIT_VERSION "${ENV_TAG_BEFORE:-latest}"
      echo "   SAMAUDIT_VERSION in der .env wieder auf ${ENV_TAG_BEFORE:-latest} gesetzt"
    fi
    SAMAUDIT_VERSION=previous compose up -d >/dev/null 2>&1 || true
    if wait_healthy; then
      echo "   vorige Version läuft wieder (Image $REPO:previous)."
      echo "   Hinweis: bis zum nächsten Update läuft sie unter dem Namen 'previous'."
      return 0
    fi
    warn "Auch die vorige Version startet nicht – bitte Log prüfen: docker logs $CONTAINER"
  else
    warn "Keine vorige Version vorhanden."
  fi
  return 1
}

# --------------------------------------------------------------------------- Ablauf
if [ "$MODE" = cleanup ]; then cleanup; exit 0; fi

if [ ! -f .env ]; then
  if [ -f .env.example ]; then cp .env.example .env; chmod 600 .env
    die ".env fehlte und wurde aus .env.example angelegt. Bitte mindestens DOMAIN_FQDN eintragen und erneut starten."
  fi
  die ".env fehlt. Bitte .env.example herunterladen, als .env speichern und ausfüllen (mindestens DOMAIN_FQDN)."
fi
grep -Eq '^[[:space:]]*DOMAIN_FQDN[[:space:]]*=[[:space:]]*[^[:space:]#]' .env || warn "DOMAIN_FQDN ist in der .env nicht gesetzt."
mkdir -p data certs

check_owner

if [ "$MODE" = restore ]; then
  [ -f docker-compose.yml ] || die "docker-compose.yml fehlt – erst einmal sh update.sh ausführen."
  step "Sicherung zurückspielen"
  # zurückgespielt wird mit dem bisherigen Image; mit --version=… wird danach die gewünschte Version gestartet
  compose stop "$SERVICE" || true
  rc=0
  if [ -n "$RESTORE_FILE" ]; then compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore "$(basename "$RESTORE_FILE")" || rc=$?
  else compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore || rc=$?; fi
  if [ "$rc" != 0 ] || [ -z "$NEW_VERSION" ]; then
    compose up -d
    wait_healthy && echo "${c_ok}SAMAUDIT läuft.${c_off}" || die "SAMAUDIT ist nicht bereit (Status: $(health_of)) – docker logs $CONTAINER"
    [ "$rc" = 0 ] || die "Es wurde nichts zurückgespielt (siehe oben)."
    exit 0
  fi
  echo "   zurückgespielt – jetzt Wechsel auf Version $NEW_VERSION"
fi

# gewünschte Version (der bisherige Eintrag wird gemerkt – ein Rückfall stellt ihn wieder her)
ENV_TAG_BEFORE="$(env_get SAMAUDIT_VERSION)"
if [ -n "$NEW_VERSION" ]; then
  valid_tag "$NEW_VERSION" || die "Ungültige Version: $NEW_VERSION"
  env_set SAMAUDIT_VERSION "$NEW_VERSION"
  echo "Version festgelegt: SAMAUDIT_VERSION=$NEW_VERSION (in der .env)"
fi
TAG="$(env_get SAMAUDIT_VERSION)"; TAG="${TAG:-latest}"
valid_tag "$TAG" || die "Ungültige SAMAUDIT_VERSION in der .env: $TAG"
[ "$TAG" = previous ] && die "SAMAUDIT_VERSION=previous ist für den Rückfall reserviert – bitte eine Version oder latest eintragen."

# 1) laufendes Image als "previous" merken
OLD_ID=""; OLD_VER=""
if container_exists; then
  OLD_ID="$(docker inspect -f '{{.Image}}' "$CONTAINER")"
  OLD_VER="$(image_version "$OLD_ID")"
  docker tag "$OLD_ID" "$REPO:previous"
fi

# 2) Version holen
if [ "$MODE" = load ]; then
  [ -f "$LOAD_FILE" ] || die "Datei nicht gefunden: $LOAD_FILE"
  sums="$(dirname "$LOAD_FILE")/SHA256SUMS"
  if [ -f "$sums" ]; then
    want="$(grep -F " $(basename "$LOAD_FILE")" "$sums" | awk '{print $1}' | head -n 1)"
    if command -v sha256sum >/dev/null 2>&1; then have="$(sha256sum "$LOAD_FILE" | awk '{print $1}')"
    else have="$(openssl dgst -sha256 "$LOAD_FILE" 2>/dev/null | awk '{print $NF}')"; fi
    [ -n "$want" ] && [ "$want" = "$have" ] || die "Prüfsumme stimmt nicht (SHA256SUMS) – Datei beschädigt oder falsch."
    echo "   Prüfsumme in Ordnung"
  else
    warn "Keine SHA256SUMS neben der Datei – Prüfsumme nicht geprüft."
  fi
  step "Image laden: $(basename "$LOAD_FILE")"
  out="$(docker load -i "$LOAD_FILE")" || die "Image konnte nicht geladen werden."
  printf '%s\n' "$out"
  loaded="$(printf '%s\n' "$out" | sed -n 's/^Loaded image: //p' | grep -F "$REPO:" | head -n 1)"
  [ -n "$loaded" ] || die "Die Datei enthält kein Image von $REPO."
  TAG="${loaded##*:}"; env_set SAMAUDIT_VERSION "$TAG"
  echo "   SAMAUDIT_VERSION=$TAG (in der .env)"
else
  step "Image holen: $REPO:$TAG"
  docker pull "$REPO:$TAG" || die "Image konnte nicht geholt werden. Privates Repository? Einmal anmelden:
       docker login ghcr.io -u <GitHub-Benutzer>   (Passwort: Token mit read:packages – wird nicht angezeigt)"
fi
NEW_ID="$(docker image inspect -f '{{.Id}}' "$REPO:$TAG")"
NEW_VER="$(image_version "$REPO:$TAG")"
echo "SAMAUDIT: bisher ${OLD_VER:-–}  →  neu ${NEW_VER:-$TAG}"

# 3) Compose-Datei (und Vorlagen) aus dem Image
take_files_from_image "$REPO:$TAG"
[ -f docker-compose.yml ] || die "docker-compose.yml fehlt und ist auch nicht im Image enthalten."

LEGACY=0
if container_exists && [ -z "$(label_of "$CONTAINER" com.docker.compose.project)" ]; then LEGACY=1; fi
if [ "$LEGACY" = 0 ] && [ "$OLD_ID" = "$NEW_ID" ] && [ "$(health_of)" = healthy ]; then
  echo "SAMAUDIT ${NEW_VER:-} ist aktuell – nichts zu tun."
  exit 0
fi

# 4) starten
if [ "$LEGACY" = 1 ]; then
  step "Umstieg auf Docker Compose (einmalig)"
  migrate_legacy
fi
drop_foreign_network
step "Starten"
START="$(date +%s)"
compose up -d || { rollback "" "" || true; die "docker compose up ist fehlgeschlagen (siehe oben)."; }

# 5) Gesundheitscheck
step "Gesundheitscheck"
if ! wait_healthy; then
  docker logs --tail 40 "$CONTAINER" 2>&1 || true
  if [ -n "$OLD_ID" ] && ask "Die neue Version startet nicht. Vorige Version wieder starten?" J; then
    rollback "${NEW_VER%%-s*}" "$START" || true
    die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Log oben). Es läuft wieder die vorige."
  fi
  die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Status: $(health_of), Log oben)."
fi
echo "   ${c_ok}läuft${c_off} – Version ${NEW_VER:-$TAG}"
docker logs --since 5m "$CONTAINER" 2>&1 | grep -E "ERROR|Konfiguration:|Hinweis:|gesichert" | tail -n 5 || true

# 6) aufräumen: nicht mehr benannte SAMAUDIT-Images (previous bleibt für einen Rückschritt)
docker image prune -f --filter "label=org.opencontainers.image.title=SAMAUDIT" >/dev/null 2>&1 || true

host="$(env_get PUBLIC_HOSTNAME)"; port="$(env_get PORT)"
scheme=https; [ "$(env_get TLS_ENABLED | tr 'A-Z' 'a-z')" = "false" ] && scheme=http
echo
echo "${c_ok}Fertig.${c_off} SAMAUDIT ${NEW_VER:-$TAG} läuft: $scheme://${host:-<server>}:${port:-9400}"
if [ "$LEGACY" = 1 ] || [ -d app ] || [ -f Dockerfile ]; then
  echo "Programmdateien früherer Versionen werden nicht mehr gebraucht. Aufräumen: sh update.sh --cleanup"
fi
