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
# Ablauf: neue Version holen → laufendes Image als "previous" merken → docker compose up -d → Gesundheitscheck.
# Startet die neue Version nicht, läuft wieder die vorige (eine dabei geänderte Datenbank wird aus der
# Sicherung "vor-<Version>" zurückgespielt). Die Datenbank sichert SAMAUDIT beim Versionswechsel selbst.
# Läuft mit /bin/sh (dash, busybox – z. B. Synology), braucht Docker mit Compose v2.
#
# Windows-Zeilenenden (CRLF) werden repariert; das "#" am Zeilenende hält die nächste Zeile auch mit CRLF lauffähig.
if grep -q "$(printf '\r')" "$0" 2>/dev/null; then tr -d '\r' < "$0" > "$0.lf.$$" && cat "$0.lf.$$" > "$0" && rm -f "$0.lf.$$" && exec sh "$0" "$@"; echo "Bitte update.sh mit Unix-Zeilenenden (LF) speichern." >&2; exit 1; fi #
set -eu

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
# relativer Pfad zur Image-Datei: gilt vom Aufrufort aus
case "$LOAD_FILE" in ""|/*) ;; *) LOAD_FILE="$PWD/$LOAD_FILE" ;; esac

cd "$(dirname "$0")"
INSTALL_DIR="$(pwd -P)"
CONTAINER=samaudit
SERVICE=samaudit
NETWORK=samaudit-net
BRIDGE=br-samaudit
DEFAULT_REPO=ghcr.io/soleil0815/samaudit
HEALTH_TIMEOUT="${SAMAUDIT_HEALTH_TIMEOUT:-180}"
ROOT="${SAMAUDIT_TEST_ROOT:-}"        # nur für die Selbsttests: Ersatz für "/" (nie das echte /etc)
NL='
'

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

strip_cr() {  # strip_cr DATEI – Windows-Zeilenenden entfernen (Datei/Link bleibt dieselbe, Rechte bleiben)
  tmp="$(mktemp "$INSTALL_DIR/.cr.XXXXXX")"
  tr -d '\r' < "$1" > "$tmp" && cat "$tmp" > "$1"; rm -f "$tmp"
}
env_get() {  # env_get NAME → Wert aus der .env (ohne Kommentar, ohne Anführungszeichen)
  [ -f .env ] || return 0
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" .env | tail -n 1 \
    | sed -e 's/[[:space:]]#.*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/" -e 's/[[:space:]]*$//'
}
env_set() {  # env_set NAME WERT – Zeile(n) ersetzen oder anhängen; die .env bleibt dieselbe Datei (auch als Link)
  tmp="$(mktemp "$INSTALL_DIR/.env.tmp.XXXXXX")"
  awk -v k="$1" -v v="$2" '
    { line = $0; sub(/^[ \t]*#?[ \t]*/, "", line)
      if (index(line, k) == 1) { rest = substr(line, length(k) + 1); sub(/^[ \t]*/, "", rest)
        if (substr(rest, 1, 1) == "=") { print k "=" v; done = 1; next } }
      print }
    END { if (!done) { print ""; print k "=" v } }' .env > "$tmp" && cat "$tmp" > .env
  rm -f "$tmp"
}

command -v docker >/dev/null 2>&1 || die "docker ist nicht installiert."
docker info >/dev/null 2>&1 || die "Kein Zugriff auf Docker – mit sudo ausführen oder den Benutzer in die Gruppe 'docker' aufnehmen."
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  cv="$(docker-compose version --short 2>/dev/null || true)"
  case "$cv" in 1.*|"") die "docker-compose ${cv:-?} ist zu alt – benötigt wird Docker Compose v2 (docker compose)." ;; esac
  COMPOSE="docker-compose"
else die "Docker Compose fehlt (docker compose bzw. docker-compose)."; fi
compose() { $COMPOSE "$@"; }

if [ -f .env ] && grep -q "$(printf '\r')" .env; then strip_cr .env; echo "Windows-Zeilenenden in .env repariert."; fi

REPO="$(env_get SAMAUDIT_IMAGE)"; REPO="${REPO:-$DEFAULT_REPO}"
container_exists() { docker inspect "$CONTAINER" >/dev/null 2>&1; }
label_of() { docker inspect -f "{{index .Config.Labels \"$2\"}}" "$1" 2>/dev/null || true; }
health_of() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing; }
image_version() { docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null || true; }
compose_file_version() { sed -n 's/^[[:space:]]*SAMAUDIT_COMPOSE:[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}.*/\1/p' "$1" 2>/dev/null | head -n 1; }
volume_lines() { grep -E '^[[:space:]]*-[[:space:]].*:/app/(data|certs)' "$1" 2>/dev/null | sed 's/[[:space:]]*#.*$//; s/[[:space:]]*$//' || true; }

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

realpath_of() {  # vollständig aufgelöster Pfad (Links, ..), auch ohne Leserecht am Ziel; leer = unbekannt
  r="$(readlink -f "$1" 2>/dev/null || true)"
  if [ -z "$r" ]; then
    if [ -d "$1" ]; then r="$( (cd -P "$1" 2>/dev/null && pwd -P) || true)"
    else d="$( (cd -P "$(dirname "$1")" 2>/dev/null && pwd -P) || true)"; [ -n "$d" ] && r="$d/$(basename "$1")"; fi
  fi
  printf '%s\n' "$r"
}

# Wem gehört der Container? Eine andere Compose-Installation (z. B. Stack in Dockhand) nicht anfassen.
check_owner() {
  container_exists || return 0
  wd="$(label_of "$CONTAINER" com.docker.compose.project.working_dir)"
  if [ -n "$wd" ] && [ "$(realpath_of "$wd")" != "$INSTALL_DIR" ] && [ "$wd" != "$INSTALL_DIR" ]; then
    die "Der Container $CONTAINER gehört zu einer anderen Compose-Installation ($wd), z. B. einem Stack in
       Dockhand/Portainer. Bitte dort aktualisieren – oder dieses Skript in jenem Ordner ausführen."
  fi
}

# --------------------------------------------------------------------------- Aufräumen (--cleanup)
# Dateien früherer Versionen (ZIP-Weg, lokaler Bau, Host-Firewall). Nur in einem SAMAUDIT-Ordner, nur
# bekannte Namen. Daten, Sicherungen, Einstellungen, Compose-Dateien und alles, was ein Container im
# Ordner einbindet, sind geschützt – auch über Links und Einhängepunkte. Im Zweifel wird nichts gelöscht.
CLEAN_FILES="Dockerfile entrypoint.sh run.py requirements.txt requirements.in requirements-dev.txt requirements-dev.in
requirements.txt.new .dockerignore .gitattributes .gitignore .trivyignore README.md README.en.md LICENSE NOTICE
THIRD-PARTY-NOTICES.md DATENSCHUTZ.md SECURITY.md CHANGELOG-SECURITY.md .samaudit-manifest base-image.lock .env.run
.firewall-targets samaudit-firewall.sh docker-compose.override.example.yml docker-compose.example.yml"

is_samaudit_dir() {  # Ordner eines Unterordners mit Programmdateien, erkannt am Inhalt
  case "$1" in
    app) grep -qs 'APP_NAME = "SAMAUDIT"' app/version.py ;;
    tools) [ -f tools/clean-history.sh ] || [ -f tools/lockutil.py ] || [ -f tools/update-locks.sh ] ;;
    tests) [ -f tests/smoke.py ] ;;
    locks) [ -f locks/os-packages.txt ] ;;
    .github) [ -f .github/workflows/docker-image.yml ] ;;
    *) return 1 ;;
  esac
}

protected_paths() {  # eine Zeile je geschütztem Pfad (aufgelöst UND wie im Ordner geschrieben)
  for p in data backups certs .env .env.example docker-compose.yml docker-compose.override.yml docker-compose.yml.alt update.sh; do
    printf '%s/%s\n' "$INSTALL_DIR" "$p"
    if [ -e "$p" ] || [ -L "$p" ]; then r="$(realpath_of "$p")"; [ -n "$r" ] && printf '%s\n' "$r"; fi
  done
  # Ordner, die Container (auch gestoppte) aus diesem Ordner einbinden
  ids="$(docker ps -aq)" || return 1
  for c in $ids; do
    docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null || true
  done | while IFS= read -r m; do
    [ -n "$m" ] || continue
    r="$(realpath_of "$m")"; [ -n "$r" ] || r="$m"
    case "$r" in "$INSTALL_DIR"|"$INSTALL_DIR"/*) printf '%s\n' "$r" ;; esac
  done
  # Einhängepunkte unterhalb des Ordners (rm -r würde sonst hineinlaufen); /proc/mounts kodiert Leerzeichen als \040
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

overlaps() {  # overlaps A B → 0, wenn A gleich B ist oder einer im anderen liegt
  case "$1/" in "$2"/*) return 0 ;; esac
  case "$2/" in "$1"/*) return 0 ;; esac
  return 1
}

cleanup() {
  { [ -e .git ] || [ -L .git ]; } && die "Hier liegt eine Git-Arbeitskopie (.git) – das ist ein Entwicklerordner, --cleanup räumt hier nichts auf."
  if ! grep -qs 'SAMAUDIT_COMPOSE' docker-compose.yml && [ ! -f .samaudit-manifest ] \
     && ! grep -qs 'APP_NAME = "SAMAUDIT"' app/version.py; then
    die "Das ist kein SAMAUDIT-Ordner (keine docker-compose.yml von SAMAUDIT, keine Programmdateien) – nichts aufgeräumt."
  fi
  prot="$(protected_paths)" || die "Die geschützten Pfade konnten nicht vollständig ermittelt werden (Docker erreichbar?) – nichts gelöscht."
  case "$NL$prot$NL" in *"$NL$INSTALL_DIR/data$NL"*) ;; *) die "Schutzliste unvollständig – nichts gelöscht." ;; esac

  list=""; skipped=""
  add() { list="$list$1$NL"; }
  for f in $CLEAN_FILES; do { [ -e "$f" ] || [ -L "$f" ]; } && add "$f"; done
  for d in app tools tests locks .github; do
    if [ -L "$d" ]; then add "$d"
    elif [ -d "$d" ]; then
      if is_samaudit_dir "$d"; then add "$d"; else skipped="$skipped  $d/ (nicht als SAMAUDIT-Ordner erkannt)$NL"; fi
    fi
  done
  for f in .update-* update.sh.new.[0-9]* docker-compose.yml.new.[0-9]* .env.example.new.[0-9]* \
           samaudit*.zip SAMAUDIT*.zip Samaudit*.zip samaudit*.ZIP SAMAUDIT*.ZIP; do
    { [ -e "$f" ] || [ -L "$f" ]; } || continue
    case "$f" in *"$NL"*) skipped="$skipped  (Name mit Zeilenumbruch übersprungen)$NL"; continue ;; esac
    add "$f"
  done
  # Versionsordner: entpackte Pakete früherer Versionen (erkannt an app/version.py) – nie mit Daten darin
  for d in samaudit* SAMAUDIT* Samaudit*; do
    [ -d "$d" ] && [ ! -L "$d" ] && grep -qs 'APP_NAME = "SAMAUDIT"' "$d/app/version.py" || continue
    case "$d" in *"$NL"*) continue ;; esac
    if [ -e "$d/data" ] || [ -n "$(find "$d" \( -name '*.db' -o -name '*.tgz' -o -name '.env' \) 2>/dev/null | head -n 1)" ]; then
      skipped="$skipped  $d/ (enthält Daten oder Einstellungen)$NL"; continue
    fi
    add "$d"
  done
  list="$(printf '%s' "$list" | sort -u)"

  ok=""
  set -f; OLDIFS="$IFS"; IFS="$NL"
  for f in $list; do
    [ -n "$f" ] || continue
    case "$f" in */*|..|.|-*) skipped="$skipped  $f (unsicherer Name)$NL"; continue ;; esac
    if [ -L "$f" ]; then ok="$ok$f$NL"; continue; fi            # Link: nur der Link selbst wird entfernt, nie das Ziel
    r="$(realpath_of "$f")"
    case "$r" in "$INSTALL_DIR"/*) ;; *) skipped="$skipped  $f (Pfad nicht sicher bestimmbar)$NL"; continue ;; esac
    hit=""
    for p in $prot; do [ -n "$p" ] && overlaps "$r" "$p" && { hit="$p"; break; }; done
    if [ -n "$hit" ]; then skipped="$skipped  $f (geschützt: enthält oder ist $hit)$NL"; continue; fi
    if [ -d "$f" ] && [ "$(find "$f" -xdev 2>/dev/null | wc -l)" != "$(find "$f" 2>/dev/null | wc -l)" ]; then
      skipped="$skipped  $f (enthält ein eingehängtes Laufwerk)$NL"; continue
    fi
    ok="$ok$f$NL"
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
          while $SUDO iptables -C "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS 2>/dev/null; do $SUDO iptables -D "$ch" -i "$BRIDGE" -j SAMAUDIT-EGRESS; done
        done
        while $SUDO iptables -C INPUT -i "$BRIDGE" -j SAMAUDIT-HOST 2>/dev/null; do $SUDO iptables -D INPUT -i "$BRIDGE" -j SAMAUDIT-HOST; done
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
        if [ "$(volume_lines docker-compose.yml)" != "$(volume_lines "$tmpd/docker-compose.yml")" ]; then
          # die bisherige Datei bindet andere Ordner ein – nicht ersetzen, sonst liefe SAMAUDIT auf leeren Daten
          cp "$tmpd/docker-compose.yml" docker-compose.yml.neu
          warn "Im Image liegt eine neuere docker-compose.yml (Version $new_v), Ihre Datei bindet aber andere Ordner ein.
         Sie wurde NICHT ersetzt; die neue liegt als docker-compose.yml.neu daneben. Bitte die eigenen Pfade
         in eine docker-compose.override.yml übernehmen und dann docker-compose.yml.neu → docker-compose.yml."
        else
          cp -p docker-compose.yml docker-compose.yml.alt
          cp "$tmpd/docker-compose.yml" docker-compose.yml.new.$$ && mv -f docker-compose.yml.new.$$ docker-compose.yml
          warn "Neue docker-compose.yml (Version ${old_v:-ohne} → $new_v) abgelegt; die bisherige liegt als docker-compose.yml.alt daneben.
         Eigene Änderungen bitte in docker-compose.override.yml übernehmen."
        fi
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
# DOCKER_DNS/DOCKER_EXTRA_HOSTS in die Override-Datei übernehmen, alten Container beiseitestellen
# (für den Rückfall) und seine Netz-Definition lösen (Compose legt das Netz selbst an).
legacy_check_mount() {
  src="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Source}}{{end}}{{end}}' "$CONTAINER" 2>/dev/null || true)"
  [ -n "$src" ] || return 0
  if [ "$(realpath_of "$src")" != "$INSTALL_DIR/data" ] && [ "$src" != "$INSTALL_DIR/data" ]; then
    die "Der laufende Container $CONTAINER verwendet die Daten aus $src, nicht aus $INSTALL_DIR/data.
       Bitte update.sh im Ordner der bisherigen Installation ausführen – hier wird nichts geändert."
  fi
}
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
  if grep -Eq "^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^'[:space:]][^#]*[\$]" .env 2>/dev/null; then
    warn "In der .env enthält ein Wert ein \$-Zeichen. Docker Compose würde es als Variable lesen –
         solche Werte bitte in einfache Anführungszeichen setzen, z. B. TLS_PFX_PASSWORD='ab\$cd'."
  fi
  for c in "$CONTAINER-old" "$CONTAINER-alt"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker stop "$CONTAINER" >/dev/null 2>&1 || true
  docker rename "$CONTAINER" "$CONTAINER-alt" || die "Der bisherige Container ließ sich nicht beiseitestellen – nichts geändert."
  docker update --restart=no "$CONTAINER-alt" >/dev/null 2>&1 || true
  docker network disconnect -f "$NETWORK" "$CONTAINER-alt" >/dev/null 2>&1 || true
  LEGACY_ASIDE=1
  echo "   bisherigen Container (gestartet mit docker run) beiseitegestellt – Daten bleiben"
}
legacy_back() {  # Umstieg misslungen: alten Container wieder wie vorher starten
  [ "${LEGACY_ASIDE:-0}" = 1 ] || return 1
  step "Bisherige Installation wird wieder gestartet"
  compose down >/dev/null 2>&1 || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker network inspect "$NETWORK" >/dev/null 2>&1 || \
    docker network create --driver bridge -o "com.docker.network.bridge.name=$BRIDGE" "$NETWORK" >/dev/null 2>&1 || true
  docker network connect "$NETWORK" "$CONTAINER-alt" >/dev/null 2>&1 || true
  docker rename "$CONTAINER-alt" "$CONTAINER" && docker update --restart=unless-stopped "$CONTAINER" >/dev/null 2>&1 || true
  docker start "$CONTAINER" >/dev/null 2>&1 || true
  LEGACY_ASIDE=0
  wait_healthy && { echo "   bisherige Installation läuft wieder."; return 0; }
  warn "Auch die bisherige Installation startet nicht – bitte prüfen: docker ps -a"
  return 1
}
drop_foreign_network() {  # von update.sh ≤ 1.9 angelegtes Netz: Compose möchte es selbst verwalten
  docker network inspect "$NETWORK" >/dev/null 2>&1 || return 0
  [ -n "$(docker network inspect -f '{{index .Labels "com.docker.compose.network"}}' "$NETWORK" 2>/dev/null || true)" ] && return 0
  docker network rm "$NETWORK" >/dev/null 2>&1 || warn "Docker-Netz $NETWORK konnte nicht entfernt werden (noch in Gebrauch?)."
}

# --------------------------------------------------------------------------- Rückfall
# Die vorige Version läuft danach unter ihrer eigenen Versionsnummer (in der .env festgelegt) –
# so startet auch ein späteres "docker compose up -d" oder eine Container-Verwaltung nicht die kaputte.
rollback() {
  step "Vorige Version wird wieder gestartet"
  [ -n "$OLD_ID" ] || { warn "Keine vorige Version vorhanden."; return 1; }
  compose stop "$SERVICE" >/dev/null 2>&1 || true
  # hat die neue Version die Datenbank schon übernommen? dann deren Sicherung "vor-…" zurückspielen
  SAMAUDIT_VERSION="$TAG" compose run --rm --no-deps -T --name "$CONTAINER-restore" "$SERVICE" restore --rollback "$START" \
    || warn "Datenbank konnte nicht automatisch zurückgespielt werden (siehe oben) – ggf. sh update.sh --restore."
  back_tag="$OLD_VER"; valid_tag "$back_tag" || back_tag="${ENV_TAG_BEFORE:-latest}"
  [ "$back_tag" = previous ] && back_tag=latest
  docker tag "$OLD_ID" "$REPO:$back_tag"
  env_set SAMAUDIT_VERSION "$back_tag"
  ROLLED_BACK=1
  compose up -d >/dev/null 2>&1 || true
  if wait_healthy; then
    echo "   vorige Version $back_tag läuft wieder."
    [ "$back_tag" != "${ENV_TAG_BEFORE:-latest}" ] && \
      echo "   SAMAUDIT_VERSION=$back_tag ist jetzt in der .env festgelegt – nach Behebung wieder ${ENV_TAG_BEFORE:-latest} eintragen."
    return 0
  fi
  warn "Auch die vorige Version startet nicht – bitte Log prüfen: docker logs $CONTAINER"
  return 1
}

# Bei einem Abbruch nichts halb lassen: .env zurück, angehaltenen Dienst wieder starten
ENV_CHANGED=0; STOPPED=0; ROLLED_BACK=0; LEGACY_ASIDE=0
on_exit() {
  rc=$?
  [ "$rc" = 0 ] && return 0
  if [ "$ENV_CHANGED" = 1 ] && [ "$ROLLED_BACK" = 0 ]; then
    env_set SAMAUDIT_VERSION "${ENV_TAG_BEFORE:-latest}"
    echo "   SAMAUDIT_VERSION in der .env wieder auf ${ENV_TAG_BEFORE:-latest} gesetzt."
  fi
  if [ "$LEGACY_ASIDE" = 1 ]; then legacy_back || true
  elif [ "$STOPPED" = 1 ] && [ "$ROLLED_BACK" = 0 ] && [ "$(health_of)" != healthy ]; then
    echo "   bisherige Version wird wieder gestartet …"; compose up -d >/dev/null 2>&1 || true
  fi
  exit "$rc"
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
trap on_exit EXIT

ENV_TAG_BEFORE="$(env_get SAMAUDIT_VERSION)"
if [ -n "$NEW_VERSION" ]; then valid_tag "$NEW_VERSION" || die "Ungültige Version: $NEW_VERSION"; TAG="$NEW_VERSION"
else TAG="${ENV_TAG_BEFORE:-latest}"; fi
valid_tag "$TAG" || die "Ungültige SAMAUDIT_VERSION in der .env: $TAG"
[ "$TAG" = previous ] && die "Die Version 'previous' ist reserviert – bitte eine Versionsnummer oder latest eintragen."

restore_now() {  # zurückspielen mit dem bisherigen Image (das neuere kennt "restore" sicher)
  [ -f docker-compose.yml ] || die "docker-compose.yml fehlt – erst einmal sh update.sh ausführen."
  step "Sicherung zurückspielen"
  compose stop "$SERVICE" || true
  STOPPED=1
  if [ -n "$RESTORE_FILE" ]; then
    SAMAUDIT_VERSION="${ENV_TAG_BEFORE:-latest}" compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore "$(basename "$RESTORE_FILE")"
  else
    SAMAUDIT_VERSION="${ENV_TAG_BEFORE:-latest}" compose run --rm --no-deps --name "$CONTAINER-restore" "$SERVICE" restore
  fi || die "Es wurde nichts zurückgespielt (siehe oben)."
}

if [ "$MODE" = restore ] && [ -z "$NEW_VERSION" ]; then
  restore_now
  compose up -d
  wait_healthy && echo "${c_ok}SAMAUDIT läuft.${c_off}" || die "SAMAUDIT ist nicht bereit (Status: $(health_of)) – docker logs $CONTAINER"
  STOPPED=0
  exit 0
fi

OLD_ID=""; OLD_VER=""
if container_exists; then
  OLD_ID="$(docker inspect -f '{{.Image}}' "$CONTAINER")"
  OLD_VER="$(image_version "$OLD_ID")"
fi

# 1) neue Version holen – die .env wird erst geändert, wenn das Image da ist
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
  TAG="${loaded##*:}"
  valid_tag "$TAG" && [ "$TAG" != previous ] || die "Ungültige Version in der Image-Datei: $TAG"
else
  step "Image holen: $REPO:$TAG"
  docker pull "$REPO:$TAG" || die "Image $REPO:$TAG konnte nicht geholt werden (Version vorhanden? Privates Repository? Dann einmal:
       docker login ghcr.io -u <GitHub-Benutzer> – Passwort: Token mit read:packages, wird nicht angezeigt)."
fi
NEW_ID="$(docker image inspect -f '{{.Id}}' "$REPO:$TAG")"
NEW_VER="$(image_version "$REPO:$TAG")"
echo "SAMAUDIT: bisher ${OLD_VER:-–}  →  neu ${NEW_VER:-$TAG}"

# 2) bei --restore --version=…: jetzt zurückspielen (das neue Image ist schon da)
[ "$MODE" = restore ] && restore_now

# 3) Version in die .env
if [ "$TAG" != "${ENV_TAG_BEFORE:-latest}" ] || { [ -n "$NEW_VERSION$LOAD_FILE" ] && [ -z "$ENV_TAG_BEFORE" ]; }; then
  env_set SAMAUDIT_VERSION "$TAG"; ENV_CHANGED=1
  echo "   SAMAUDIT_VERSION=$TAG (in der .env)"
fi

# 4) Compose-Datei (und Vorlagen) aus dem Image
take_files_from_image "$REPO:$TAG"
[ -f docker-compose.yml ] || die "docker-compose.yml fehlt und ist auch nicht im Image enthalten."

LEGACY=0
if container_exists && [ -z "$(label_of "$CONTAINER" com.docker.compose.project)" ]; then LEGACY=1; fi
if [ "$LEGACY" = 0 ] && [ "$MODE" != restore ] && [ "$OLD_ID" = "$NEW_ID" ] && [ "$(health_of)" = healthy ]; then
  echo "SAMAUDIT ${NEW_VER:-} ist aktuell – nichts zu tun."
  ENV_CHANGED=0
  exit 0
fi

# 5) laufendes Image als "previous" merken, starten
[ -n "$OLD_ID" ] && docker tag "$OLD_ID" "$REPO:previous"
if [ "$LEGACY" = 1 ]; then
  step "Umstieg auf Docker Compose (einmalig)"
  legacy_check_mount
  migrate_legacy
fi
drop_foreign_network
step "Starten"
START="$(date +%s)"
STOPPED=1
if ! compose up -d; then
  if [ "$LEGACY" = 1 ]; then legacy_back || true; die "docker compose up ist fehlgeschlagen (siehe oben). Die bisherige Installation läuft weiter."; fi
  if [ -n "$OLD_ID" ] && rollback; then die "docker compose up ist fehlgeschlagen (siehe oben). Es läuft wieder die vorige Version."; fi
  die "docker compose up ist fehlgeschlagen (siehe oben)."
fi

# 6) Gesundheitscheck
step "Gesundheitscheck"
if ! wait_healthy; then
  docker logs --tail 40 "$CONTAINER" 2>&1 || true
  if [ "$LEGACY" = 1 ]; then
    legacy_back && die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Log oben). Die bisherige Installation läuft wieder."
    die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Log oben)."
  fi
  if [ -n "$OLD_ID" ] && ask "Die neue Version startet nicht. Vorige Version wieder starten?" J; then
    rollback && die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Log oben). Es läuft wieder die vorige."
    die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit, und die vorige startet auch nicht (siehe oben)."
  fi
  die "Neue Version ${NEW_VER:-$TAG} ist nicht bereit (Status: $(health_of), Log oben)."
fi
STOPPED=0; ENV_CHANGED=0
echo "   ${c_ok}läuft${c_off} – Version ${NEW_VER:-$TAG}"
docker logs --since 5m "$CONTAINER" 2>&1 | grep -E "ERROR|Konfiguration:|Hinweis:|gesichert" | tail -n 5 || true
if [ "$LEGACY" = 1 ]; then docker rm -f "$CONTAINER-alt" >/dev/null 2>&1 || true; LEGACY_ASIDE=0; fi

# 7) aufräumen: nicht mehr benannte SAMAUDIT-Images (previous bleibt für einen Rückschritt)
docker image prune -f --filter "label=org.opencontainers.image.title=SAMAUDIT" >/dev/null 2>&1 || true

host="$(env_get PUBLIC_HOSTNAME)"; port="$(env_get PORT)"
scheme=https; [ "$(env_get TLS_ENABLED | tr 'A-Z' 'a-z')" = "false" ] && scheme=http
echo
echo "${c_ok}Fertig.${c_off} SAMAUDIT ${NEW_VER:-$TAG} läuft: $scheme://${host:-<server>}:${port:-9400}"
if [ "$LEGACY" = 1 ] || [ -d app ] || [ -f Dockerfile ]; then
  echo "Programmdateien früherer Versionen werden nicht mehr gebraucht. Aufräumen: sh update.sh --cleanup"
fi
