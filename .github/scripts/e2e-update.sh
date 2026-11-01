#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Real end-to-end run of the update path with Docker Compose (no registry needed – uses --load):
#   1. old installation (container started with "docker run", program files, ZIP) → update.sh migrates
#      it to Compose, takes over DOCKER_EXTRA_HOSTS, the program backs up the database "vor-<version>"
#   2. broken new version → update.sh starts the previous one again and resets SAMAUDIT_VERSION
#   3. restore of a backup via "docker compose run … restore"
#   4. database of a newer version → the program refuses to start with a clear message
#   5. update.sh --cleanup removes the old program files, data stay
#   6. same version again → nothing to do
# Everything runs in a temporary folder; update.sh runs with /bin/sh (dash).
#
#   .github/scripts/e2e-update.sh IMAGE
set -euo pipefail
src="${1:?usage: e2e-update.sh IMAGE}"
repo=ghcr.io/soleil0815/samaudit
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
here="$PWD"
work="$(mktemp -d)"
dir="$work/samaudit"
fail() {
  echo "::error title=Update-Weg fehlgeschlagen::$1"
  printf '### Update-Weg fehlgeschlagen\n%s\n' "$1" >> "$summary"
  docker ps -a || true
  docker logs --tail 60 samaudit 2>&1 || true
  # the container log also as an annotation (job logs cannot always be opened); demo data only, no secrets
  docker logs --tail 40 samaudit 2>&1 | python3 -c "import sys; t=sys.stdin.read()[-3500:] or '(leer)'; print('::error title=Container-Log::' + t.replace('%','%25').replace('\r','%0D').replace('\n','%0A'))" || true
  docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{json .State.Health}}' samaudit 2>&1 | head -c 3000 \
    | sed 's/^/::error title=Container-Zustand::/' || true
  exit 1
}
cleanup() {
  (cd "$dir" 2>/dev/null && docker compose down >/dev/null 2>&1) || true
  docker rm -f samaudit samaudit-restore >/dev/null 2>&1 || true
  docker network rm samaudit-net >/dev/null 2>&1 || true
  sudo rm -rf "$work" 2>/dev/null || rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT
upd() { (cd "$dir" && sh ./update.sh "$@"); }
db_py() { docker exec -u 10001:10001 samaudit python -c "$1"; }
wait_healthy() {
  for _ in $(seq 1 60); do
    case "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' samaudit 2>/dev/null)" in
      healthy) return 0 ;;
    esac
    sleep 3
  done
  return 1
}

ver="$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$src")"
[ -n "$ver" ] || fail "Image ohne Versionsangabe"
docker tag "$src" "$repo:$ver"
# "kaputte" neue Version: übernimmt die Datenbank (Programmversion 9.9.9), besteht aber den Gesundheitscheck nie
printf 'FROM %s\nRUN sed -i "s/^VERSION = .*/VERSION = \\"9.9.9\\"/" /app/app/version.py\nLABEL org.opencontainers.image.version="9.9.9"\nHEALTHCHECK --interval=2s --timeout=2s --start-period=1s --start-interval=1s --retries=2 CMD false\n' "$src" \
  | docker build -q -t "$repo:9.9.9" - >/dev/null
docker save "$repo:$ver" | gzip > "$work/samaudit-$ver-amd64.tar.gz"
docker save "$repo:9.9.9" | gzip > "$work/samaudit-9.9.9-amd64.tar.gz"
(cd "$work" && sha256sum samaudit-*.tar.gz > SHA256SUMS)
docker rmi "$repo:$ver" "$repo:9.9.9" >/dev/null

# --------------------------------------------------------------------------- 1) old installation
mkdir -p "$dir/data" "$dir/certs" "$dir/app" "$dir/backups"
cp "$here/update.sh" "$dir/update.sh"
cat > "$dir/.env" <<'EOF'
DOMAIN_FQDN=demo.local
DEMO_MODE=true
PORT=19400
PUBLIC_HOSTNAME=localhost
DOCKER_EXTRA_HOSTS=dc01.firma.local:10.0.10.10
EOF
printf 'APP_NAME = "SAMAUDIT"\nVERSION = "1.9.8"\n' > "$dir/app/version.py"
touch "$dir/Dockerfile" "$dir/base-image.lock" "$dir/.samaudit-manifest" "$dir/samaudit-v1.9.8.zip"
echo "SICHERUNG" > "$dir/backups/samaudit-1.9.8-20261001.tgz"
docker network create --driver bridge -o com.docker.network.bridge.name=br-samaudit samaudit-net >/dev/null
docker run -d --name samaudit --network samaudit-net -v "$dir/data:/app/data" -v "$dir/certs:/app/certs:ro" \
  -e DEMO_MODE=true -e DOMAIN_FQDN=demo.local --read-only --tmpfs /tmp "$src" >/dev/null
wait_healthy || fail "Alte Installation startet nicht"
# Datenbank wie von einer Version vor 2.0 (ohne Versionsangabe)
db_py "import sqlite3; c = sqlite3.connect('/app/data/samaudit.db'); c.execute(\"DELETE FROM kv WHERE key='app_version'\"); c.commit()"

# 1a) Umstieg scheitert (Port belegt) → die bisherige Installation muss wieder laufen
python3 -m http.server 19400 >/dev/null 2>&1 &
blocker=$!
sleep 1
if upd -y --load "$work/samaudit-$ver-amd64.tar.gz"; then kill "$blocker"; fail "Umstieg trotz belegtem Port als erfolgreich gemeldet"; fi
kill "$blocker"; wait "$blocker" 2>/dev/null || true
wait_healthy || fail "nach gescheitertem Umstieg läuft die bisherige Installation nicht"
[ -z "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' samaudit)" ] || fail "gescheiterter Umstieg: nicht der bisherige Container"
docker inspect samaudit-alt >/dev/null 2>&1 && fail "gescheiterter Umstieg: samaudit-alt bleibt liegen"
grep -q "^SAMAUDIT_VERSION=$ver" "$dir/.env" && fail "gescheiterter Umstieg: SAMAUDIT_VERSION nicht zurückgesetzt"
echo "1a) gescheiterter Umstieg: ok"

upd -y --load "$work/samaudit-$ver-amd64.tar.gz" || fail "Umstieg mit update.sh fehlgeschlagen"
[ -n "$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' samaudit)" ] || fail "Container läuft nicht unter Compose"
[ -f "$dir/docker-compose.yml" ] || fail "docker-compose.yml wurde nicht angelegt"
grep -q "dc01.firma.local:10.0.10.10" "$dir/docker-compose.override.yml" || fail "DOCKER_EXTRA_HOSTS nicht übernommen"
docker exec samaudit getent hosts dc01.firma.local | grep 10.0.10.10 >/dev/null || fail "Override-Datei wirkt nicht"
curl -sfk https://localhost:19400/healthz | grep "\"$ver\"" >/dev/null || fail "healthz liefert nicht Version $ver"
sudo sh -c "ls '$dir/data/backups/' | grep '^samaudit-vor-$ver-' >/dev/null" || fail "keine Sicherung vor-$ver angelegt"
docker logs samaudit 2>&1 | grep "Hinweis: .*docker-compose" >/dev/null && fail "Compose-Hinweis trotz aktueller Datei"
echo "1) Umstieg: ok"

# --------------------------------------------------------------------------- 2) broken new version
if upd -y --load "$work/samaudit-9.9.9-amd64.tar.gz"; then fail "kaputte Version wurde als erfolgreich gemeldet"; fi
wait_healthy || fail "nach dem Rückfall läuft SAMAUDIT nicht"
[ "$(docker inspect -f '{{.Image}}' samaudit)" = "$(docker image inspect -f '{{.Id}}' "$repo:previous")" ] || fail "Rückfall: nicht die vorige Version"
grep -q "^SAMAUDIT_VERSION=$ver\$" "$dir/.env" || fail "Rückfall: SAMAUDIT_VERSION nicht zurückgesetzt"
[ "$(db_py "from app import datastate; from app.config import settings; print(datastate._read_meta(settings.db_path)['app_version'])")" = "$ver" ] \
  || fail "Rückfall: Datenbank nicht auf den Stand vor 9.9.9 zurückgespielt"
(cd "$dir" && docker compose up -d >/dev/null 2>&1); wait_healthy || fail "nach dem Rückfall startet docker compose up -d nicht die vorige Version"
echo "2) Rückfall: ok"

# --------------------------------------------------------------------------- 3) restore
(cd "$dir" && docker compose up -d >/dev/null 2>&1); wait_healthy || fail "Neustart mit $ver"
name="$(db_py "from app import datastate; import os; print(os.path.basename(datastate.backup_now('e2e')))")"
upd -y --restore "$name" | tee "$work/restore.log" || fail "update.sh --restore fehlgeschlagen"
grep -q "Zurückgespielt: $name" "$work/restore.log" || fail "Sicherung wurde nicht zurückgespielt"
echo "3) Zurückspielen: ok"

# --------------------------------------------------------------------------- 4) database of a newer version
db_py "import sqlite3; c = sqlite3.connect('/app/data/samaudit.db'); c.execute(\"UPDATE kv SET value='99.0.0' WHERE key='app_version'\"); c.commit()"
docker restart samaudit >/dev/null
for _ in $(seq 1 20); do docker logs samaudit 2>&1 | grep "START ABGEBROCHEN" >/dev/null && break; sleep 2; done
docker logs samaudit 2>&1 | grep "START ABGEBROCHEN: Die Datenbank stammt von SAMAUDIT 99.0.0" >/dev/null || fail "Rückschritt wurde nicht erkannt"
upd -y --restore "$name" >/dev/null || fail "Zurückspielen nach Rückschritt fehlgeschlagen"
echo "4) Schutz vor Rückschritt: ok"

# --------------------------------------------------------------------------- 5) cleanup
upd --cleanup -y || fail "update.sh --cleanup fehlgeschlagen"
for f in app Dockerfile base-image.lock .samaudit-manifest samaudit-v1.9.8.zip; do
  [ ! -e "$dir/$f" ] || fail "--cleanup hat $f nicht entfernt"
done
sudo test -f "$dir/data/samaudit.db" || fail "--cleanup: Datenbank fehlt"
grep -q SICHERUNG "$dir/backups/samaudit-1.9.8-20261001.tgz" || fail "--cleanup: alte Sicherung fehlt"
for f in .env docker-compose.yml docker-compose.override.yml update.sh; do [ -e "$dir/$f" ] || fail "--cleanup: $f fehlt"; done
echo "5) Aufräumen: ok"

# --------------------------------------------------------------------------- 6) nothing to do
upd -y --load "$work/samaudit-$ver-amd64.tar.gz" | tee "$work/again.log" || fail "erneutes Laden fehlgeschlagen"
grep -q "nichts zu tun" "$work/again.log" || fail "gleiche Version: es wurde trotzdem neu gestartet"
echo "6) Gleiche Version: ok"

printf '### Update-Weg mit Docker Compose\nUmstieg, Rückfall, Zurückspielen, Rückschritt-Schutz, Aufräumen: alles in Ordnung.\n' >> "$summary"
