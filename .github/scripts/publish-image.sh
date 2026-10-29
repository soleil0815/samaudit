#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Builds and publishes the image for VERSION – the image that gets the tags is exactly the one
# that was checked:
#   1. refuse if VERSION already exists in the registry (published versions are never overwritten)
#   2. build linux/amd64 + linux/arm64 WITHOUT cache and push it untagged (by digest only)
#   3. pull that digest and check it: locks, tests in the image, Trivy (.github/scripts/*.sh)
#   4. only then add the tags: VERSION, and "latest" if VERSION is the highest version
#
#   .github/scripts/publish-image.sh VERSION        (env: IMAGE = ghcr.io/<owner>/<repo>)
set -euo pipefail
version="${1:?usage: publish-image.sh VERSION}"
image="${IMAGE:?set IMAGE, e.g. ghcr.io/owner/repo}"
app_version="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' app/version.py)"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
fail() { echo "::error title=$1::$2"; printf '### %s\n%s\n' "$1" "$2" >> "$summary"; exit 1; }

if docker buildx imagetools inspect "$image:$version" >/dev/null 2>&1; then
  fail "Version existiert bereits" "$image:$version ist schon veröffentlicht und wird nie überschrieben."
fi

meta="${RUNNER_TEMP:-/tmp}/build-meta.json"
docker buildx build --no-cache --pull \
  --platform linux/amd64,linux/arm64 \
  --build-arg "APP_VERSION=$app_version" --build-arg "IMAGE_VERSION=$version" \
  --label "org.opencontainers.image.revision=${REVISION:-${GITHUB_SHA:-}}" \
  --provenance=true --sbom=true \
  --output "type=image,name=$image,push-by-digest=true,name-canonical=true,push=true" \
  --metadata-file "$meta" . \
  || fail "Bau fehlgeschlagen" "Das Image für $version konnte nicht gebaut werden (Details im Log dieses Schritts)."
digest="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Bau fehlgeschlagen" "Kein Digest für das gebaute Image."
echo "built (untagged): $image@$digest"

docker pull --platform linux/amd64 "$image@$digest"
.github/scripts/verify-image.sh "$image@$digest"
.github/scripts/trivy.sh "$image@$digest"

# image files for installations without internet (docker load), one per platform, plus checksums
assets="${RUNNER_TEMP:-/tmp}/release-assets"
rm -rf "$assets"; mkdir -p "$assets"
save_opts=(); docker save --help 2>/dev/null | grep -- '--platform' >/dev/null && save_opts=(--platform)
for arch in amd64 arm64; do
  docker pull -q --platform "linux/$arch" "$image@$digest" >/dev/null
  docker tag "$image@$digest" "$image:$version"
  if [ ${#save_opts[@]} -gt 0 ]; then docker save --platform "linux/$arch" "$image:$version"
  else docker save "$image:$version"; fi | gzip -9 > "$assets/samaudit-$version-$arch.tar.gz" \
    || fail "Image-Datei fehlgeschlagen" "Die Image-Datei für $arch konnte nicht erstellt werden."
  tar -tzf "$assets/samaudit-$version-$arch.tar.gz" | grep '^manifest.json$' >/dev/null \
    || fail "Image-Datei fehlgeschlagen" "Die Image-Datei für $arch ist unvollständig."
  docker rmi "$image:$version" >/dev/null 2>&1 || true
done
cp docker-compose.yml .env.example update.sh "$assets/"          # files for a new installation
(cd "$assets" && sha256sum samaudit-*.tar.gz docker-compose.yml .env.example update.sh > SHA256SUMS)
echo "image files: $(ls "$assets" | tr '\n' ' ')"

tags=(-t "$image:$version")
mapfile -t existing < <(git tag -l 'v*')
if python3 tools/lockutil.py is-highest "$version" "${existing[@]}"; then
  tags+=(-t "$image:latest")
else
  echo "::notice::$version is not the highest version – latest stays unchanged"
fi
docker buildx imagetools create "${tags[@]}" "$image@$digest" \
  || fail "Veröffentlichen fehlgeschlagen" "Die Tags für $version konnten nicht gesetzt werden."
{
  echo "### Veröffentlicht: $image:$version"
  echo "Digest: \`$digest\`"
  printf 'Tags: %s\n' "${tags[*]//-t /}"
} >> "$summary"
echo "published: ${tags[*]//-t /} -> $digest"
