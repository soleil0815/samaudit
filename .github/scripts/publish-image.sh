#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Builds and publishes the image for VERSION – the image that gets the tags is exactly the one
# that was checked. Two steps, so that each platform is built on its own hardware (no emulation)
# and both run at the same time:
#
#   publish-image.sh build VERSION ARCH   (runner of that platform: ubuntu-latest / ubuntu-24.04-arm)
#     1. refuse if VERSION already exists in the registry (published versions are never overwritten)
#     2. build linux/ARCH WITHOUT cache and push it untagged (by digest only)
#     3. pull that digest and check it: locks, tests in the image, Trivy (.github/scripts/*.sh)
#     4. write the digest to $RUNNER_TEMP/digest/ARCH
#
#   publish-image.sh tag VERSION DIGEST_DIR   (after BOTH platforms passed)
#     5. refuse again if VERSION exists meanwhile
#     6. image files for installations without internet (from the checked digests) + SHA256SUMS
#     7. only then add the tags: VERSION, and "latest" if VERSION is the highest version
#
#   env: IMAGE = ghcr.io/<owner>/<repo>
set -euo pipefail
mode="${1:?usage: publish-image.sh build VERSION ARCH | tag VERSION DIGEST_DIR}"
version="${2:?usage: publish-image.sh build VERSION ARCH | tag VERSION DIGEST_DIR}"
image="${IMAGE:?set IMAGE, e.g. ghcr.io/owner/repo}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
fail() { echo "::error title=$1::$2"; printf '### %s\n%s\n' "$1" "$2" >> "$summary"; exit 1; }

if docker buildx imagetools inspect "$image:$version" >/dev/null 2>&1; then
  fail "Version already exists" "$image:$version is already published and is never overwritten."
fi

if [ "$mode" = build ]; then
  arch="${3:?usage: publish-image.sh build VERSION ARCH}"
  case "$arch" in amd64|arm64) ;; *) fail "Unknown platform" "$arch" ;; esac
  app_version="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' app/version.py)"
  meta="${RUNNER_TEMP:-/tmp}/build-meta.json"
  docker buildx build --no-cache --pull \
    --platform "linux/$arch" \
    --build-arg "APP_VERSION=$app_version" --build-arg "IMAGE_VERSION=$version" \
    --label "org.opencontainers.image.revision=${REVISION:-${GITHUB_SHA:-}}" \
    --provenance=true --sbom=true \
    --output "type=image,name=$image,push-by-digest=true,name-canonical=true,push=true" \
    --metadata-file "$meta" . \
    || fail "Build failed" "The $arch image for $version could not be built (details in the log of this step)."
  digest="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta")"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Build failed" "No digest for the built $arch image."
  echo "built (untagged): $image@$digest ($arch)"

  docker pull --platform "linux/$arch" "$image@$digest"
  .github/scripts/verify-image.sh "$image@$digest"
  .github/scripts/trivy.sh "$image@$digest"

  mkdir -p "${RUNNER_TEMP:-/tmp}/digest"
  echo "$digest" > "${RUNNER_TEMP:-/tmp}/digest/$arch"
  echo "checked: $image@$digest ($arch)" >> "$summary"
  exit 0
fi

[ "$mode" = tag ] || fail "Unknown step" "$mode (build or tag)"
dir="${3:?usage: publish-image.sh tag VERSION DIGEST_DIR}"
declare -A digests
for arch in amd64 arm64; do
  [ -f "$dir/$arch" ] || fail "Platform missing" "No checked $arch image from this run."
  digests[$arch]="$(cat "$dir/$arch")"
  [[ "${digests[$arch]}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Platform missing" "Invalid $arch digest."
done

# image files for installations without internet (docker load), one per platform, plus checksums
assets="${RUNNER_TEMP:-/tmp}/release-assets"
rm -rf "$assets"; mkdir -p "$assets"
save_opts=(); docker save --help 2>/dev/null | grep -- '--platform' >/dev/null && save_opts=(--platform)
for arch in amd64 arm64; do
  ref="$image@${digests[$arch]}"
  docker pull -q --platform "linux/$arch" "$ref" >/dev/null
  docker tag "$ref" "$image:$version"
  if [ ${#save_opts[@]} -gt 0 ]; then docker save --platform "linux/$arch" "$image:$version"
  else docker save "$image:$version"; fi | gzip -9 > "$assets/samaudit-$version-$arch.tar.gz" \
    || fail "Image file failed" "The image file for $arch could not be created."
  tar -tzf "$assets/samaudit-$version-$arch.tar.gz" | grep '^manifest.json$' >/dev/null \
    || fail "Image file failed" "The image file for $arch is incomplete."
  docker rmi "$image:$version" >/dev/null 2>&1 || true
done
# files for a new installation; .env.example as "env.example" – release uploads skip names starting with "."
cp docker-compose.yml update.sh "$assets/" && cp .env.example "$assets/env.example"
(cd "$assets" && sha256sum samaudit-*.tar.gz docker-compose.yml env.example update.sh > SHA256SUMS)
echo "image files: $(ls "$assets" | tr '\n' ' ')"

tags=(-t "$image:$version")
mapfile -t existing < <(git tag -l 'v*')
if python3 tools/lockutil.py is-highest "$version" "${existing[@]}"; then
  tags+=(-t "$image:latest")
else
  echo "::notice::$version is not the highest version – latest stays unchanged"
fi
docker buildx imagetools create "${tags[@]}" "$image@${digests[amd64]}" "$image@${digests[arm64]}" \
  || fail "Publishing failed" "The tags for $version could not be set."
platforms="$(docker buildx imagetools inspect "$image:$version" --format '{{json .Manifest}}' \
  | python3 -c 'import json, sys; print(" ".join(sorted({m["platform"]["architecture"] for m in json.load(sys.stdin)["manifests"] if m.get("platform", {}).get("os") == "linux"})))')" \
  || fail "Publishing failed" "Could not read back $image:$version."
[ "$platforms" = "amd64 arm64" ] || fail "Publishing failed" "$image:$version contains '$platforms' instead of amd64 and arm64."
{
  echo "### Published: $image:$version"
  echo "amd64: \`${digests[amd64]}\` · arm64: \`${digests[arm64]}\`"
  printf 'Tags: %s\n' "${tags[*]//-t /}"
} >> "$summary"
echo "published: ${tags[*]//-t /} -> amd64 ${digests[amd64]}, arm64 ${digests[arm64]}"
