#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Daily check that SAMAUDIT can be installed by anyone, without a GitHub account:
#   1. the container image ghcr.io/<owner>/<repo>:latest can be pulled anonymously (amd64 and arm64)
#   2. the files of the quick start can be downloaded from the latest release
#   3. (warning only) the image "latest" and the latest release carry the same version
# Any failure turns the run red, so GitHub sends a notification.
#
#   .github/scripts/public-check.sh OWNER/REPO
set -euo pipefail
repo="${1:?usage: public-check.sh OWNER/REPO}"
image="ghcr.io/${repo,,}:latest"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export DOCKER_CONFIG="$work/docker"   # empty Docker config: no stored login, exactly like a stranger
mkdir -p "$DOCKER_CONFIG"
fail=0
err() { echo "::error title=$1::$2"; printf -- '- ❌ **%s**: %s\n' "$1" "$2" >> "$summary"; fail=1; }
ok() { echo "ok: $1"; printf -- '- ✅ %s\n' "$1" >> "$summary"; }

echo "## Public access" >> "$summary"

# 1) image, anonymously
if docker manifest inspect "$image" > "$work/manifest.json" 2> "$work/manifest.err"; then
  for arch in amd64 arm64; do
    if grep '"architecture": *"'"$arch"'"' "$work/manifest.json" >/dev/null; then
      ok "image $image offers linux/$arch"
    else
      err "Image incomplete" "$image has no linux/$arch variant"
    fi
  done
  if docker pull -q --platform linux/amd64 "$image" >/dev/null 2> "$work/pull.err"; then
    image_version="$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")"
    ok "anonymous docker pull of $image works (version ${image_version:-unknown})"
  else
    err "Image not publicly reachable" "docker pull $image without login failed: $(tail -c 300 "$work/pull.err" | tr '\n' ' ')"
  fi
else
  err "Image not publicly reachable" "$image cannot be read without login – is the package still public? $(tail -c 300 "$work/manifest.err" | tr '\n' ' ')"
fi

# 2) quick-start files of the latest release, anonymously
for f in docker-compose.yml env.example update.sh SHA256SUMS; do
  url="https://github.com/$repo/releases/latest/download/$f"
  if curl -fsSL --retry 3 --retry-delay 5 -o "$work/$f" "$url" && [ -s "$work/$f" ]; then
    ok "release file $f downloadable"
  else
    err "Release file missing" "$url cannot be downloaded – the quick start would fail"
  fi
done

# 3) same version for image and release (warning only: right after a release this may lag a few minutes)
tag="$(curl -fsS -o /dev/null -w '%{redirect_url}' "https://github.com/$repo/releases/latest" | sed -n 's#.*/tag/v##p')"
if [ -n "${image_version:-}" ] && [ -n "$tag" ] && [ "$tag" != "$image_version" ]; then
  echo "::warning title=Versions differ::image latest is $image_version, latest release is $tag"
  printf -- '- ⚠️ image latest is %s, latest release is %s\n' "$image_version" "$tag" >> "$summary"
fi

exit "$fail"
