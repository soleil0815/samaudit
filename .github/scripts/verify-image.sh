#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Checks a built image before anything is published:
#   1. the Debian packages in the image match locks/os-packages.txt exactly (reproducible build)
#   2. the automatic tests (tests/smoke.py) pass INSIDE the image
#   3. pip and apt are no longer present
# and writes the package versions to the job summary.
#
#   .github/scripts/verify-image.sh IMAGE [--record]   --record: write the list instead of comparing
set -euo pipefail
image="${1:?usage: verify-image.sh IMAGE [--record]}"
record="${2:-}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
fail() { echo "::error title=$1::$2"; printf '### %s\n%s\n' "$1" "$2" >> "$summary"; exit 1; }

run() { docker run --rm --entrypoint "$1" "$image" "${@:2}"; }

run cat /app/os-packages.txt > "${RUNNER_TEMP:-/tmp}/os-packages.txt"
if [ "$record" = "--record" ]; then
  mkdir -p locks && cp "${RUNNER_TEMP:-/tmp}/os-packages.txt" locks/os-packages.txt
elif ! diff -u locks/os-packages.txt "${RUNNER_TEMP:-/tmp}/os-packages.txt" > "${RUNNER_TEMP:-/tmp}/os-diff.txt"; then
  fail "Bau nicht reproduzierbar" "Die Debian-Pakete im Image weichen von locks/os-packages.txt ab:
$(head -40 "${RUNNER_TEMP:-/tmp}/os-diff.txt")"
fi

docker run --rm --entrypoint python -v "$PWD/tests:/app/tests:ro" "$image" tests/smoke.py \
  || fail "Tests im Image fehlgeschlagen" "tests/smoke.py ist im fertigen Image nicht durchgelaufen (Details im Log dieses Schritts)."

if run sh -c 'command -v pip || command -v apt-get || command -v apt || python -c "import pip"' >/dev/null 2>&1; then
  fail "Paketmanager im Image" "pip oder apt ist noch im Image vorhanden."
fi

{
  echo "### Image $image"
  echo '```'
  run python -c "import os, platform; print('SAMAUDIT', os.environ.get('SAMAUDIT_IMAGE_VERSION'), '| Python', platform.python_version())"
  run sh -c '. /etc/os-release; echo "$PRETTY_NAME"'
  echo "Debian-Pakete: $(wc -l < "${RUNNER_TEMP:-/tmp}/os-packages.txt")"
  run cat /app/package-versions.txt
  echo '```'
} >> "$summary"
echo "image verified: $image"
