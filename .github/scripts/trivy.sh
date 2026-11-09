#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Vulnerability scan of a container image with Trivy.
#
#   .github/scripts/trivy.sh IMAGE
#
# Trivy is NOT taken from a GitHub Action or a "latest" download: in March 2026 the
# trivy-action / setup-trivy tags and release v0.69.4 were hijacked (CVE-2026-33634).
# Instead a fixed release is downloaded and checked against the SHA-256 pinned below.
# To update: new version + checksum from trivy_<version>_checksums.txt of that release
# (use a release that is at least two weeks old).
#
# Blocking (exit code 1): CRITICAL/HIGH vulnerabilities for which a fixed version exists, and any
# failure of the scan itself. Everything else is only reported (job summary + artifact).
# Accepted exceptions: .trivyignore – one ID per line with a reason and an expiry date
# ("CVE-2026-1234 exp:2027-01-31  # reason"); expired entries no longer apply.
set -euo pipefail

TRIVY_VERSION=0.75.0
TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f   # trivy_0.75.0_Linux-64bit.tar.gz
TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3   # trivy_0.75.0_Linux-ARM64.tar.gz

image="${1:?usage: trivy.sh IMAGE}"
bin="${RUNNER_TEMP:-/tmp}/trivy-$TRIVY_VERSION"
out="${RUNNER_TEMP:-/tmp}/trivy-report"
mkdir -p "$bin" "$out"

if [ -n "${TRIVY_BIN:-}" ]; then
  trivy="$TRIVY_BIN"                      # self-tests: a stand-in for trivy
elif [ ! -x "$bin/trivy" ]; then
  # the release for this runner: the release jobs scan each platform on its own hardware
  case "$(uname -m)" in
    x86_64) asset=Linux-64bit; sum="$TRIVY_SHA256" ;;
    aarch64|arm64) asset=Linux-ARM64; sum="$TRIVY_SHA256_ARM64" ;;
    *) echo "::error::No pinned Trivy release for $(uname -m)"; exit 1 ;;
  esac
  tgz="$bin/trivy.tgz"
  # GitHub's release download answers now and then with 502/504: retry patiently before giving up
  curl -sSfL --retry 6 --retry-delay 15 --retry-all-errors --connect-timeout 20 -o "$tgz" \
    "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${asset}.tar.gz" \
    || { echo "::error title=Trivy download failed::trivy_${TRIVY_VERSION}_${asset}.tar.gz could not be downloaded (GitHub not reachable?) – start the run again later"; exit 1; }
  echo "${sum}  $tgz" | sha256sum -c - || { echo "::error::Trivy download does not match the pinned checksum"; exit 1; }
  tar xzf "$tgz" -C "$bin" trivy
fi
trivy="${trivy:-$bin/trivy}"
"$trivy" --version

ignore=()
[ -f .trivyignore ] && ignore=(--ignorefile .trivyignore)

# 1) full report (all severities, also unfixed) – for information only
"$trivy" image --quiet --scanners vuln --format table "${ignore[@]}" "$image" > "$out/full.txt" || true
"$trivy" image --quiet --scanners vuln --format json "${ignore[@]}" "$image" > "$out/full.json" || true

# 2) gate: CRITICAL/HIGH with an available fix
set +e
"$trivy" image --quiet --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 3 \
  --format json --output "$out/blocking.json" "${ignore[@]}" "$image" > "$out/blocking.txt" 2>&1
rc=$?
set -e
echo "$rc" > "$out/rc"
# compact list: package, installed → fixed version, CVE, severity (also as annotation, readable via API)
python3 - "$out/blocking.json" > "$out/blocking-list.txt" <<'PY' || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
rows = []
for res in data.get("Results") or []:
    for v in res.get("Vulnerabilities") or []:
        rows.append(f'{v.get("Severity", "?"):8} {v.get("PkgName")} {v.get("InstalledVersion")} -> '
                    f'{v.get("FixedVersion")}  {v.get("VulnerabilityID")}  [{res.get("Target")}]')
print("\n".join(sorted(set(rows))))
PY
[ -s "$out/blocking-list.txt" ] && cat "$out/blocking-list.txt" >> "$out/blocking.txt"

{
  echo "## Trivy: $image"
  if [ "$rc" = 0 ]; then
    echo "No CRITICAL/HIGH vulnerabilities with an available fix."
  elif [ "$rc" != 3 ]; then
    echo "**Scan failed** (exit code $rc) – treated as blocking, the image is not published."
    echo; echo '```'; tail -c 20000 "$out/blocking.txt"; echo '```'
  else
    echo "**Blocking:** CRITICAL/HIGH vulnerabilities with an available fix – the image is not published."
    echo; echo '```'; head -c 60000 "$out/blocking.txt"; echo '```'
  fi
  echo; echo "<details><summary>Full report (all severities, including unfixed)</summary>"; echo
  echo '```'; head -c 60000 "$out/full.txt"; echo '```'; echo "</details>"
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"

case "$rc" in
  0) exit 0 ;;
  3) msg="$(head -40 "$out/blocking-list.txt" 2>/dev/null | sed ':a;N;$!ba;s/%/%25/g;s/\n/%0A/g')"
     echo "::error title=Trivy: fixable CRITICAL/HIGH vulnerabilities in $image::${msg:-see job summary}"; exit 1 ;;
  *) echo "::error::Trivy scan failed (exit code $rc) – not publishing without a successful scan"; exit 1 ;;
esac
