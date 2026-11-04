# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests for .github/scripts/public-check.sh with stand-ins for docker and curl."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "public-check.sh"

FAKE_DOCKER = r'''#!/usr/bin/env bash
# records whether a login config exists; behaves according to $FAKE_IMAGE (public|private|amd64only)
[ -z "$(ls -A "$DOCKER_CONFIG" 2>/dev/null)" ] || { echo "credentials present" >&2; exit 9; }
case "$1 $2" in
  "manifest inspect")
    [ "$FAKE_IMAGE" = private ] && { echo "unauthorized" >&2; exit 1; }
    echo '{"manifests":[{"platform":{"architecture": "amd64","os":"linux"}}'
    [ "$FAKE_IMAGE" = amd64only ] || echo ',{"platform":{"architecture": "arm64","os":"linux"}}'
    echo ']}' ;;
  "pull -q") [ "$FAKE_IMAGE" = private ] && exit 1; exit 0 ;;
  "inspect --format") echo "2.1.7" ;;
  *) exit 0 ;;
esac
'''

FAKE_CURL = r'''#!/usr/bin/env bash
# release files: present unless listed in $FAKE_MISSING; "releases/latest" redirects to $FAKE_TAG
out=""; url=""; wout=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift ;; -w) wout="$2"; shift ;; --retry|--retry-delay) shift ;; -*) ;; *) url="$1" ;; esac
  shift
done
case "$url" in
  */releases/latest) [ -n "$wout" ] && printf 'https://github.com/o/r/releases/tag/v%s' "$FAKE_TAG"; exit 0 ;;
  */releases/latest/download/*)
    f="${url##*/}"
    case " $FAKE_MISSING " in *" $f "*) exit 22 ;; esac
    [ -n "$out" ] && echo data > "$out"; exit 0 ;;
esac
exit 22
'''


class PublicCheck(unittest.TestCase):
    def run_check(self, image="public", missing="", tag="2.1.7"):
        tmp = Path(tempfile.mkdtemp(prefix="public-check-"))
        for name, body in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL)):
            p = tmp / name
            p.write_text(body)
            p.chmod(p.stat().st_mode | stat.S_IEXEC)
        summary = tmp / "summary.md"
        env = {**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}", "FAKE_IMAGE": image, "FAKE_MISSING": missing,
               "FAKE_TAG": tag, "GITHUB_STEP_SUMMARY": str(summary)}
        env.pop("DOCKER_CONFIG", None)
        r = subprocess.run(["bash", str(SCRIPT), "Owner/Repo"], capture_output=True, text=True, env=env)
        return r, summary.read_text() if summary.exists() else ""

    def test_all_public(self):
        r, summary = self.run_check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("::error", r.stdout)
        self.assertIn("anonymous docker pull of ghcr.io/owner/repo:latest works", summary)

    def test_private_image_turns_red(self):
        r, _ = self.run_check(image="private")
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error title=Image not publicly reachable::", r.stdout)

    def test_missing_platform_turns_red(self):
        r, _ = self.run_check(image="amd64only")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no linux/arm64 variant", r.stdout)

    def test_missing_release_file_turns_red(self):
        r, _ = self.run_check(missing="env.example")
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error title=Release file missing::", r.stdout)
        self.assertIn("env.example", r.stdout)

    def test_version_mismatch_is_only_a_warning(self):
        r, _ = self.run_check(tag="2.1.6")
        self.assertEqual(r.returncode, 0)
        self.assertIn("::warning title=Versions differ::", r.stdout)


if __name__ == "__main__":
    unittest.main()
