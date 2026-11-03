# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests for tools/clean-history.sh (rewrites names/addresses out of the Git history)."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "clean-history.sh"
NOREPLY = "222504472+soleil0815@users.noreply.github.com"


def git(cwd, *args, env=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, **(env or {})}).stdout


def commit(repo, msg, name, email, cname=None, cemail=None):
    git(repo, "commit", "-q", "--allow-empty", "-m", msg,
        env={"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
             "GIT_COMMITTER_NAME": cname or name, "GIT_COMMITTER_EMAIL": cemail or email})


class CleanHistory(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="clean-history-"))
        work = self.tmp / "work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        (work / "f.txt").write_text("eins\n")
        git(work, "add", "f.txt")
        commit(work, "start", "Max Muster", "max@example.org")
        commit(work, "claude", "Claude", "noreply@anthropic.com")
        commit(work, "merge via web", "Max", NOREPLY, "GitHub", "noreply@github.com")
        git(work, "tag", "v1.0.0")
        commit(work, "bot", "github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com")
        git(work, "branch", "alt", "HEAD~2")
        self.remote = self.tmp / "remote.git"
        git(self.tmp, "clone", "-q", "--bare", str(work), str(self.remote))
        self.tree = git(self.remote, "rev-parse", "main^{tree}").strip()

    def run_script(self, *args, answer="y\ny\n", email=NOREPLY):
        return subprocess.run(["bash", str(SCRIPT), *args], input=answer, capture_output=True, text=True,
                              env={**os.environ, "NEW_EMAIL": email})

    def idents(self):
        out = git(self.remote, "log", "main", "--tags", "--format=%an <%ae>%n%cn <%ce>")
        return set(out.splitlines())

    def test_in_place_rewrites_only_people_and_keeps_contents(self):
        r = self.run_script("--in-place", str(self.remote))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ids = self.idents()
        self.assertNotIn("Max Muster <max@example.org>", ids)
        self.assertNotIn(f"Max <{NOREPLY}>", ids)
        self.assertIn(f"soleil0815 <{NOREPLY}>", ids)                      # name taken from the noreply address
        self.assertIn("Claude <noreply@anthropic.com>", ids)
        self.assertIn("GitHub <noreply@github.com>", ids)
        self.assertEqual(git(self.remote, "rev-parse", "main^{tree}").strip(), self.tree)
        self.assertEqual(git(self.remote, "rev-list", "--count", "main").strip(), "4")
        self.assertEqual(git(self.remote, "tag").split(), ["v1.0.0"])
        self.assertNotIn("alt", git(self.remote, "branch"))                  # old branch deleted on request
        self.assertNotIn("Max", git(self.remote, "log", "v1.0.0", "--format=%an %cn"))

    def test_nothing_pushed_without_yes(self):
        before = git(self.remote, "rev-parse", "main").strip()
        r = self.run_script("--in-place", str(self.remote), answer="n\n")
        self.assertEqual(r.returncode, 0)
        self.assertIn("nothing pushed", r.stdout)
        self.assertEqual(git(self.remote, "rev-parse", "main").strip(), before)

    def test_refuses_unknown_identity_that_cannot_be_rewritten(self):
        work = self.tmp / "work"
        commit(work, "kept by address but wrong name", "Michael", "noreply@github.com")
        git(work, "push", "-q", str(self.remote), "main")
        before = git(self.remote, "rev-parse", "main").strip()
        r = self.run_script("--in-place", str(self.remote))
        self.assertEqual(r.returncode, 1)
        self.assertIn("STOP", r.stderr)
        self.assertEqual(git(self.remote, "rev-parse", "main").strip(), before)

    def test_argument_checks(self):
        self.assertEqual(self.run_script("a", "a").returncode, 2)            # same source and target
        self.assertEqual(self.run_script("--in-place", "x", email="me@example.org").returncode, 2)
        self.assertEqual(self.run_script().returncode, 2)


if __name__ == "__main__":
    unittest.main()
