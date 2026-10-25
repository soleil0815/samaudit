# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests of the build and release machinery (no Docker, no network).

Covered: pinned build inputs, schedules, order of the steps, permissions/pinning of the
workflows, version bounds, release numbering, "latest only for the highest version",
end-of-life thresholds and the Trivy gate with a stand-in for trivy."""
from __future__ import annotations

import datetime as dt
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import lockutil  # noqa: E402

WF = ROOT / ".github" / "workflows"
POLICY = dict(line.split("=", 1) for line in (ROOT / "tools/lock-policy.env").read_text().splitlines()
              if line and not line.startswith("#"))


def workflow(name: str) -> dict:
    data = yaml.safe_load((WF / name).read_text(encoding="utf-8"))
    data["on"] = data.pop(True, data.get("on"))     # YAML 1.1 reads "on" as True
    return data


def step_index(job: dict, step_id: str) -> int:
    for i, s in enumerate(job["steps"]):
        if s.get("id") == step_id:
            return i
    raise AssertionError(f"step id {step_id!r} missing")


class PinnedBuild(unittest.TestCase):
    def test_base_image_has_series_codename_and_digest(self):
        df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        base = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", df, re.M).group(1)
        series, codename = POLICY["PYTHON_SERIES"], POLICY["DEBIAN_CODENAME"]
        self.assertRegex(base, rf"^python:{re.escape(series)}\.\d+-slim-{codename}@sha256:[0-9a-f]{{64}}$")
        self.assertNotRegex(base, r"@sha256:0{64}$", "placeholder digest – run tools/update-locks.sh")
        self.assertIn(f"ARG DEBIAN_CODENAME={codename}", df)
        self.assertRegex(df, r"(?m)^ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z$")

    def test_every_python_package_pinned_with_hashes(self):
        lines = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        reqs = [ln for ln in lines if re.match(r"^[A-Za-z0-9]", ln)]
        self.assertGreater(len(reqs), 5)
        for ln in reqs:
            self.assertRegex(ln, r"^[A-Za-z0-9._-]+==[^\s]+", f"not pinned exactly: {ln}")
        text = "\n".join(lines)
        blocks = re.split(r"\n(?=[A-Za-z0-9])", text[text.find(reqs[0]):])
        for b in blocks:
            self.assertIn("--hash=sha256:", b, f"no hash: {b.splitlines()[0]}")

    def test_os_package_list_present(self):
        lines = (ROOT / "locks/os-packages.txt").read_text(encoding="utf-8").splitlines()
        self.assertGreater(len(lines), 20)
        self.assertTrue(all(len(ln.split()) == 2 for ln in lines))
        self.assertFalse(any(ln.split()[0] == "apt" for ln in lines), "apt must be removed from the image")

    def test_dockerfile_order_and_cleanup(self):
        df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        i_apt = df.index("apt-get -o Acquire::Check-Valid-Until=false")
        i_pip = df.index("--require-hashes")
        i_rm_pip = df.index("pip uninstall -y pip")
        i_rm_apt = df.index("dpkg --purge")
        i_list = df.index("dpkg-query -W")
        self.assertLess(i_apt, i_pip)
        self.assertLess(i_pip, i_rm_pip)
        self.assertLess(i_rm_apt, i_list, "package list must be written after removing apt")
        self.assertIn("snapshot.debian.org", df)
        self.assertNotIn("--upgrade-strategy", df)


class Workflows(unittest.TestCase):
    ALL = sorted(p.name for p in WF.glob("*.yml"))

    def test_actions_pinned_to_commit_hashes(self):
        for name in self.ALL:
            for line in (WF / name).read_text(encoding="utf-8").splitlines():
                m = re.search(r"uses:\s*(\S+)", line)
                if m and not m.group(1).startswith("./"):
                    self.assertRegex(m.group(1), r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", f"{name}: {line.strip()}")

    def test_no_trivy_action(self):
        for name in self.ALL:
            text = (WF / name).read_text(encoding="utf-8")
            self.assertNotIn("trivy-action", text)
            self.assertNotIn("setup-trivy", text)

    def test_minimal_permissions_and_no_stored_credentials(self):
        for name in self.ALL:
            wf = workflow(name)
            self.assertEqual(wf.get("permissions"), {}, f"{name}: top-level permissions must be empty")
            for jname, job in wf["jobs"].items():
                self.assertIn("permissions", job, f"{name}/{jname}: no job permissions")
                for s in job.get("steps", []):
                    if "actions/checkout@" in s.get("uses", ""):
                        self.assertIs((s.get("with") or {}).get("persist-credentials"), False,
                                      f"{name}/{jname}: checkout must not persist credentials")

    def test_schedules(self):
        sec = workflow("security-update.yml")["on"]
        cron = sec["schedule"][0]["cron"].split()
        self.assertEqual(cron[4], "1", "security update must run on Mondays")
        self.assertLessEqual(int(cron[1]), 6, "security update must run early in the morning")
        self.assertIn("workflow_dispatch", sec)
        daily = workflow("scan-published.yml")["on"]
        d = daily["schedule"][0]["cron"].split()
        self.assertEqual(d[2:], ["*", "*", "*"], "published image must be scanned daily")
        self.assertNotIn("schedule", workflow("docker-image.yml")["on"], "program releases are not scheduled")

    def test_publishing_only_from_main_and_never_twice_at_once(self):
        for name, job in (("docker-image.yml", "publish"), ("security-update.yml", "publish"),
                          ("security-update.yml", "prepare")):
            j = workflow(name)["jobs"][job]
            self.assertIn("refs/heads/main", j["if"], f"{name}/{job}: only from main")
        for name in ("docker-image.yml", "security-update.yml"):
            j = workflow(name)["jobs"]["publish"]
            self.assertEqual(j["concurrency"], {"group": "release", "cancel-in-progress": False})

    def test_security_update_step_order(self):
        jobs = workflow("security-update.yml")["jobs"]
        prep = jobs["prepare"]
        order = [step_index(prep, s) for s in ("locks", "verify", "trivy", "upload")]
        self.assertEqual(order, sorted(order), "prepare: locks -> tests -> Trivy -> hand over")
        for sid in ("verify", "trivy", "upload"):
            self.assertIn("changed == 'true'", prep["steps"][step_index(prep, sid)]["if"])
        self.assertIn("update-locks.sh", prep["steps"][step_index(prep, "locks")]["run"])
        pub = jobs["publish"]
        self.assertEqual(pub["needs"], "prepare")
        self.assertIn("changed == 'true'", pub["if"])
        order = [step_index(pub, s) for s in ("version", "commit", "publish", "release")]
        self.assertEqual(order, sorted(order))
        self.assertIn("next-version", pub["steps"][step_index(pub, "version")]["run"])

    def test_release_step_order(self):
        jobs = workflow("docker-image.yml")["jobs"]
        b = jobs["build"]
        order = [step_index(b, s) for s in ("build", "verify", "trivy")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(sorted(jobs["publish"]["needs"]), ["build", "test"])
        self.assertEqual(sorted(jobs["automerge"]["needs"]), ["build", "test"])

    def test_publish_script_checks_before_tagging(self):
        s = (ROOT / ".github/scripts/publish-image.sh").read_text(encoding="utf-8")
        order = [s.index(x) for x in ("imagetools inspect", "--no-cache", "push-by-digest=true",
                                       "verify-image.sh", "trivy.sh", "is-highest", "imagetools create")]
        self.assertEqual(order, sorted(order), "exists? -> build -> check -> trivy -> latest? -> tag")


class VersionBounds(unittest.TestCase):
    def test_upper_bounds(self):
        self.assertEqual(lockutil.upper_bound("starlette", "1.6.2"), "2")
        self.assertEqual(lockutil.upper_bound("cryptography", "50.0.1"), "51")
        self.assertEqual(lockutil.upper_bound("uvicorn", "0.53.0"), "0.54")
        self.assertIsNone(lockutil.upper_bound("tzdata", "2025.2"))
        self.assertIsNone(lockutil.upper_bound("certifi", "2026.10.19"))

    def test_constraints_from_lock(self):
        lock = "starlette==1.6.0 \\\n    --hash=sha256:aa\nuvicorn==0.53.1 ; python_version >= '3.9'\ntzdata==2025.2\n"
        c = lockutil.constraints(lock)
        self.assertIn("starlette>=1.6.0,<2", c)
        self.assertIn("uvicorn>=0.53.1,<0.54", c)
        self.assertIn("tzdata>=2025.2\n", c)

    def test_within_bounds(self):
        old = {"starlette": "1.6.0", "uvicorn": "0.53.0", "tzdata": "2025.2"}
        self.assertEqual(lockutil.within_bounds(old, {"starlette": "1.9.3", "uvicorn": "0.53.9", "tzdata": "2026.1"}), [])
        self.assertTrue(lockutil.within_bounds(old, {"starlette": "2.0.0"}))
        self.assertTrue(lockutil.within_bounds(old, {"uvicorn": "0.54.0"}))
        self.assertTrue(lockutil.within_bounds(old, {"starlette": "1.5.0"}))

    def test_pick_base_stays_in_series_and_release(self):
        lib = ("Tags: 3.14.1-slim-trixie, 3.14-slim\n"
               "Tags: 3.13.17-slim-trixie, 3.13-slim-trixie, 3.13.17-slim\n"
               "Tags: 3.13.18rc1-slim-trixie\n"
               "Tags: 3.13.19-slim-bookworm\n"
               "Tags: 3.13.9-slim-trixie\n")
        self.assertEqual(lockutil.pick_base(lib, "3.13", "trixie"), "3.13.17-slim-trixie")
        with self.assertRaises(ValueError):
            lockutil.pick_base(lib, "3.12", "trixie")


class ReleaseNumbers(unittest.TestCase):
    def test_counter(self):
        self.assertEqual(lockutil.next_version("1.9.7", ["v1.9.6", "v1.9.6-s3", "v1.9.7"]), "1.9.7-s1")
        self.assertEqual(lockutil.next_version("1.9.7", ["v1.9.7", "v1.9.7-s1", "v1.9.7-s2"]), "1.9.7-s3")
        self.assertEqual(lockutil.next_version("1.9.8", ["v1.9.7-s5"]), "1.9.8-s1")

    def test_latest_only_for_highest(self):
        tags = ["v1.9.6", "v1.9.6-s2", "v1.9.7", "v1.9.7-s1"]
        self.assertTrue(lockutil.is_highest("1.9.7-s2", tags))
        self.assertTrue(lockutil.is_highest("1.10.0", tags))
        self.assertFalse(lockutil.is_highest("1.9.6-s3", tags))
        self.assertFalse(lockutil.is_highest("1.9.7", tags))


class EndOfLife(unittest.TestCase):
    def test_thresholds(self):
        today = dt.date(2028, 1, 1)
        self.assertEqual(lockutil.eol_status("2029-10-31", today)[0], "ok")
        self.assertEqual(lockutil.eol_status("2028-11-30", today)[0], "notice")
        self.assertEqual(lockutil.eol_status("2028-05-01", today)[0], "fail")

    def test_api_formats(self):
        self.assertEqual(lockutil.eol_date({"result": {"eolFrom": "2029-10-31"}}), "2029-10-31")
        self.assertEqual(lockutil.eol_date({"eol": "2028-08-09"}), "2028-08-09")
        self.assertIsNone(lockutil.eol_date({"eol": False}))


class TrivyGate(unittest.TestCase):
    """trivy.sh with a stand-in: exit 3 = fixable HIGH/CRITICAL found, other = scan failure."""

    def run_gate(self, gate_rc: int) -> subprocess.CompletedProcess:
        tmp = Path(tempfile.mkdtemp())
        fake = tmp / "trivy"
        fake.write_text("#!/bin/sh\n"
                        "case \"$*\" in *--version*) echo 'Version: fake'; exit 0;; esac\n"
                        "case \"$*\" in *--exit-code*) out=''; prev=''\n"
                        "  for a in \"$@\"; do [ \"$prev\" = --output ] && out=\"$a\"; prev=\"$a\"; done\n"
                        "  printf '%s' '{\"Results\":[{\"Target\":\"Python\",\"Vulnerabilities\":"
                        "[{\"Severity\":\"HIGH\",\"PkgName\":\"demo\",\"InstalledVersion\":\"1\","
                        "\"FixedVersion\":\"2\",\"VulnerabilityID\":\"CVE-0000-1\"}]}]}' > \"$out\"\n"
                        f"  exit {gate_rc};;\nesac\nexit 0\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        env = dict(os.environ, TRIVY_BIN=str(fake), RUNNER_TEMP=str(tmp), GITHUB_STEP_SUMMARY=str(tmp / "sum.md"))
        return subprocess.run(["bash", str(ROOT / ".github/scripts/trivy.sh"), "image:test"],
                              cwd=ROOT, env=env, capture_output=True, text=True)

    def test_clean_passes(self):
        self.assertEqual(self.run_gate(0).returncode, 0)

    def test_fixable_findings_block_with_readable_reason(self):
        r = self.run_gate(3)
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error title=Trivy", r.stdout)
        self.assertIn("CVE-0000-1", r.stdout)

    def test_scan_failure_blocks(self):
        r = self.run_gate(1)
        self.assertEqual(r.returncode, 1)
        self.assertIn("scan failed", r.stdout)

    def test_trivy_pinned_by_checksum(self):
        s = (ROOT / ".github/scripts/trivy.sh").read_text(encoding="utf-8")
        self.assertRegex(s, r"(?m)^TRIVY_VERSION=\d+\.\d+\.\d+$")
        self.assertRegex(s, r"(?m)^TRIVY_SHA256=[0-9a-f]{64}")
        self.assertIn("sha256sum -c", s)

    def test_trivyignore_entries_have_reason_and_expiry(self):
        p = ROOT / ".trivyignore"
        for line in p.read_text(encoding="utf-8").splitlines() if p.exists() else []:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            m = re.match(r"^(\S+)\s+exp:(\d{4}-\d{2}-\d{2})\s+#\s*\S.{9,}$", entry)
            self.assertIsNotNone(m, f".trivyignore needs 'ID exp:YYYY-MM-DD  # reason': {entry}")
            self.assertGreater(dt.date.fromisoformat(m.group(2)), dt.date.today(), f"expired: {entry}")


if __name__ == "__main__":
    unittest.main()
