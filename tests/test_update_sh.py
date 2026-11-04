# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self-tests for update.sh – with a stand-in docker (tests/fakedocker), always under dash or /bin/sh,
only in temp folders (never in the real /etc, never in real data folders)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fakedocker"
SH = shutil.which("dash") or "/bin/sh"
REPO = "ghcr.io/soleil0815/samaudit"


def compose_text(version: int) -> str:
    t = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    return t.replace('SAMAUDIT_COMPOSE: "1"', f'SAMAUDIT_COMPOSE: "{version}"')


class Env:
    """An installation folder + state of the stand-in docker."""

    def __init__(self, tc: unittest.TestCase, name: str = "install"):
        self.tmp = Path(tempfile.mkdtemp(prefix="samaudit-test-"))
        tc.addCleanup(shutil.rmtree, self.tmp, True)
        self.extra_env: dict[str, str] = {}
        self.extra_path = ""
        self.dir = self.tmp / name
        self.dir.mkdir()
        shutil.copy(ROOT / "update.sh", self.dir / "update.sh")
        (self.dir / ".env").write_text("DOMAIN_FQDN=firma.local\nPORT=9400\n", encoding="utf-8")
        self.rootfs = self.tmp / "root"            # stand-in for "/" (systemd unit etc.)
        (self.rootfs / "proc").mkdir(parents=True)
        (self.rootfs / "proc" / "mounts").write_text("", encoding="utf-8")
        self.state_file = self.tmp / "state.json"
        self.state = {"registry": {}, "images": {}, "meta": {}, "containers": {}, "networks": {}, "calls": []}
        self.dists = self.tmp / "dists"
        self.save()

    def image(self, iid: str, version: str, health: str = "healthy", compose_version: int = 1,
              tags: tuple[str, ...] = ("latest",), local: bool = False) -> None:
        dist = self.dists / iid
        dist.mkdir(parents=True)
        (dist / "docker-compose.yml").write_text(compose_text(compose_version), encoding="utf-8")
        (dist / ".env.example").write_text("DOMAIN_FQDN=firma.local\n", encoding="utf-8")
        shutil.copy(ROOT / "update.sh", dist / "update.sh")
        self.state["meta"][iid] = {"version": version, "dist": str(dist), "health": health}
        for t in tags:
            self.state["registry"][f"{REPO}:{t}"] = iid
            if local:
                self.state["images"][f"{REPO}:{t}"] = iid
        self.save()

    def running(self, iid: str, compose: bool = True) -> None:
        labels = {"com.docker.compose.project": "samaudit",
                  "com.docker.compose.project.working_dir": str(self.dir)} if compose else {}
        self.state["containers"]["samaudit"] = {"image": iid, "health": "healthy", "labels": labels,
                                               "mounts": [str(self.dir / "data")]}
        self.save()

    def save(self) -> None:
        self.state_file.write_text(json.dumps(self.state), encoding="utf-8")

    def load(self) -> dict:
        self.state = json.loads(self.state_file.read_text(encoding="utf-8"))
        return self.state

    def run(self, *args: str, inp: str | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
        env = {"PATH": f"{self.extra_path}{FAKE}:{os.environ['PATH']}", "FAKE_STATE": str(self.state_file),
               "SAMAUDIT_TEST_ROOT": str(self.rootfs), "SAMAUDIT_HEALTH_TIMEOUT": "6", "HOME": str(self.tmp),
               "LANG": "C.UTF-8", **self.extra_env}
        r = subprocess.run([SH, str(self.dir / "update.sh"), *args], cwd=cwd or self.dir, env=env, input=inp, capture_output=True,
                           text=True, timeout=120)
        self.load()
        self.out = r.stdout + r.stderr
        return r

    def calls(self, *prefix: str) -> list[dict]:
        return [c for c in self.state["calls"] if c["argv"][:len(prefix)] == list(prefix)]


class UpdateFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chmod(FAKE / "docker", 0o755)

    def test_runs_with_plain_sh(self):
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh"))
        r = subprocess.run([SH, "-n", str(ROOT / "update.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        for bashism in (r"\[\[ ", r"\bmapfile\b", "<<<", r"\$\{PIPESTATUS", r"\bdeclare ", r"\blocal\b",
                        r"(^|[\s=(])\$'", r"\bsource ", r"\bfunction "):
            self.assertIsNone(re.search(bashism, text), f"bash-only syntax: {bashism}")

    def test_fresh_install_takes_compose_file_from_image(self):
        e = Env(self)
        e.image("img2", "2.0.1")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertTrue((e.dir / "docker-compose.yml").exists())
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img2")
        self.assertTrue(e.calls("compose", "up", "-d"))
        self.assertFalse(e.calls("build"), "update.sh must never build")

    def test_update_remembers_previous_and_starts_new(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img2", "2.0.1")
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual(e.state["images"][f"{REPO}:previous"], "img1")
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img2")
        self.assertIn("2.0.0", e.out)
        self.assertIn("2.0.1", e.out)

    def test_nothing_to_do_when_current(self):
        e = Env(self)
        e.image("img2", "2.0.1", local=True)
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img2")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertIn("nothing to do", e.out)
        self.assertFalse(e.calls("compose", "up", "-d"))

    def test_failed_start_rolls_back_and_restores_database(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img3", "2.0.1-s2", health="unhealthy")
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        r = e.run("-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img1", e.out)
        runs = e.calls("compose", "run")
        self.assertTrue(runs, e.out)
        self.assertEqual(runs[0]["argv"][-2], "--rollback")
        self.assertTrue(runs[0]["argv"][-1].isdigit())                # start time of the update
        self.assertEqual(runs[0]["SAMAUDIT_VERSION"], "latest")      # restore with the new image
        # the previous version runs under its own number, .env is pinned to it
        self.assertIn("SAMAUDIT_VERSION=2.0.0", (e.dir / ".env").read_text())
        self.assertEqual(e.state["images"][f"{REPO}:2.0.0"], "img1")
        self.assertIn("previous version 2.0.0 is running again", e.out)

    def test_rollback_resets_the_version_in_env(self):
        e = Env(self)
        (e.dir / ".env").write_text("DOMAIN_FQDN=firma.local\nSAMAUDIT_VERSION=2.0.0\n", encoding="utf-8")
        e.image("img1", "2.0.0", tags=("2.0.0",), local=True)
        e.image("img3", "2.0.1", health="unhealthy", tags=("2.0.1",))
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        r = e.run("-y", "--version=2.0.1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SAMAUDIT_VERSION=2.0.0", (e.dir / ".env").read_text())
        self.assertNotIn("2.0.1", (e.dir / ".env").read_text())

    def test_restore_then_older_version(self):
        e = Env(self)
        e.image("img2", "2.1.0", tags=("latest",), local=True)
        e.image("img1", "2.0.0", tags=("2.0.0",))
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img2")
        r = e.run("-y", "--restore", "samaudit-vor-2.1.0-20261029-030000.db", "--version=2.0.0")
        self.assertEqual(r.returncode, 0, e.out)
        runs = e.calls("compose", "run")
        self.assertEqual(runs[0]["argv"][-2:], ["restore", "samaudit-vor-2.1.0-20261029-030000.db"])
        idx_run = e.state["calls"].index(runs[0])
        ups = [i for i, c in enumerate(e.state["calls"]) if c["argv"][:3] == ["compose", "up", "-d"]]
        self.assertEqual(len(ups), 1, "no start of the newer version in between")
        self.assertGreater(ups[0], idx_run)
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img1")
        self.assertIn("SAMAUDIT_VERSION=2.0.0", (e.dir / ".env").read_text())

    def test_failed_start_asks_before_rollback(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img3", "2.0.1", health="unhealthy")
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        r = e.run()                     # without -y and without a terminal: no silent decision
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(e.calls("compose", "run"))

    def test_version_is_written_to_env(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("2.0.0",))
        r = e.run("-y", "--version=2.0.0")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertIn("SAMAUDIT_VERSION=2.0.0", (e.dir / ".env").read_text())
        self.assertTrue(e.calls("pull", f"{REPO}:2.0.0"))
        r = e.run("-y", "--version=../../etc")
        self.assertNotEqual(r.returncode, 0)

    def test_newer_compose_file_replaces_old_and_keeps_alt(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img2", "2.1.0", compose_version=2)
        (e.dir / "docker-compose.yml").write_text(compose_text(1) + "# own line\n", encoding="utf-8")
        e.running("img1")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertIn('SAMAUDIT_COMPOSE: "2"', (e.dir / "docker-compose.yml").read_text())
        self.assertIn("# own line", (e.dir / "docker-compose.yml.alt").read_text())

    def test_same_compose_version_is_left_alone(self):
        e = Env(self)
        e.image("img2", "2.0.1")
        own = compose_text(1) + "# own line\n"
        (e.dir / "docker-compose.yml").write_text(own, encoding="utf-8")
        e.run("-y")
        self.assertEqual((e.dir / "docker-compose.yml").read_text(), own)
        self.assertFalse((e.dir / "docker-compose.yml.alt").exists())

    def test_legacy_installation_is_migrated(self):
        e = Env(self)
        (e.dir / ".env").write_text("DOMAIN_FQDN=firma.local\nDOCKER_DNS=10.0.10.10;10.0.10.11\n"
                                    "DOCKER_EXTRA_HOSTS=dc01.firma.local:10.0.10.10\n", encoding="utf-8")
        e.image("old", "1.9.8", tags=("1.9.8",), local=True)
        e.image("img2", "2.0.0")
        e.running("old", compose=False)
        e.state["networks"]["samaudit-net"] = {"labels": {}}
        e.save()
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        ov = (e.dir / "docker-compose.override.yml").read_text()
        self.assertIn("10.0.10.11", ov)
        self.assertIn("dc01.firma.local:10.0.10.10", ov)
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img2")
        self.assertEqual(e.state["images"][f"{REPO}:previous"], "old")
        self.assertIn("--cleanup", e.out)

    def test_foreign_compose_installation_is_not_touched(self):
        e = Env(self)
        e.image("img2", "2.0.1")
        e.state["containers"]["samaudit"] = {"image": "x", "labels": {
            "com.docker.compose.project": "samaudit", "com.docker.compose.project.working_dir": "/srv/dockhand/stacks/samaudit"}}
        e.save()
        r = e.run("-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Dockhand", e.out)
        self.assertFalse(e.calls("compose", "up", "-d"))

    def test_offline_load_checks_checksum(self):
        e = Env(self)
        e.state["meta"]["img9"] = {"version": "2.0.2", "dist": None, "health": "healthy"}
        e.image("img9", "2.0.2", tags=())
        f = e.tmp / "samaudit-2.0.2-amd64.tar.gz"
        f.write_text(json.dumps({"images": {f"{REPO}:2.0.2": "img9"}}), encoding="utf-8")
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        (e.tmp / "SHA256SUMS").write_text(f"{'0' * 64}  {f.name}\n", encoding="utf-8")
        r = e.run("-y", "--load", str(f))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Checksum mismatch", e.out)
        (e.tmp / "SHA256SUMS").write_text(f"{digest}  {f.name}\n", encoding="utf-8")
        r = e.run("-y", "--load", str(f))
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse(e.calls("pull"), "offline: no pull")
        self.assertIn("SAMAUDIT_VERSION=2.0.2", (e.dir / ".env").read_text())
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img9")

    # ---- findings of the independent review (must not come back) ----
    def test_env_untouched_when_version_does_not_exist(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("latest",), local=True)
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        before = (e.dir / ".env").read_text()
        r = e.run("-y", "--version=2.0.9")                       # typo: does not exist
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((e.dir / ".env").read_text(), before)
        self.assertFalse(e.calls("compose", "stop"))
        self.assertFalse(e.calls("compose", "up", "-d"))

    def test_restore_with_missing_version_changes_nothing(self):
        e = Env(self)
        e.image("img1", "2.1.0", tags=("latest",), local=True)
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        r = e.run("-y", "--restore", "x.db", "--version=2.0.9")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(e.calls("compose", "stop"), "image must be fetched before anything is stopped")
        self.assertFalse(e.calls("compose", "run"))

    def test_noop_keeps_previous(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img2", "2.0.1", local=True)
        e.state["images"][f"{REPO}:previous"] = "img1"
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img2")
        e.run("-y")
        self.assertIn("nothing to do", e.out)
        self.assertEqual(e.state["images"][f"{REPO}:previous"], "img1")

    def test_relative_load_path(self):
        e = Env(self)
        e.image("img9", "2.0.2", tags=())
        f = e.tmp / "img.tar.gz"
        f.write_text(json.dumps({"images": {f"{REPO}:2.0.2": "img9"}}), encoding="utf-8")
        r = e.run("-y", "--load", "img.tar.gz", cwd=e.tmp)     # called from another folder
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img9")

    def test_compose_file_with_own_paths_is_not_replaced(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("old",), local=True)
        e.image("img2", "2.1.0", compose_version=2)
        own = compose_text(1).replace("- ./data:/app/data", "- /volume1/samaudit/data:/app/data")
        (e.dir / "docker-compose.yml").write_text(own, encoding="utf-8")
        e.running("img1")
        e.run("-y")
        self.assertEqual((e.dir / "docker-compose.yml").read_text(), own)
        self.assertTrue((e.dir / "docker-compose.yml.neu").exists())
        self.assertIn("NOT replaced", e.out)

    def test_legacy_container_of_other_folder_is_not_touched(self):
        e = Env(self)
        e.image("old", "1.9.8", tags=("1.9.8",), local=True)
        e.image("img2", "2.0.0")
        e.running("old", compose=False)
        e.state["containers"]["samaudit"]["mounts"] = ["/srv/other-folder/data"]
        e.save()
        r = e.run("-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/srv/other-folder/data", e.out)
        self.assertIn("samaudit", e.state["containers"])
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "old")

    def test_legacy_migration_failure_restores_old_container(self):
        e = Env(self)
        e.image("old", "1.9.8", tags=("1.9.8",), local=True)
        e.image("img2", "2.0.0")
        e.running("old", compose=False)
        e.state["networks"]["samaudit-net"] = {"labels": {}}
        e.save()
        e.extra_env["FAKE_UP_FAILS"] = "1"
        r = e.run("-y")
        self.assertNotEqual(r.returncode, 0)
        c = e.state["containers"].get("samaudit")
        self.assertIsNotNone(c, e.out)
        self.assertEqual(c["image"], "old")
        self.assertNotIn("samaudit-alt", e.state["containers"])
        self.assertIn("existing installation", e.out)

    def test_rollback_without_version_label_still_restores_database(self):
        e = Env(self)
        e.image("img1", "", tags=("old",), local=True)
        e.image("img3", "", health="unhealthy")
        (e.dir / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        e.running("img1")
        e.run("-y")
        self.assertTrue(e.calls("compose", "run"), e.out)
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img1")

    def test_compose_v1_is_refused(self):
        e = Env(self)
        bindir = e.tmp / "bin"
        bindir.mkdir()
        (bindir / "docker-compose").write_text("#!/bin/sh\necho 1.29.2\n", encoding="utf-8")
        os.chmod(bindir / "docker-compose", 0o755)
        e.extra_path = f"{bindir}:"
        e.extra_env["FAKE_NO_COMPOSE"] = "1"
        r = e.run("-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("too old", e.out)

    def test_env_symlink_stays_a_symlink(self):
        e = Env(self)
        e.image("img1", "2.0.0", tags=("2.0.0",))
        real = e.tmp / "secret.env"
        real.write_text("DOMAIN_FQDN=firma.local\nSAMAUDIT_VERSION=latest\n", encoding="utf-8")
        (e.dir / ".env").unlink()
        os.symlink(real, e.dir / ".env")
        r = e.run("-y", "--version=2.0.0")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertTrue(os.path.islink(e.dir / ".env"))
        self.assertIn("SAMAUDIT_VERSION=2.0.0", real.read_text())

    def test_zip_and_build_paths_are_gone(self):
        e = Env(self)
        r = e.run("samaudit-v1.9.8.zip")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ZIP", e.out)
        text = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertNotIn("docker build", text)
        self.assertNotIn("unzip", text)

    def test_crlf_env_is_repaired(self):
        e = Env(self)
        e.image("img2", "2.0.1")
        (e.dir / ".env").write_bytes(b"DOMAIN_FQDN=firma.local\r\nSAMAUDIT_VERSION=latest\r\n")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertNotIn(b"\r", (e.dir / ".env").read_bytes())


class Cleanup(unittest.TestCase):
    def make(self) -> Env:
        e = Env(self)
        d = e.dir
        for f in ("Dockerfile", "run.py", "entrypoint.sh", "requirements.txt", "README.md", "LICENSE",
                  ".samaudit-manifest", "base-image.lock", "samaudit-v1.9.6.zip", "SAMAUDIT-v1.7.1.zip"):
            (d / f).write_text("x", encoding="utf-8")
        (d / "app").mkdir()
        (d / "app" / "version.py").write_text('APP_NAME = "SAMAUDIT"\nVERSION = "1.9.8"\n', encoding="utf-8")
        (d / ".update-abc").mkdir()
        (d / "samaudit-v1.9.6" / "app").mkdir(parents=True)
        (d / "samaudit-v1.9.6" / "app" / "version.py").write_text('APP_NAME = "SAMAUDIT"\n', encoding="utf-8")
        # data, backups, settings
        (d / "data").mkdir()
        (d / "data" / "samaudit.db").write_text("DATA", encoding="utf-8")
        (d / "backups").mkdir()
        (d / "backups" / "samaudit-1.9.8.tgz").write_text("BACKUP", encoding="utf-8")
        (d / "certs").mkdir()
        (d / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        (d / "docker-compose.override.yml").write_text("services: {}\n", encoding="utf-8")
        return e

    def test_removes_only_program_files(self):
        e = self.make()
        unit = e.rootfs / "etc" / "systemd" / "system" / "samaudit-firewall.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Unit]\n", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        d = e.dir
        for gone in ("Dockerfile", "run.py", "app", ".update-abc", "samaudit-v1.9.6.zip", "SAMAUDIT-v1.7.1.zip",
                     "samaudit-v1.9.6", "base-image.lock", "LICENSE"):
            self.assertFalse((d / gone).exists(), gone)
        self.assertEqual((d / "data" / "samaudit.db").read_text(), "DATA")
        self.assertEqual((d / "backups" / "samaudit-1.9.8.tgz").read_text(), "BACKUP")
        for keep in (".env", "docker-compose.yml", "docker-compose.override.yml", "update.sh", "certs"):
            self.assertTrue((d / keep).exists(), keep)
        self.assertFalse(unit.exists())

    def test_links_never_lead_into_data(self):
        e = self.make()
        d = e.dir
        shutil.rmtree(d / "app")
        os.symlink(d / "data", d / "app")                      # program folder is a link to the data
        (d / "locks").mkdir()
        (d / "locks" / "os-packages.txt").write_text("x", encoding="utf-8")
        os.symlink(d / "data" / "samaudit.db", d / "locks" / "db-link")   # link inside the folder to be deleted
        os.symlink(d / "backups", d / "tools")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse(os.path.lexists(d / "app"))           # only the link itself is gone
        self.assertFalse(os.path.lexists(d / "tools"))
        self.assertFalse((d / "locks").exists())
        self.assertEqual((d / "data" / "samaudit.db").read_text(), "DATA")
        self.assertEqual((d / "backups" / "samaudit-1.9.8.tgz").read_text(), "BACKUP")

    def test_data_folder_reached_via_program_name_is_protected(self):
        e = self.make()
        d = e.dir
        # the data lie INSIDE a folder with a program name (data is a link to it)
        (d / "tests").mkdir()
        (d / "tests" / "smoke.py").write_text("x", encoding="utf-8")
        shutil.move(str(d / "data"), str(d / "tests" / "data"))
        os.symlink(d / "tests" / "data", d / "data")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual((d / "tests" / "data" / "samaudit.db").read_text(), "DATA")
        self.assertIn("protected", e.out)

    def test_mounts_of_containers_are_protected(self):
        e = self.make()
        d = e.dir
        (d / "tools").mkdir()
        (d / "tools" / "lockutil.py").write_text("x", encoding="utf-8")
        (d / "tools" / "important.txt").write_text("MOUNTED", encoding="utf-8")
        e.state["containers"]["other"] = {"image": "x", "labels": {}, "mounts": [str(d / "tools")]}
        e.save()
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual((d / "tools" / "important.txt").read_text(), "MOUNTED")

    def test_host_mount_points_are_protected(self):
        e = self.make()
        d = e.dir
        (d / "locks").mkdir()
        (d / "locks" / "os-packages.txt").write_text("x", encoding="utf-8")
        (d / "locks" / "nas").mkdir()
        (e.rootfs / "proc" / "mounts").write_text(f"/dev/sdb1 {d}/locks/nas ext4 rw 0 0\n", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertTrue((d / "locks" / "nas").exists())

    def test_asks_and_does_nothing_without_yes(self):
        e = self.make()
        e.run("--cleanup", inp="n\n")
        self.assertTrue((e.dir / "Dockerfile").exists())
        self.assertNotIn("removed:", e.out)

    def test_refuses_in_git_checkout(self):
        e = self.make()
        (e.dir / ".git").mkdir()
        r = e.run("--cleanup", "-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((e.dir / "Dockerfile").exists())

    # ---- findings of the independent review ----
    def test_unreadable_data_does_not_disable_protection(self):
        e = self.make()
        d = e.dir
        (d / "tools").mkdir()
        (d / "tools" / "lockutil.py").write_text("x", encoding="utf-8")
        (d / "tools" / "important.txt").write_text("MOUNTED", encoding="utf-8")
        e.state["containers"]["other"] = {"image": "x", "labels": {}, "mounts": [str(d / "tools")]}
        e.save()
        os.chmod(d / "data", 0)                          # like data/ (UID 10001, 0700) for a non-root user
        self.addCleanup(os.chmod, d / "data", 0o755)
        e.run("--cleanup", "-y")
        os.chmod(d / "data", 0o755)
        self.assertTrue((d / "tools" / "important.txt").exists(), e.out)
        self.assertEqual((d / "data" / "samaudit.db").read_text(), "DATA")

    def test_docker_failure_aborts_cleanup(self):
        e = self.make()
        e.extra_env["FAKE_PS_FAILS"] = "1"
        r = e.run("--cleanup", "-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((e.dir / "Dockerfile").exists())

    def test_mount_point_in_folder_with_space(self):
        e = Env(self, name="sam audit")
        d = e.dir
        (d / "docker-compose.yml").write_text(compose_text(1), encoding="utf-8")
        (d / "data").mkdir()
        (d / "locks" / "nas").mkdir(parents=True)
        (d / "locks" / "os-packages.txt").write_text("x", encoding="utf-8")
        (d / "locks" / "nas" / "file").write_text("NAS", encoding="utf-8")
        mp = str(d / "locks" / "nas").replace(" ", "\\040")
        (e.rootfs / "proc" / "mounts").write_text(f"//nas/share {mp} cifs rw 0 0\n", encoding="utf-8")
        e.run("--cleanup", "-y")
        self.assertEqual((d / "locks" / "nas" / "file").read_text(), "NAS", e.out)

    def test_refuses_outside_a_samaudit_folder(self):
        e = Env(self)
        d = e.dir
        for f in ("README.md", "LICENSE"):
            (d / f).write_text("MINE", encoding="utf-8")
        (d / "tools").mkdir()
        r = e.run("--cleanup", "-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((d / "README.md").read_text(), "MINE")
        self.assertTrue((d / "tools").exists())

    def test_git_file_counts_as_checkout(self):
        e = self.make()
        (e.dir / ".git").write_text("gitdir: /x\n", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((e.dir / "Dockerfile").exists())

    def test_unknown_files_and_folders_are_left_alone(self):
        e = self.make()
        d = e.dir
        (d / "report.new.docx").write_text("MINE", encoding="utf-8")
        (d / "tools").mkdir()
        (d / "tools" / "my-script.sh").write_text("MINE", encoding="utf-8")
        (d / "x.new.\nnotes.txt").write_text("x", encoding="utf-8")
        (d / "notes.txt").write_text("MINE", encoding="utf-8")
        old = d / "samaudit-v1.7.0"
        (old / "app").mkdir(parents=True)
        (old / "app" / "version.py").write_text('APP_NAME = "SAMAUDIT"\n', encoding="utf-8")
        (old / "data").mkdir()
        (old / "data" / "samaudit.db").write_text("OLD DATA", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual((d / "report.new.docx").read_text(), "MINE")
        self.assertEqual((d / "tools" / "my-script.sh").read_text(), "MINE")
        self.assertEqual((d / "notes.txt").read_text(), "MINE")
        self.assertEqual((old / "data" / "samaudit.db").read_text(), "OLD DATA")
        self.assertFalse((d / "Dockerfile").exists())

    def test_names_with_spaces(self):
        e = self.make()
        (e.dir / "samaudit v1.9.zip").write_text("x", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse((e.dir / "samaudit v1.9.zip").exists())
        self.assertEqual((e.dir / "data" / "samaudit.db").read_text(), "DATA")


if __name__ == "__main__":
    unittest.main()
