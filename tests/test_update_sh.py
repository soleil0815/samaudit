# SPDX-License-Identifier: AGPL-3.0-or-later
"""Selbsttests für update.sh – mit nachgebautem docker (tests/fakedocker), immer unter dash bzw. /bin/sh,
nur in Temp-Ordnern (nie im echten /etc, nie in echten Datenordnern)."""
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
    """Ein Installationsordner + Zustand des nachgebauten docker."""

    def __init__(self, tc: unittest.TestCase):
        self.tmp = Path(tempfile.mkdtemp(prefix="samaudit-test-"))
        tc.addCleanup(shutil.rmtree, self.tmp, True)
        self.dir = self.tmp / "install"
        self.dir.mkdir()
        shutil.copy(ROOT / "update.sh", self.dir / "update.sh")
        (self.dir / ".env").write_text("DOMAIN_FQDN=firma.local\nPORT=9400\n", encoding="utf-8")
        self.rootfs = self.tmp / "root"            # Ersatz für "/" (systemd-Unit usw.)
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

    def run(self, *args: str, inp: str | None = None) -> subprocess.CompletedProcess:
        env = {"PATH": f"{FAKE}:{os.environ['PATH']}", "FAKE_STATE": str(self.state_file),
               "SAMAUDIT_TEST_ROOT": str(self.rootfs), "SAMAUDIT_HEALTH_TIMEOUT": "6", "HOME": str(self.tmp),
               "LANG": "C.UTF-8"}
        r = subprocess.run([SH, "update.sh", *args], cwd=self.dir, env=env, input=inp, capture_output=True,
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
        self.assertIn("nichts zu tun", e.out)
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
        self.assertIn("--rollback", runs[0]["argv"])
        self.assertIn("2.0.1", runs[0]["argv"])          # Programmversion ohne -sN
        self.assertNotIn("2.0.1-s2", runs[0]["argv"])
        self.assertEqual(runs[0]["SAMAUDIT_VERSION"], "latest")      # Restore mit dem neuen Image
        ups = e.calls("compose", "up", "-d")
        self.assertEqual(ups[-1]["SAMAUDIT_VERSION"], "previous")
        self.assertIn("vorige", e.out)

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
        r = e.run()                     # ohne -y und ohne Terminal: keine stille Entscheidung
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
        (e.dir / "docker-compose.yml").write_text(compose_text(1) + "# eigene Zeile\n", encoding="utf-8")
        e.running("img1")
        r = e.run("-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertIn('SAMAUDIT_COMPOSE: "2"', (e.dir / "docker-compose.yml").read_text())
        self.assertIn("# eigene Zeile", (e.dir / "docker-compose.yml.alt").read_text())

    def test_same_compose_version_is_left_alone(self):
        e = Env(self)
        e.image("img2", "2.0.1")
        own = compose_text(1) + "# eigene Zeile\n"
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
        self.assertIn("Prüfsumme", e.out)
        (e.tmp / "SHA256SUMS").write_text(f"{digest}  {f.name}\n", encoding="utf-8")
        r = e.run("-y", "--load", str(f))
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse(e.calls("pull"), "offline: no pull")
        self.assertIn("SAMAUDIT_VERSION=2.0.2", (e.dir / ".env").read_text())
        self.assertEqual(e.state["containers"]["samaudit"]["image"], "img9")

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
        (d / "app" / "version.py").write_text('VERSION = "1.9.8"\n', encoding="utf-8")
        (d / ".update-abc").mkdir()
        (d / "samaudit-v1.9.6" / "app").mkdir(parents=True)
        (d / "samaudit-v1.9.6" / "app" / "version.py").write_text("x", encoding="utf-8")
        # Daten, Sicherungen, Einstellungen
        (d / "data").mkdir()
        (d / "data" / "samaudit.db").write_text("DATEN", encoding="utf-8")
        (d / "backups").mkdir()
        (d / "backups" / "samaudit-1.9.8.tgz").write_text("SICHERUNG", encoding="utf-8")
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
        self.assertEqual((d / "data" / "samaudit.db").read_text(), "DATEN")
        self.assertEqual((d / "backups" / "samaudit-1.9.8.tgz").read_text(), "SICHERUNG")
        for keep in (".env", "docker-compose.yml", "docker-compose.override.yml", "update.sh", "certs"):
            self.assertTrue((d / keep).exists(), keep)
        self.assertFalse(unit.exists())

    def test_links_never_lead_into_data(self):
        e = self.make()
        d = e.dir
        shutil.rmtree(d / "app")
        os.symlink(d / "data", d / "app")                      # Programmordner ist ein Link auf die Daten
        (d / "locks").mkdir()
        os.symlink(d / "data" / "samaudit.db", d / "locks" / "db-link")   # Link im zu löschenden Ordner
        os.symlink(d / "backups", d / "tools")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse(os.path.lexists(d / "app"))           # nur der Link selbst ist weg
        self.assertFalse(os.path.lexists(d / "tools"))
        self.assertFalse((d / "locks").exists())
        self.assertEqual((d / "data" / "samaudit.db").read_text(), "DATEN")
        self.assertEqual((d / "backups" / "samaudit-1.9.8.tgz").read_text(), "SICHERUNG")

    def test_data_folder_reached_via_program_name_is_protected(self):
        e = self.make()
        d = e.dir
        # die Daten liegen IN einem Ordner mit Programmnamen (data ist ein Link dorthin)
        (d / "tests").mkdir()
        shutil.move(str(d / "data"), str(d / "tests" / "data"))
        os.symlink(d / "tests" / "data", d / "data")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual((d / "tests" / "data" / "samaudit.db").read_text(), "DATEN")
        self.assertIn("geschützt", e.out)

    def test_mounts_of_containers_are_protected(self):
        e = self.make()
        d = e.dir
        (d / "tools").mkdir()
        (d / "tools" / "wichtig.txt").write_text("EINGEBUNDEN", encoding="utf-8")
        e.state["containers"]["anderer"] = {"image": "x", "labels": {}, "mounts": [str(d / "tools")]}
        e.save()
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertEqual((d / "tools" / "wichtig.txt").read_text(), "EINGEBUNDEN")

    def test_host_mount_points_are_protected(self):
        e = self.make()
        d = e.dir
        (d / "locks").mkdir()
        (d / "locks" / "nas").mkdir()
        (e.rootfs / "proc" / "mounts").write_text(f"/dev/sdb1 {d}/locks/nas ext4 rw 0 0\n", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertTrue((d / "locks" / "nas").exists())

    def test_asks_and_does_nothing_without_yes(self):
        e = self.make()
        r = e.run("--cleanup", inp="n\n")
        self.assertTrue((e.dir / "Dockerfile").exists())
        self.assertNotIn("entfernt:", e.out)

    def test_refuses_in_git_checkout(self):
        e = self.make()
        (e.dir / ".git").mkdir()
        r = e.run("--cleanup", "-y")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((e.dir / "Dockerfile").exists())

    def test_names_with_spaces(self):
        e = self.make()
        (e.dir / "samaudit v1.9.zip").write_text("x", encoding="utf-8")
        r = e.run("--cleanup", "-y")
        self.assertEqual(r.returncode, 0, e.out)
        self.assertFalse((e.dir / "samaudit v1.9.zip").exists())
        self.assertEqual((e.dir / "data" / "samaudit.db").read_text(), "DATEN")


if __name__ == "__main__":
    unittest.main()
