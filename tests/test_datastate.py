# SPDX-License-Identifier: AGPL-3.0-or-later
"""Selbsttests: Sicherung vor Versionswechsel, Schutz vor Rückschritt, Zurückspielen, Sperre je Datenordner,
Versionsprüfung der docker-compose.yml. Alles in Temp-Ordnern (nie in echten Datenordnern)."""
from __future__ import annotations

import importlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class DataState(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="samaudit-data-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.environ["DATA_DIR"] = self.dir
        os.environ.pop("BACKUP_KEEP", None)
        import app.config
        importlib.reload(app.config)
        import app.datastate
        import app.db
        import app.restore
        self.ds = importlib.reload(app.datastate)
        self.db = importlib.reload(app.db)
        self.rs = importlib.reload(app.restore)

    def tearDown(self):
        if self.db._con is not None:
            self.db._con.close()
            self.db._con = None
        os.environ.pop("DATA_DIR", None)

    def start(self):
        """wie run.py: prüfen/sichern, dann Schema anlegen/migrieren und Version merken"""
        path = self.ds.check_and_backup()
        if self.db._con is not None:
            self.db._con.close()
            self.db._con = None
        self.db.init()
        return path

    def set_meta(self, version: str | None, schema: str | None = None):
        con = sqlite3.connect(self.db.settings.db_path)
        if version is None:
            con.execute("DELETE FROM kv WHERE key IN ('app_version', 'schema_version')")
        else:
            con.execute("INSERT OR REPLACE INTO kv VALUES('app_version', ?)", (version,))
        if schema is not None:
            con.execute("INSERT OR REPLACE INTO kv VALUES('schema_version', ?)", (schema,))
        con.commit()
        con.close()

    def test_fresh_install_needs_no_backup(self):
        self.assertIsNone(self.start())
        self.assertEqual(self.ds.list_backups(), [])
        meta = self.ds._read_meta(self.db.settings.db_path)
        self.assertEqual(meta["app_version"], self.ds.VERSION)
        self.assertEqual(meta["schema_version"], str(self.ds.SCHEMA_VERSION))

    def test_same_version_no_backup(self):
        self.start()
        self.assertIsNone(self.start())

    def test_version_change_backs_up_before_migration(self):
        self.start()
        self.set_meta(None)                                    # Datenbank einer Version vor 2.0
        con = sqlite3.connect(self.db.settings.db_path)
        con.execute("INSERT INTO kv VALUES('marker', 'alt')")
        con.commit(); con.close()
        path = self.start()
        self.assertTrue(path and os.path.basename(path).startswith(f"samaudit-vor-{self.ds.VERSION}-"))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        b = sqlite3.connect(path)
        self.assertEqual(b.execute("SELECT value FROM kv WHERE key='marker'").fetchone()[0], "alt")
        self.assertIsNone(b.execute("SELECT value FROM kv WHERE key='app_version'").fetchone())   # Stand VOR dem Wechsel
        b.close()

    def test_old_schema_is_migrated_after_backup(self):
        self.start()
        con = sqlite3.connect(self.db.settings.db_path)    # Schema 1: cert_pins ohne Spalte names
        con.executescript("DROP TABLE cert_pins; CREATE TABLE cert_pins (host TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,"
                          " subject TEXT, not_after TEXT, is_ca INTEGER NOT NULL DEFAULT 0, der BLOB,"
                          " first_seen TEXT NOT NULL, last_seen TEXT);")
        con.execute("UPDATE kv SET value='1' WHERE key='schema_version'")
        con.commit(); con.close()
        path = self.start()
        self.assertIsNotNone(path)
        cols = {r[1] for r in sqlite3.connect(self.db.settings.db_path).execute("PRAGMA table_info(cert_pins)")}
        self.assertIn("names", cols)
        old_cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(cert_pins)")}
        self.assertNotIn("names", old_cols)

    def test_newer_database_refuses_with_backup_hint(self):
        self.start()
        newer = "99.0.0"
        self.ds.backup_now(f"vor-{newer}")
        self.set_meta(newer)
        with self.assertRaises(self.ds.StartRefused) as cm:
            self.ds.check_and_backup()
        msg = str(cm.exception)
        self.assertIn(newer, msg)
        self.assertIn(f"samaudit-vor-{newer}-", msg)
        self.assertIn("restore", msg)

    def test_newer_schema_refuses(self):
        self.start()
        self.set_meta(self.ds.VERSION, str(self.ds.SCHEMA_VERSION + 1))
        with self.assertRaises(self.ds.StartRefused):
            self.ds.check_and_backup()

    def test_security_update_of_same_version_is_not_a_downgrade(self):
        self.assertEqual(self.ds.version_key("2.0.1-s3"), self.ds.version_key("2.0.1"))
        self.assertGreater(self.ds.version_key("2.0.10"), self.ds.version_key("2.0.9"))

    def test_backups_are_pruned(self):
        os.environ["BACKUP_KEEP"] = "2"
        self.start()
        for i in range(4):
            self.ds.backup_now(f"vor-1.{i}.0")
            time.sleep(0.01)
        self.ds._prune()
        left = [os.path.basename(f) for f in self.ds.list_backups()]
        self.assertEqual(len(left), 2)
        self.assertTrue(any("vor-1.3.0" in f for f in left))

    def test_failed_backup_blocks_the_start(self):
        self.start()
        self.set_meta("1.0.0")
        os.makedirs(self.ds.backup_dir(), exist_ok=True)
        os.chmod(self.ds.backup_dir(), 0o500)
        self.addCleanup(os.chmod, self.ds.backup_dir(), 0o700)
        if os.access(self.ds.backup_dir(), os.W_OK):
            self.skipTest("läuft als root – Schreibschutz greift nicht")
        with self.assertRaises(self.ds.StartRefused):
            self.ds.check_and_backup()

    def test_only_one_instance_per_data_folder(self):
        code = ("import os, sys, time; sys.path.insert(0, %r); os.environ['DATA_DIR'] = %r; "
                "from app import datastate; datastate.acquire_lock(); print('locked', flush=True); time.sleep(30)"
                % (str(ROOT), self.dir))
        p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), "locked")
        self.assertTrue(self.ds.is_locked_elsewhere())
        with self.assertRaises(self.ds.StartRefused):
            self.ds.acquire_lock()
        self.assertEqual(self.rs.main(["irgendwas.db"]), 1)        # restore verweigert, solange es läuft
        p.kill(); p.wait()
        self.assertFalse(self.ds.is_locked_elsewhere())

    def test_restore_by_name_keeps_current_db(self):
        self.start()
        con = sqlite3.connect(self.db.settings.db_path)
        con.execute("INSERT INTO kv VALUES('marker', 'vorher')"); con.commit(); con.close()
        b = self.ds.backup_now("vor-9.9.9")
        con = sqlite3.connect(self.db.settings.db_path)
        con.execute("UPDATE kv SET value='nachher' WHERE key='marker'"); con.commit(); con.close()
        self.db._con.close(); self.db._con = None
        self.assertEqual(self.rs.main([os.path.basename(b)]), 0)
        v = sqlite3.connect(self.db.settings.db_path).execute("SELECT value FROM kv WHERE key='marker'").fetchone()[0]
        self.assertEqual(v, "vorher")
        self.assertTrue(any("samaudit-ersetzt-" in f for f in self.ds.list_backups()))
        self.assertEqual(self.rs.main(["../../etc/passwd"]), 1)

    def test_rollback_restores_only_what_the_failed_update_changed(self):
        self.start()
        since = time.time()
        self.set_meta(None)
        self.start()                          # „neue Version“ übernimmt die Datenbank → Sicherung vor-<VERSION>
        self.db._con.close(); self.db._con = None
        self.assertEqual(self.rs.rollback(self.ds.VERSION, since), 0)
        self.assertIsNone(self.ds._read_meta(self.db.settings.db_path).get("app_version"))
        # Datenbank nicht von der neuen Version verändert → nichts zurückspielen
        self.assertEqual(self.rs.rollback("77.0.0", since), 0)


class ComposeVersion(unittest.TestCase):
    def setUp(self):
        import app.datastate
        self.ds = app.datastate
        self.saved = os.environ.pop("SAMAUDIT_COMPOSE", None)
        self.addCleanup(lambda: os.environ.__setitem__("SAMAUDIT_COMPOSE", self.saved) if self.saved
                        else os.environ.pop("SAMAUDIT_COMPOSE", None))

    def test_file_in_repo_matches_program(self):
        text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        m = re.search(r'SAMAUDIT_COMPOSE:\s*"(\d+)"', text)
        self.assertIsNotNone(m)
        self.assertEqual(int(m.group(1)), self.ds.COMPOSE_REQUIRED)

    def test_missing_or_old_file_gives_hint(self):
        self.assertIsNotNone(self.ds.compose_message("de"))
        os.environ["SAMAUDIT_COMPOSE"] = "1"
        req = self.ds.COMPOSE_REQUIRED
        self.ds.COMPOSE_REQUIRED = 2                    # Programm erwartet eine neuere Datei
        self.addCleanup(setattr, self.ds, "COMPOSE_REQUIRED", req)
        self.assertIn("veraltet (Version 1, benötigt 2)", self.ds.compose_message("de"))
        self.assertIn("outdated", self.ds.compose_message("en"))
        self.ds.COMPOSE_REQUIRED = req
        os.environ["SAMAUDIT_COMPOSE"] = str(self.ds.COMPOSE_REQUIRED)
        self.assertIsNone(self.ds.compose_message("de"))
        os.environ["SAMAUDIT_COMPOSE"] = str(self.ds.COMPOSE_REQUIRED + 1)
        self.assertIsNone(self.ds.compose_message("de"))

    def test_image_ships_compose_file_and_defaults_live_in_program(self):
        df = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(df, r"COPY [^\n]*docker-compose\.yml[^\n]*/app/dist/")
        import yaml
        c = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        s = c["services"]["samaudit"]
        self.assertEqual(s["image"], "${SAMAUDIT_IMAGE:-ghcr.io/soleil0815/samaudit}:${SAMAUDIT_VERSION:-latest}")
        self.assertEqual(s["ports"], ["${PORT:-9400}:9400"])
        self.assertEqual(s["environment"]["PORT"], "9400")
        # keine auf Prüfsummen gepinnten Zusatz-Container – die Datei muss sich nicht je Version ändern
        self.assertEqual(list(c["services"]), ["samaudit"])
        self.assertNotIn("@sha256:", (ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
