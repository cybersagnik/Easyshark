import sqlite3
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from core.state_archive import create, prune, restore, verify


class TestStateArchive(unittest.TestCase):
    key = "test-only-backup-authentication-key-32-bytes"

    def test_verified_backup_and_restore_preserve_sqlite_and_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state"
            state.mkdir()
            db = sqlite3.connect(state / "jobs.db")
            db.execute("CREATE TABLE jobs(id INTEGER PRIMARY KEY, status TEXT)")
            db.execute("INSERT INTO jobs(status) VALUES('running')")
            db.commit()
            db.close()
            (state / "audit.jsonl").write_text('{"action":"test"}\n',
                                                encoding="utf-8")
            archive = root / "backup.zip"
            result = create(str(state), str(archive), self.key)
            self.assertEqual(result["files"], 2)
            self.assertTrue(verify(str(archive), self.key)["valid"])
            restored = root / "restored"
            restore(str(archive), str(restored), self.key)
            connection = sqlite3.connect(restored / "jobs.db")
            try:
                self.assertEqual(connection.execute(
                    "SELECT status FROM jobs").fetchone()[0], "running")
            finally:
                connection.close()
            self.assertEqual((restored / "audit.jsonl").read_text(),
                             '{"action":"test"}\n')

    def test_tampered_archive_fails_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state"
            state.mkdir()
            (state / "session.json").write_text("{}", encoding="utf-8")
            archive = root / "backup.zip"
            create(str(state), str(archive), self.key)
            with zipfile.ZipFile(archive, "a") as bundle:
                bundle.writestr("session.json", b"tampered")
            self.assertFalse(verify(str(archive), self.key)["valid"])

    def test_wrong_backup_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            state = root / "state"
            state.mkdir()
            (state / "session.json").write_text("{}", encoding="utf-8")
            archive = root / "backup.zip"
            create(str(state), str(archive), self.key)
            self.assertFalse(verify(str(archive), "wrong-key-that-is-still-long-enough-000")["valid"])

    def test_retention_is_dry_run_until_explicitly_applied(self):
        with tempfile.TemporaryDirectory() as folder:
            sessions = Path(folder) / "sessions"
            sessions.mkdir()
            old = sessions / "old.json"
            old.write_text("{}", encoding="utf-8")
            timestamp = time.time() - 10 * 86400
            import os
            os.utime(old, (timestamp, timestamp))
            preview = prune(folder, 5)
            self.assertFalse(preview["applied"])
            self.assertTrue(old.exists())
            prune(folder, 5, apply=True)
            self.assertFalse(old.exists())


if __name__ == "__main__":
    unittest.main()
