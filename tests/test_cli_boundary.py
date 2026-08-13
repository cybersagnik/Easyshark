import unittest
from pathlib import Path


class TestCLIBoundary(unittest.TestCase):
    def test_v2_has_no_web_api_runtime_dependencies(self):
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "requirements.txt").read_text(encoding="utf-8").lower()
        locked = (root / "requirements.lock").read_text(encoding="utf-8").lower()
        self.assertNotIn("fastapi", requirements + locked)
        self.assertNotIn("uvicorn", requirements + locked)
        api_dir = root / "core" / "api"
        self.assertFalse(api_dir.exists() and any(api_dir.glob("*.py")))

    def test_production_lock_is_exact(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "requirements.lock").read_text(encoding="utf-8")
        rows = [row for row in text.splitlines()
                if row and not row[0].isspace() and not row.startswith("#")]
        self.assertTrue(rows)
        self.assertTrue(all("==" in row for row in rows), rows)
        self.assertGreaterEqual(text.count("--hash=sha256:"), len(rows) * 2)


if __name__ == "__main__":
    unittest.main()
