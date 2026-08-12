import json
import tempfile
import unittest
from pathlib import Path

from ai.oracle import OracleStore, generate_synthetic_corpus, run_corpus


class TestOracleCorpus(unittest.TestCase):
    def test_generated_pcaps_are_reproducible_hash_pinned_and_detectable(self):
        with tempfile.TemporaryDirectory() as folder:
            first = Path(folder) / "first"
            second = Path(folder) / "second"
            result = generate_synthetic_corpus(str(first))
            generate_synthetic_corpus(str(second))
            left = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
            right = json.loads((second / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(left, right)
            self.assertEqual(left["schema"], "easyshark.corpus.v2")
            self.assertEqual(result["cases"], 7)
            self.assertTrue(any(not case["labels"] for case in left["cases"]))
            for case in left["cases"]:
                self.assertEqual(len(case["sha256"]), 64)
                self.assertEqual(case["license"], "CC0-1.0")

            scored = run_corpus(
                str(first / "manifest.json"),
                OracleStore(str(Path(folder) / "oracle.db")))
            self.assertEqual(scored["failed"], [])
            self.assertEqual(scored["precision"], 1.0)
            self.assertEqual(scored["recall"], 1.0)
            self.assertIn("prompt_injection_payload", scored["by_subject"])
            self.assertTrue(all(row["samples"] == 7
                                for row in scored["by_subject"].values()))

    def test_manifest_hash_path_and_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "corpus"
            generate_synthetic_corpus(str(root))
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["cases"][0]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            scored = run_corpus(
                str(manifest_path), OracleStore(str(root / "hash.db")))
            self.assertEqual(len(scored["failed"]), 1)
            self.assertIn("SHA-256", scored["failed"][0]["error"])

            outside = root.parent / "outside.pcap"
            outside.write_bytes(b"not a capture")
            escaped = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            escaped["cases"] = [{**escaped["cases"][0], "pcap": "../outside.pcap"}]
            escape_path = root / "escape.json"
            escape_path.write_text(json.dumps(escaped), encoding="utf-8")
            scored = run_corpus(
                str(escape_path), OracleStore(str(root / "escape.db")))
            self.assertIn("escapes", scored["failed"][0]["error"])

            bad = root / "bad.json"
            bad.write_text(json.dumps({"schema": "easyshark.corpus.v99",
                                       "cases": []}), encoding="utf-8")
            with self.assertRaises(ValueError):
                run_corpus(str(bad), OracleStore(str(root / "schema.db")))


if __name__ == "__main__":
    unittest.main()
