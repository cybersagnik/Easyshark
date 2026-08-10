"""Independent-feedback promotion tests for the RSI learner."""
import tempfile
import unittest
from pathlib import Path

import ai.pattern_learner as learner
from ai.rsi import record_feedback, status


class TestRSI(unittest.TestCase):
    def setUp(self):
        self.old_path = learner.PATTERNS_PATH
        self.tmp = tempfile.TemporaryDirectory()
        learner.PATTERNS_PATH = Path(self.tmp.name) / "patterns.jsonl"

    def tearDown(self):
        learner.PATTERNS_PATH = self.old_path
        self.tmp.cleanup()

    def test_candidates_are_not_used_before_feedback(self):
        learner.update_patterns("smtp username", ["get_smtp_credentials"], 1.0)
        self.assertIsNone(learner.suggest_tools("what SMTP username was used"))
        self.assertEqual(status()["candidate"], 1)

    def test_three_good_labels_promote_pattern(self):
        learner.update_patterns("smtp username", ["get_smtp_credentials"], 1.0)
        for _ in range(3):
            self.assertEqual(record_feedback("what SMTP username was used", True), 1)
        self.assertEqual(learner.suggest_tools("what SMTP username was used"),
                         ["get_smtp_credentials"])
        self.assertEqual(status()["active"], 1)

    def test_repeated_bad_labels_retire_pattern(self):
        learner.update_patterns("smtp username", ["get_smtp_credentials"], 1.0)
        for _ in range(3):
            record_feedback("what SMTP username was used", False)
        self.assertIsNone(learner.suggest_tools("what SMTP username was used"))
        self.assertEqual(status()["retired"], 1)


if __name__ == "__main__":
    unittest.main()
