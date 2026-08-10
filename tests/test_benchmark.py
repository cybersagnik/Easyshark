import unittest

from ai.benchmark import score


class TestBenchmark(unittest.TestCase):
    def test_scores_active_pattern_against_labels(self):
        result = score([
            {"status": "active", "question_keywords": ["smtp", "username"],
             "tool_sequence": ["get_smtp_credentials"]}],
            [{"question": "SMTP username", "expected_tools": ["get_smtp_credentials"]}])
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
