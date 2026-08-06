"""Planner allow_llm routing tests. No LLM executed."""
import unittest

from ai.planner import CommandPlanner


class TestPlannerAllowLLM(unittest.TestCase):
    def test_allow_llm_false_routes_unclassifiable_to_analyze_without_llm(self):
        p = CommandPlanner(llm_client=None)
        # The heuristic catch-all routes any non-empty input to the
        # explainer ("analyze ..."). allow_llm=False must not change that
        # routing and must never touch the (absent) LLM client.
        self.assertEqual(p.plan("good morning", {}, allow_llm=False),
                         "analyze good morning")

    def test_heuristic_verb_still_routes_with_allow_llm_false(self):
        p = CommandPlanner(llm_client=None)
        self.assertEqual(p.plan("stats", {}, allow_llm=False), "stats")

    def test_factual_question_heuristic_routes_to_analyze(self):
        p = CommandPlanner(llm_client=None)
        d = p.plan("what SMTP username was used?",
                   {"triage": {}}, allow_llm=False)
        self.assertIsNotNone(d)
        self.assertTrue(d.startswith("analyze"))

    def test_empty_input_returns_none(self):
        p = CommandPlanner(llm_client=None)
        self.assertIsNone(p.plan("", {}, allow_llm=True))
        self.assertIsNone(p.plan("  ", {}, allow_llm=False))


if __name__ == "__main__":
    unittest.main()
