"""TrafficExplainer routing tests with a stubbed LLM (no network)."""
import os
import unittest

from ai.explainer import TrafficExplainer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP01 = os.path.join(ROOT, "PCAP_SAMPLES", "evidence01.pcap")


class _FakeLLM:
    """Duck-typed stand-in for LLMClient. Never touches the network."""

    def __init__(self, stream_deltas=None, tools_answer="Answer: fallback (source: get_statistics)"):
        self.stream_deltas = list(stream_deltas or [])
        self.tools_answer = tools_answer
        self.stream_called = False
        self.tools_called = False
        self.evidence_seeded = None
        self.seeded_question = None

    def is_available(self):
        return True

    def query_stream(self, prompt, **kwargs):
        self.stream_called = True
        for delta in self.stream_deltas:
            yield delta

    def query_with_tools(self, question, context, system_prompt=None,
                         evidence_seeded=False, **kwargs):
        self.tools_called = True
        self.evidence_seeded = evidence_seeded
        self.seeded_question = question
        return self.tools_answer

    def query(self, *args, **kwargs):
        return "Answer: one (source: summary)"


class TestExplainerNoLLM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PCAP01):
            raise unittest.SkipTest("evidence01 pcap missing")
        from cli.shell import InteractiveShell
        cls.shell = InteractiveShell(PCAP01, enable_ai=False)
        cls.packets = cls.shell.get_packets()
        cls.flows = cls.shell.flow_engine.get_all_flows()
        cls.alerts = [a for r in cls.shell.rules for a in r.get_alerts()]

    def test_single_shot_stream_used_first(self):
        fake = _FakeLLM(stream_deltas=["Answer: Sec558user1 (source: extract_strings)"])
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("what IM screen name appears in the capture?",
                                  self.packets, self.flows, self.alerts)
        self.assertIn("Sec558user1", ans)
        self.assertTrue(fake.stream_called, "single-shot streaming should be primary")
        self.assertFalse(fake.tools_called, "tool loop must not fire when evidence answers")

    def test_insufficient_data_falls_back_to_tools(self):
        fake = _FakeLLM(stream_deltas=["Insufficient data"],
                        tools_answer="Answer: 16 (source: list_flows)")
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("how many flows exist?",
                                  self.packets, self.flows, self.alerts)
        self.assertEqual(ans, "Answer: 16 (source: list_flows)")
        self.assertTrue(fake.tools_called)
        self.assertTrue(fake.evidence_seeded,
                        "tool-loop fallback must be seeded with the bundle")
        self.assertIn("DETERMINISTIC EVIDENCE", fake.seeded_question)

    def test_empty_single_shot_falls_back_to_tools(self):
        fake = _FakeLLM(stream_deltas=[])
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("some question", self.packets, self.flows, self.alerts)
        self.assertEqual(ans, "Answer: fallback (source: get_statistics)")
        self.assertTrue(fake.tools_called)

    def test_tool_plan_single_shot_falls_back_to_tools(self):
        # The free-tier model prints its intended call as JSON text instead
        # of answering. That must NOT be surfaced — fall through to tools.
        fake = _FakeLLM(
            stream_deltas=['{"tool": "extract_files", "args": '
                           '{"file_type": "docx"}}'],
            tools_answer="Answer: recipe.docx (source: extract_files)")
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("what file was transferred?",
                                  self.packets, self.flows, self.alerts)
        self.assertEqual(ans, "Answer: recipe.docx (source: extract_files)")
        self.assertTrue(fake.stream_called)
        self.assertTrue(fake.tools_called)

    def test_no_tools_system_prompt_for_single_shot(self):
        # The single-shot completion must not advertise tools — a
        # tools-laden system prompt makes free-tier models echo JSON.
        class RecordingLLM(_FakeLLM):
            def __init__(self):
                super().__init__(stream_deltas=["Answer: ok (source: evidence)"])
                self.sys_prompts = []

            def query_stream(self, prompt, **kwargs):
                self.sys_prompts.append(kwargs.get("system_prompt"))
                return super().query_stream(prompt, **kwargs)

        rec = RecordingLLM()
        exp = TrafficExplainer(rec)
        exp.explain_traffic("what file was attached?",
                            self.packets, self.flows, self.alerts)
        self.assertTrue(rec.sys_prompts)
        sys_prompt = (rec.sys_prompts[0] or "").lower()
        self.assertIn("no tools available", sys_prompt)
        self.assertNotIn("tools to prefer", sys_prompt)

    def test_single_shot_extracts_last_real_answer_line(self):
        # Reasoning model thinks out loud, then ends with the answer line.
        # Only the real final line must be surfaced.
        from ai.explainer import _extract_single_shot_answer
        reply = (
            "The smtp_creds field shows two entries with the same email. "
            "Since only one distinct address appears, the count is 1.\n"
            "Answer: 1 (source: smtp_creds)"
        )
        self.assertEqual(
            _extract_single_shot_answer(reply),
            "Answer: 1 (source: smtp_creds)")

    def test_single_shot_rejects_template_echo(self):
        # The model quoting the format instruction mid-thought is NOT an
        # answer; neither is a truncated deliberation with no answer line.
        from ai.explainer import _extract_single_shot_answer
        self.assertIsNone(_extract_single_shot_answer(
            "The field could be 'smtp_creds' or 'usernames'. I'll use "
            "'smtp_creds' as it's explicit. Answer: <value> (source: "
            "<field/tool>)'"))
        self.assertIsNone(_extract_single_shot_answer(
            "Since only one distinct email address appears, answer is 1. I"))
        self.assertIsNone(_extract_single_shot_answer(""))

    def test_rambling_single_shot_still_answers(self):
        fake = _FakeLLM(stream_deltas=[
            "The smtp_creds shows two entries but same email. Answer: 1 "
            "(source: smtp_creds)"])
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("how many emails are there?",
                                  self.packets, self.flows, self.alerts)
        self.assertEqual(ans, "Answer: 1 (source: smtp_creds)")
        self.assertFalse(fake.tools_called,
                         "a complete answer line must not fall through to tools")

    def test_truncated_single_shot_falls_back_to_tools(self):
        # Model burns the whole token budget reasoning without a final
        # Answer line — must NOT be printed; fall through to the tool loop.
        fake = _FakeLLM(stream_deltas=[
            "The smtp_creds shows two entries but same email. Since only "
            "one distinct address appears, answer is 1. I"],
            tools_answer="Answer: 1 (source: get_smtp_credentials)")
        exp = TrafficExplainer(fake)
        ans = exp.explain_traffic("how many emails are there?",
                                  self.packets, self.flows, self.alerts)
        self.assertEqual(ans, "Answer: 1 (source: get_smtp_credentials)")
        self.assertTrue(fake.tools_called)

    def test_llm_unavailable_offline_summary(self):
        class NoLLM:
            def is_available(self):
                return False
        exp = TrafficExplainer(NoLLM())
        ans = exp.explain_traffic("any question", self.packets, self.flows, self.alerts)
        self.assertIsInstance(ans, str)
        self.assertIn("Traffic Analysis Summary", ans)


if __name__ == "__main__":
    unittest.main()
