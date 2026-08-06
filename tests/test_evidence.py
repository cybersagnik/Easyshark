"""Deterministic evidence-bundle tests. No LLM executed."""
import os
import unittest

from ai.evidence import build_evidence_bundle, clear_bundle_cache

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP01 = os.path.join(ROOT, "PCAP_SAMPLES", "evidence01.pcap")
PCAP02 = os.path.join(ROOT, "PCAP_SAMPLES", "evidence02.pcap")


def _shell(pcap):
    from cli.shell import InteractiveShell
    s = InteractiveShell(pcap, enable_ai=False)
    return s, s.get_packets(), s.flow_engine.get_all_flows()


class TestEvidenceBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PCAP01) or not os.path.exists(PCAP02):
            raise unittest.SkipTest("evidence01/02 pcaps missing")
        cls.s01, cls.p01, cls.f01 = _shell(PCAP01)
        cls.s02, cls.p02, cls.f02 = _shell(PCAP02)

    def test_evidence02_smtp(self):
        b = build_evidence_bundle(self.p02, self.f02, [], pcap_path=PCAP02)
        self.assertIn("smtp_creds", b)
        self.assertIn("sneakyg33k@aol.com", b)
        self.assertIn("attachment", b)

    def test_evidence01_im_carve(self):
        b = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        self.assertIn("carved_file", b)
        self.assertIn("recipe.docx", b.lower())

    def test_cache_returns_identical_bundle(self):
        clear_bundle_cache()
        b1 = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        b2 = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        self.assertEqual(b1, b2)

    def test_clear_rebuilds_deterministically(self):
        clear_bundle_cache()
        b1 = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        clear_bundle_cache()
        b2 = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        self.assertEqual(b1, b2)

    def test_length_capped(self):
        b = build_evidence_bundle(self.p02, self.f02, [],
                                  pcap_path=PCAP02, max_chars=2000)
        self.assertLessEqual(len(b), 2060)

    def test_empty_packets_no_crash(self):
        b = build_evidence_bundle([], [], [], pcap_path=PCAP01)
        self.assertIsInstance(b, str)
        self.assertIn("packets=0", b)

    # ---- L1: count / distinct / correlation sections ------------------ #

    def test_l1_distinct_emails(self):
        b = build_evidence_bundle(self.p02, self.f02, [], pcap_path=PCAP02)
        self.assertIn("distinct_emails=", b)
        self.assertIn("sneakyg33k@aol.com", b)
        self.assertIn("mistersecretx@aol.com", b.lower())

    def test_l1_smtp_recipients(self):
        b = build_evidence_bundle(self.p02, self.f02, [], pcap_path=PCAP02)
        self.assertIn("smtp_recipients=", b)

    def test_l1_flow_aggregates(self):
        b = build_evidence_bundle(self.p01, self.f01, [], pcap_path=PCAP01)
        self.assertIn("flows_by_proto=", b)
        self.assertIn("top_flows=", b)
        self.assertIn("bytes=", b)

    def test_l1_bundle_still_bounded(self):
        b = build_evidence_bundle(self.p02, self.f02, [],
                                  pcap_path=PCAP02, max_chars=4000)
        self.assertLessEqual(len(b), 4060)


if __name__ == "__main__":
    unittest.main()
