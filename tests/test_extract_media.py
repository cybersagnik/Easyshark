"""Deterministic test for extract_embedded_media — extracts embedded
images from .docx SMTP attachments and writes them to a host path.
No LLM, no sandbox container, no network."""
import os
import tempfile
import unittest

PCAP02 = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                      "PCAP_SAMPLES", "evidence02.pcap")

# Ground truth: the embedded media md5 inside secretrendezvous.docx
# (from the deterministic pre-analysis evidence bundle).
EXPECTED_MEDIA_MD5 = "aadeace50997b1ba24b09ac2ef1940b7"


class TestExtractEmbeddedMedia(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cli.shell import InteractiveShell
        from ai.tool_registry import ToolContext
        shell = InteractiveShell(PCAP02, enable_ai=False)
        cls.ctx = ToolContext(
            packets=shell.get_packets(),
            flows=shell.flow_engine.get_all_flows(),
            alerts=[a for r in shell.rules for a in r.get_alerts()],
            stats_engine=shell.stats_engine,
            flow_engine=shell.flow_engine,
        )

    def test_extracts_image_to_disk(self):
        from ai.tool_registry import tool_extract_embedded_media
        with tempfile.TemporaryDirectory(prefix="easyshark-media-") as tmp:
            result = tool_extract_embedded_media(
                {"output_dir": tmp}, self.ctx)
        self.assertNotIn("error", result, str(result))
        self.assertGreaterEqual(result.get("count", 0), 1)
        md5s = [s["md5"] for s in result["saved"]]
        self.assertIn(EXPECTED_MEDIA_MD5, md5s,
                      f"expected {EXPECTED_MEDIA_MD5} in {md5s}")
        for s in result["saved"]:
            self.assertTrue(os.path.basename(s["filename"]),
                            f"empty basename: {s}")
            self.assertNotIn("..", s["filename"],
                             "path traversal in saved filename")

    def test_file_actually_written(self):
        from ai.tool_registry import tool_extract_embedded_media
        with tempfile.TemporaryDirectory(prefix="easyshark-media-") as tmp:
            result = tool_extract_embedded_media(
                {"output_dir": tmp}, self.ctx)
            self.assertNotIn("error", result)
            for s in result["saved"]:
                self.assertTrue(os.path.isfile(s["path"]),
                                f"file not written: {s['path']}")
                self.assertGreater(os.path.getsize(s["path"]), 0)

    def test_missing_output_dir_errors(self):
        from ai.tool_registry import tool_extract_embedded_media
        result = tool_extract_embedded_media({}, self.ctx)
        self.assertIn("error", result)

    def test_no_docx_in_non_smtp_capture(self):
        from cli.shell import InteractiveShell
        from ai.tool_registry import ToolContext, tool_extract_embedded_media
        pcap01 = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                              "PCAP_SAMPLES", "evidence01.pcap")
        shell = InteractiveShell(pcap01, enable_ai=False)
        ctx = ToolContext(
            packets=shell.get_packets(),
            flows=shell.flow_engine.get_all_flows(),
            alerts=[a for r in shell.rules for a in r.get_alerts()],
            stats_engine=shell.stats_engine,
            flow_engine=shell.flow_engine,
        )
        with tempfile.TemporaryDirectory(prefix="easyshark-media-") as tmp:
            result = tool_extract_embedded_media(
                {"output_dir": tmp}, ctx)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
