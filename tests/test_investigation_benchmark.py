import tempfile
import unittest
from pathlib import Path

from core.investigation_benchmark import benchmark


class TestInvestigationBenchmark(unittest.TestCase):
    def test_benchmark_proves_cache_equivalence(self):
        capture = (Path(__file__).resolve().parents[1] / "PCAP_SAMPLES" /
                   "evidence01.pcap")
        result = benchmark(str(capture))
        self.assertTrue(result["equivalent"])
        self.assertGreater(result["packets"], 0)
        self.assertEqual(set(result["latency_ms"]), {
            "initial_load", "cold_analysis", "memory_cache_hit",
            "restart_load", "restart_cache_hit",
        })


if __name__ == "__main__":
    unittest.main()
