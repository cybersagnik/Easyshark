import unittest

from core.production_gate import assess_manifest, assess_metrics, result_document


def _production_manifest():
    cases = []
    classes = ["attack", "benign", "encrypted", "malformed", "noisy"]
    for index in range(500):
        cases.append({
            "id": f"case-{index}", "sha256": f"{index:064x}",
            "split": "held_out" if index < 100 else "train",
            "traffic_classes": [classes[index % len(classes)]],
        })
    return {
        "schema": "easyshark.corpus.v2", "cases": cases,
        "provenance": {"kind": "independent"},
        "labeling": {"independent": True, "reviewers": 2},
    }


class TestProductionGate(unittest.TestCase):
    def test_complete_independent_manifest_passes_metadata_contract(self):
        gates = assess_manifest(_production_manifest())
        self.assertTrue(all(row["passed"] for row in gates), gates)

    def test_synthetic_or_small_manifest_fails_closed(self):
        manifest = _production_manifest()
        manifest["cases"] = manifest["cases"][:7]
        manifest["provenance"]["kind"] = "synthetic"
        failed = {row["name"] for row in assess_manifest(manifest)
                  if not row["passed"]}
        self.assertTrue({"case_count", "independent_labels",
                         "held_out_split"} <= failed)

    def test_metrics_enforce_calibration_and_execution(self):
        good = {"failed": [], "ece": .09, "brier": .14,
                "by_subject": {"beacon": {"false_positives": 0,
                                             "false_negatives": 0}}}
        self.assertTrue(result_document(assess_metrics(good))["ready"])
        bad = dict(good, ece=.1, failed=[{"case": 1}])
        failed = {row["name"] for row in assess_metrics(bad)
                  if not row["passed"]}
        self.assertEqual(failed, {"corpus_execution", "calibration_ece"})


if __name__ == "__main__":
    unittest.main()
