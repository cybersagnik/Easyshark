"""Import smoke test — every module under ai/cli/core/config/detect/
preprocessors must import cleanly. No LLM is executed."""
import importlib
import pkgutil
import unittest

import ai
import cli
import config
import core
import detect
import preprocessors


class TestImports(unittest.TestCase):
    def test_all_modules_import(self):
        mods = []
        for pkg in (ai, cli, core, config, detect, preprocessors):
            for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
                mods.append(m.name)
        failures = []
        for m in sorted(mods):
            try:
                importlib.import_module(m)
            except SystemExit:
                pass  # argparse/--help modules exit by design
            except Exception as exc:  # noqa: BLE001 - report any import error
                failures.append((m, repr(exc)))
        self.assertEqual(failures, [], "Import failures:\n" +
                         "\n".join(f"  {m}: {e}" for m, e in failures))

    def test_evidence_api(self):
        from ai import evidence
        self.assertTrue(callable(evidence.build_evidence_bundle))
        self.assertTrue(callable(evidence.clear_bundle_cache))

    def test_tool_registry_tools(self):
        from ai.tool_registry import TOOL_EXECUTORS, TOOL_SCHEMAS
        self.assertGreaterEqual(len(TOOL_EXECUTORS), 11)
        self.assertEqual(len(TOOL_SCHEMAS), len(TOOL_EXECUTORS))


if __name__ == "__main__":
    unittest.main()
