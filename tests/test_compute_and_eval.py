"""L2 compute_packets (structured DSL) + L3 python_eval (gated sandbox).
No LLM / network — deterministic executors over real evidence01 packets."""
import json
import os
import tempfile
import unittest

from ai.tool_registry import (
    ToolContext, tool_compute_packets, run_python_eval,
    filter_tool_schemas, PYTHON_EVAL_ENABLED,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAP01 = os.path.join(ROOT, "PCAP_SAMPLES", "evidence01.pcap")


class TestComputePackets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PCAP01):
            raise unittest.SkipTest("evidence01 pcap missing")
        from cli.shell import InteractiveShell
        cls.shell = InteractiveShell(PCAP01, enable_ai=False)
        cls.ctx = ToolContext(
            packets=cls.shell.get_packets(),
            flows=cls.shell.flow_engine.get_all_flows(),
            alerts=[a for r in cls.shell.rules for a in r.get_alerts()],
            stats_engine=cls.shell.stats_engine,
            flow_engine=cls.shell.flow_engine,
        )

    def test_group_by_protocol_count(self):
        r = tool_compute_packets({"group_by": "protocol"}, self.ctx)
        self.assertNotIn("error", r)
        self.assertEqual(r["matched"], len(self.ctx.packets))
        names = {row["key"] for row in r["rows"]}
        self.assertIn("TCP", names)

    def test_count_distinct_dst_ip(self):
        r = tool_compute_packets(
            {"aggregate": "count_distinct", "on": "dst_ip"}, self.ctx)
        self.assertNotIn("error", r)
        expected = len({p.dst_ip for p in self.ctx.packets if p.dst_ip})
        self.assertEqual(r["result"], expected)

    def test_where_filter_matches_manual(self):
        r = tool_compute_packets(
            {"where": "protocol == 'TCP'", "aggregate": "count"}, self.ctx)
        self.assertNotIn("error", r)
        expected = sum(1 for p in self.ctx.packets if p.protocol == "TCP")
        self.assertEqual(r["result"], expected)

    def test_sum_with_where(self):
        r = tool_compute_packets(
            {"aggregate": "sum", "on": "length",
             "where": "protocol == 'TCP'"}, self.ctx)
        self.assertNotIn("error", r)
        expected = sum(p.length for p in self.ctx.packets
                       if p.protocol == "TCP")
        self.assertEqual(r["result"], expected)

    def test_grouped_sum(self):
        r = tool_compute_packets(
            {"group_by": "protocol", "aggregate": "sum", "on": "length"},
            self.ctx)
        self.assertNotIn("error", r)
        by_proto = {}
        for p in self.ctx.packets:
            by_proto[p.protocol] = by_proto.get(p.protocol, 0) + p.length
        self.assertEqual(
            {row["key"]: row["value"] for row in r["rows"]},
            {k: v for k, v in by_proto.items() if k is not None})

    def test_and_or_where(self):
        r = tool_compute_packets(
            {"where": "src_ip == '192.168.1.158' or dst_ip == '64.12.24.50'",
             "aggregate": "count"}, self.ctx)
        self.assertNotIn("error", r)
        self.assertGreater(r["result"], 0)

    def test_invalid_group_by_rejected(self):
        r = tool_compute_packets({"group_by": "bogus"}, self.ctx)
        self.assertIn("error", r)
        self.assertIn("bogus", r["error"])

    def test_bad_where_rejected(self):
        r = tool_compute_packets({"where": "protocol >>> 'TCP'"}, self.ctx)
        self.assertIn("error", r)

    def test_unknown_field_in_where_rejected(self):
        r = tool_compute_packets({"where": "nope == 1"}, self.ctx)
        self.assertIn("error", r)

    def test_unknown_aggregate_rejected(self):
        r = tool_compute_packets({"aggregate": "median"}, self.ctx)
        self.assertIn("error", r)

    def test_limit_applied(self):
        r = tool_compute_packets(
            {"group_by": "dst_ip", "aggregate": "count", "limit": 3}, self.ctx)
        self.assertNotIn("error", r)
        self.assertLessEqual(len(r["rows"]), 3)


class TestPythonEval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PCAP01):
            raise unittest.SkipTest("evidence01 pcap missing")
        from cli.shell import InteractiveShell
        cls.shell = InteractiveShell(PCAP01, enable_ai=False)
        cls.ctx = ToolContext(
            packets=cls.shell.get_packets(),
            flows=cls.shell.flow_engine.get_all_flows(),
            alerts=[a for r in cls.shell.rules for a in r.get_alerts()],
            stats_engine=cls.shell.stats_engine,
            flow_engine=cls.shell.flow_engine,
        )

    def test_eval_len(self):
        r = run_python_eval("result = len(packets)", self.ctx)
        self.assertNotIn("error", r)
        self.assertEqual(r["result"], len(self.ctx.packets))

    def test_eval_safe_import(self):
        code = ("from collections import Counter; "
                "result = len(Counter(p.protocol for p in packets))")
        r = run_python_eval(code, self.ctx)
        self.assertNotIn("error", r)
        self.assertGreaterEqual(r["result"], 1)

    def test_banlist_rejected(self):
        r = run_python_eval("result = open('/etc/passwd').read()", self.ctx)
        self.assertIn("error", r)
        self.assertIn("open", r["error"])

    def test_bad_import_rejected(self):
        r = run_python_eval("import socket; result = 1", self.ctx)
        self.assertIn("error", r)

    def test_syntax_error_reported(self):
        r = run_python_eval("result = len(packets", self.ctx)
        self.assertIn("error", r)

    def test_missing_result(self):
        r = run_python_eval("x = 1", self.ctx)
        self.assertIn("result", r)
        self.assertIsNone(r["result"])

    def test_audit_log_written(self):
        import ai.tool_registry as tr
        fd, path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        try:
            old = tr._PY_EVAL_LOG_PATH
            tr._PY_EVAL_LOG_PATH = path
            try:
                run_python_eval("result = len(packets)", self.ctx)
            finally:
                tr._PY_EVAL_LOG_PATH = old
            with open(path, encoding="utf-8") as fh:
                row = json.loads(fh.readline().strip())
            self.assertEqual(row["error"], False)
            self.assertIn("result = len(packets)", row["code_preview"])
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


class TestPythonEvalGate(unittest.TestCase):
    def test_gate_hides_python_eval_by_default_off(self):
        import ai.tool_registry as tr
        names = {s["function"]["name"] for s in
                 filter_tool_schemas({"tcp": True}, None)}
        self.assertIn("compute_packets", names)
        if not PYTHON_EVAL_ENABLED:
            self.assertNotIn("python_eval", names)

    def test_gate_shows_python_eval_when_on(self):
        import ai.tool_registry as tr
        old = tr.PYTHON_EVAL_ENABLED
        tr.PYTHON_EVAL_ENABLED = True
        try:
            names = {s["function"]["name"] for s in
                     filter_tool_schemas({"tcp": True}, None)}
            self.assertIn("python_eval", names)
        finally:
            tr.PYTHON_EVAL_ENABLED = old

    def test_no_triage_returns_full_schemas(self):
        import ai.tool_registry as tr
        old = tr.PYTHON_EVAL_ENABLED
        tr.PYTHON_EVAL_ENABLED = True
        try:
            names = {s["function"]["name"] for s in filter_tool_schemas(None, None)}
            self.assertIn("python_eval", names)
        finally:
            tr.PYTHON_EVAL_ENABLED = old

    def test_create_tool_gate_off(self):
        import ai.tool_registry as tr
        old = tr.PYTHON_EVAL_ENABLED
        tr.PYTHON_EVAL_ENABLED = False
        try:
            names = {s["function"]["name"] for s in
                     filter_tool_schemas({"tcp": True}, None)}
            self.assertNotIn("create_tool", names)
        finally:
            tr.PYTHON_EVAL_ENABLED = old

    def test_create_tool_gate_on(self):
        import ai.tool_registry as tr
        old = tr.PYTHON_EVAL_ENABLED
        tr.PYTHON_EVAL_ENABLED = True
        try:
            names = {s["function"]["name"] for s in
                     filter_tool_schemas({"tcp": True}, None)}
            self.assertIn("create_tool", names)
        finally:
            tr.PYTHON_EVAL_ENABLED = old


class TestCreateTool(unittest.TestCase):
    """L4 — LLM-driven sandboxed tool creation (create_tool / register_tool)."""

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(PCAP01):
            raise unittest.SkipTest("evidence01 pcap missing")
        from cli.shell import InteractiveShell
        cls.shell = InteractiveShell(PCAP01, enable_ai=False)
        cls.ctx = ToolContext(
            packets=cls.shell.get_packets(),
            flows=cls.shell.flow_engine.get_all_flows(),
            alerts=[a for r in cls.shell.rules for a in r.get_alerts()],
            stats_engine=cls.shell.stats_engine,
            flow_engine=cls.shell.flow_engine,
        )
        import ai.tool_registry as tr
        cls.tr = tr

    def tearDown(self):
        for name in list(self.tr._CREATED_TOOLS):
            self.tr._CREATED_TOOLS.pop(name, None)
            self.tr.TOOL_EXECUTORS.pop(name, None)
            self.tr.TOOL_SCHEMAS[:] = [
                s for s in self.tr.TOOL_SCHEMAS
                if (s.get("function") or {}).get("name") != name]

    def _unique(self, base="t_created"):
        i = 0
        name = base
        while name in self.tr.TOOL_EXECUTORS:
            i += 1
            name = f"{base}{i}"
        return name

    def test_created_tool_can_be_executed(self):
        name = self._unique()
        code = ("result = len([p for p in packets "
                "if getattr(p, 'protocol', None) == 'TCP'])")
        r = self.tr.create_runtime_tool(
            name, "Count TCP packets", {"type": "object",
                                        "properties": {}}, code, self.ctx)
        self.assertNotIn("error", r)
        self.assertEqual(r["created"], name)
        self.assertTrue(self.tr.is_sandboxed_tool(name))
        # executor returns sandbox result directly
        out = self.tr.execute_tool(name, {}, self.ctx)
        self.assertNotIn("error", out)
        self.assertEqual(out["result"],
                         sum(1 for p in self.ctx.packets
                             if p.protocol == "TCP"))

    def test_created_tool_gets_args(self):
        name = self._unique()
        code = ("result = args.get('offset', 0) + "
                "len([p for p in packets if p.protocol == 'UDP'])")
        r = self.tr.create_runtime_tool(
            name, "UDP count + offset",
            {"type": "object", "properties": {
                "offset": {"type": "integer"}}},
            code, self.ctx)
        self.assertNotIn("error", r)
        expected = 100 + sum(1 for p in self.ctx.packets
                             if p.protocol == "UDP")
        out = self.tr.execute_tool(name, {"offset": 100}, self.ctx)
        self.assertNotIn("error", out)
        self.assertEqual(out["result"], expected)

    def test_schema_registered_and_callable_by_name(self):
        name = self._unique()
        self.tr.create_runtime_tool(
            name, "count arp", {"type": "object", "properties": {}},
            "result = len([p for p in packets if p.protocol == 'ARP'])",
            self.ctx)
        names = {s["function"]["name"] for s in self.tr.TOOL_SCHEMAS}
        self.assertIn(name, names)
        self.assertIn(name, self.tr.TOOL_EXECUTORS)

    def test_bad_name_rejected(self):
        r = self.tr.create_runtime_tool(
            "NotValid", "x", {"type": "object", "properties": {}},
            "result = 1", self.ctx)
        self.assertIn("error", r)

    def test_existing_name_rejected(self):
        r = self.tr.create_runtime_tool(
            "compute_packets", "x", {"type": "object", "properties": {}},
            "result = 1", self.ctx)
        self.assertIn("error", r)

    def test_banlist_escape_rejected(self):
        r = self.tr.create_runtime_tool(
            self._unique(), "x", {"type": "object", "properties": {}},
            "result = open('/etc/passwd').read()", self.ctx)
        self.assertIn("error", r)

    def test_dry_run_failure_rejected(self):
        r = self.tr.create_runtime_tool(
            self._unique(), "x", {"type": "object", "properties": {}},
            "import socket; result = 1", self.ctx)
        self.assertIn("error", r)

    def test_missing_required_fields_rejected(self):
        r = self.tr.create_runtime_tool(
            "", "", {}, "", self.ctx)
        self.assertIn("error", r)

    def test_too_long_code_rejected(self):
        r = self.tr.create_runtime_tool(
            self._unique(), "x", {"type": "object", "properties": {}},
            "result = 1" * 5000, self.ctx)
        self.assertIn("error", r)

    def test_created_tool_listing(self):
        name = self._unique()
        self.tr.create_runtime_tool(
            name, "x", {"type": "object", "properties": {}},
            "result = 1", self.ctx)
        self.assertIn(name, self.tr.list_created_tools())


if __name__ == "__main__":
    unittest.main()
