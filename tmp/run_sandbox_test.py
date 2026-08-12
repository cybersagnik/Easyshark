"""Manual E2E test for the OpenSandbox container backend.

Exercises ai/tool_registry.run_python_eval -> ai.sandbox.run ->
SandboxSync (Docker) against the LOCAL server on 127.0.0.1:8080.

Requires (from .env):
  EASYSHARK_PROCESS_SANDBOX=1
  EASYSHARK_SANDBOX_BACKEND=opensandbox
  OPEN_SANDBOX_DOMAIN=http://127.0.0.1:8080
  OPEN_SANDBOX_PROTOCOL=http

Run:  python3 tmp/run_sandbox_test.py
"""
import os
import sys
import tempfile

sys.path.insert(0, "/mnt/d/Easyshark")
os.environ.setdefault("EASYSHARK_PROCESS_SANDBOX", "1")
os.environ.setdefault("EASYSHARK_SANDBOX_BACKEND", "opensandbox")
os.environ.setdefault("OPEN_SANDBOX_DOMAIN", "http://127.0.0.1:8080")
os.environ.setdefault("OPEN_SANDBOX_PROTOCOL", "http")

from cli.shell import InteractiveShell  # noqa: E402
from ai.tool_registry import ToolContext, run_python_eval  # noqa: E402

PCAP = "/mnt/d/Easyshark/PCAP_SAMPLES/evidence02.pcap"

PASS = "PASS"
FAIL = "FAIL"


def check(name, cond, detail=""):
    tag = PASS if cond else FAIL
    print(f"  [{tag}] {name}" + (f"  ({detail})" if detail else ""))
    return cond


def main():
    print("=" * 60)
    print("OpenSandbox container backend — E2E test")
    print("=" * 60)

    # Health of the local control plane.
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=5) as r:
            health = r.read().decode().strip()
        ok = "healthy" in health
    except Exception as exc:
        health, ok = str(exc), False
    if not check("local server /health", ok, health):
        print("\nStart it first:\n"
              "  OPENSANDBOX_INSECURE_SERVER=YES nohup opensandbox-server "
              "--config ~/.sandbox.toml &")
        return 1

    shell = InteractiveShell(PCAP, enable_ai=False)
    ctx = ToolContext(
        packets=shell.get_packets(),
        flows=shell.flow_engine.get_all_flows(),
        alerts=[a for r in shell.rules for a in r.get_alerts()],
        stats_engine=shell.stats_engine,
        flow_engine=shell.flow_engine,
    )
    print(f"\nLoaded {PCAP}: {len(ctx.packets)} packets")

    all_ok = True

    print("\n-- happy path (real packets over the wire into Docker) --")
    r = run_python_eval("result = len(packets)", ctx)
    all_ok &= check("eval len(packets)", "error" not in r,
                    str(r.get("result")))
    all_ok &= check("container backend used", r.get("sandbox_backend") == "opensandbox",
                    str(r.get("sandbox_backend")))

    r = run_python_eval(
        "from collections import Counter; "
        "result = Counter(p.protocol for p in packets).most_common(1)[0]",
        ctx)
    all_ok &= check("safe import + read packets", "error" not in r,
                    str(r.get("result")))

    r = run_python_eval(
        "result = sum(1 for p in packets if getattr(p, 'src_ip', '') == "
        "'192.168.1.159')", ctx)
    all_ok &= check("iterate + filter packets", "error" not in r,
                    str(r.get("result")))

    print("\n-- isolation (must all be blocked) --")
    r = run_python_eval("result = open('/etc/passwd').read()", ctx)
    all_ok &= check("open() rejected", "error" in r, str(r.get("error", "")))
    all_ok &= check("host /etc/passwd not leaked", "root:" not in str(r),
                    str(r)[:60])

    r = run_python_eval("import socket; result = 1", ctx)
    all_ok &= check("socket import rejected", "error" in r, str(r.get("error", "")))

    r = run_python_eval("import subprocess; result = 1", ctx)
    all_ok &= check("subprocess import rejected", "error" in r,
                    str(r.get("error", "")))

    r = run_python_eval("import os; result = os.listdir('/etc')", ctx)
    all_ok &= check("os not importable in eval", "error" in r,
                    str(r.get("error", ""))[:60])

    r = run_python_eval("result = __import__('os').getcwd()", ctx)
    all_ok &= check("dynamic os import rejected", "error" in r,
                    str(r.get("error", ""))[:60])

    print("\n-- robustness --")
    r = run_python_eval("result = len(packets", ctx)
    all_ok &= check("syntax error reported", "error" in r, str(r.get("error", "")))

    r = run_python_eval("x = 1", ctx)
    all_ok &= check("missing result returns None", r.get("result") is None, "")

    # Only if a sandbox boom is easy to trigger — skip by default.
    print(f"\n{'ALL PASS' if all_ok else 'SOME FAILED'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())