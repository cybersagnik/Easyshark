"""Optional process boundary for generated analysis snippets."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from typing import Any, Dict

_CHILD = r'''import json, sys, types, builtins
payload = json.load(sys.stdin)
allowed = {"math", "re", "collections", "statistics"}
names = "abs all any bool dict enumerate filter float getattr hasattr int len list map max min print range repr round set sorted str sum tuple type zip Exception ValueError TypeError KeyError IndexError".split()
safe = {k: getattr(builtins, k) for k in names if hasattr(builtins, k)}
def imp(name, *args, **kwargs):
    if name in allowed:
        return __import__(name, *args, **kwargs)
    raise ImportError("module not allowed: " + name)
safe["__import__"] = imp
def obj(v):
    if isinstance(v, dict):
        return types.SimpleNamespace(**{k: obj(x) for k, x in v.items()})
    if isinstance(v, list):
        return [obj(x) for x in v]
    return v
ns = {k: obj(v) for k, v in payload.get("variables", {}).items()}
ns["__builtins__"] = safe
try:
    exec(compile(payload["code"], "<isolated_python_eval>", "exec"), ns, ns)
    print(json.dumps({"result": ns.get("result")}, default=str))
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__ + ": " + str(exc)}))
'''


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def run(code: str, variables: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    if not isinstance(code, str) or len(code) > 4000:
        return {"error": "isolated code is missing or exceeds 4000 characters"}
    with tempfile.TemporaryDirectory(prefix="easyshark-sandbox-") as cwd:
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-S", "-c", _CHILD],
                input=json.dumps({"code": code, "variables": _jsonable(variables)}),
                text=True, capture_output=True, timeout=timeout,
                cwd=cwd, env={"PYTHONIOENCODING": "utf-8"}, check=False)
        except subprocess.TimeoutExpired:
            return {"error": "isolated python timeout"}
        if proc.returncode != 0:
            return {"error": f"isolated python exited with {proc.returncode}"}
        try:
            return json.loads(proc.stdout.strip() or "{}")
        except json.JSONDecodeError:
            return {"error": "isolated python returned invalid JSON"}
