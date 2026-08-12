"""Optional process boundary for generated analysis snippets."""
from __future__ import annotations

import json
import base64
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, is_dataclass
from typing import Any, Dict

_CHILD = r'''import json, sys, types, builtins
payload = json.load(sys.stdin)
allowed = {"math", "re", "collections", "statistics", "zipfile", "io"}
names = "abs all any bool dict enumerate filter float getattr hasattr int len list map max min print range repr round set sorted str sum tuple type zip Exception ValueError TypeError KeyError IndexError".split()
safe = {k: getattr(builtins, k) for k in names if hasattr(builtins, k)}
def imp(name, *args, **kwargs):
    if name in allowed:
        return __import__(name, *args, **kwargs)
    raise ImportError("module not allowed: " + name)
safe["__import__"] = imp
class _AttrDict(dict):
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)
def obj(v):
    if isinstance(v, dict):
        return _AttrDict({k: obj(x) for k, x in v.items()})
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


def _run_local(code: str, variables: Dict[str, Any], timeout: float) -> Dict[str, Any]:
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


def _run_opensandbox(code: str, variables: Dict[str, Any],
                     timeout: float) -> Dict[str, Any]:
    """Run the existing restricted child inside an OpenSandbox container."""
    try:
        from datetime import timedelta
        from opensandbox import SandboxSync
        from opensandbox.config import ConnectionConfigSync
        from opensandbox.models.sandboxes import NetworkPolicy
    except ImportError:
        return {"error": ("OpenSandbox backend requested but the SDK is missing; "
                          "install requirements-opensandbox.txt")}

    domain = os.environ.get("OPEN_SANDBOX_DOMAIN")
    if not domain:
        return {"error": "OPEN_SANDBOX_DOMAIN is required for OpenSandbox"}
    # The variables payload (all packets/flows/alerts) can exceed 1 MB as
    # base64. Embedding it in argv blows past Linux MAX_ARG_STRLEN (~128 KB)
    # and the execd silently drops the command. Write it to a file inside the
    # container instead and have the child read it back.
    payload_path = "/tmp/easyshark_payload.b64"
    payload = json.dumps({"code": code, "variables": _jsonable(variables)})
    payload64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    child = _CHILD.replace(
        "import json, sys, types, builtins",
        "import json, sys, types, builtins, base64").replace(
        "payload = json.load(sys.stdin)",
        "payload = json.loads(base64.b64decode(open("
        + repr(payload_path) + ", 'rb').read()))")
    child64 = base64.b64encode(child.encode("utf-8")).decode("ascii")
    command = ("python -c \"import base64;exec(compile(base64.b64decode('" +
               child64 + "'),'<easyshark-opensandbox>','exec'))\"")
    config = ConnectionConfigSync(
        domain=domain,
        protocol=os.environ.get("OPEN_SANDBOX_PROTOCOL", "https"),
        api_key=os.environ.get("OPEN_SANDBOX_API_KEY"),
        request_timeout=timedelta(seconds=max(10.0, timeout + 5.0)))
    sandbox = None
    try:
        sandbox = SandboxSync.create(
            os.environ.get("EASYSHARK_SANDBOX_IMAGE", "python:3.12-slim"),
            connection_config=config,
            timeout=timedelta(seconds=max(60.0, timeout + 10.0)),
            resource={"cpu": "1", "memory": "256Mi"},
            network_policy=NetworkPolicy(defaultAction="deny", egress=[]))
        try:
            sandbox.files.write_file(
                payload_path, payload64 + "\n", encoding="utf-8")
        except Exception as exc:
            return {"error": f"OpenSandbox payload upload failed: {exc}"}
        execution = sandbox.commands.run(command)
        stdout = "".join(getattr(item, "text", str(item))
                         for item in execution.logs.stdout)
        result = json.loads(stdout.strip() or "{}")
        result["sandbox_backend"] = "opensandbox"
        return result
    except Exception as exc:
        return {"error": f"OpenSandbox execution failed: {exc}"}
    finally:
        if sandbox is not None:
            try:
                sandbox.destroy()
            except Exception:
                pass


def run(code: str, variables: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    if not isinstance(code, str) or len(code) > 4000:
        return {"error": "isolated code is missing or exceeds 4000 characters"}
    backend = os.environ.get("EASYSHARK_SANDBOX_BACKEND", "local").lower()
    if backend == "opensandbox":
        return _run_opensandbox(code, variables, timeout)
    if backend == "auto" and os.environ.get("OPEN_SANDBOX_DOMAIN"):
        remote = _run_opensandbox(code, variables, timeout)
        if "error" not in remote:
            return remote
    if backend not in ("local", "auto", "process"):
        return {"error": "EASYSHARK_SANDBOX_BACKEND must be local, auto, or opensandbox"}
    result = _run_local(code, variables, timeout)
    result.setdefault("sandbox_backend", "local-process")
    return result
