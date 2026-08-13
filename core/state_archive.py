"""Verified backup, restore, and retention tools for local v2 state."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List


MANIFEST = "easyshark-backup-manifest.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sqlite_snapshot(path: Path, temporary: Path) -> bytes:
    snapshot = temporary / path.name
    source = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    destination = sqlite3.connect(str(snapshot))
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()
    return snapshot.read_bytes()


def _key(value: str) -> bytes:
    raw = str(value or "").encode("utf-8")
    if len(raw) < 32:
        raise ValueError("backup HMAC key must contain at least 32 bytes")
    return raw


def _signature(entries: List[Dict[str, Any]], key: str) -> str:
    canonical = json.dumps(entries, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return hmac.new(_key(key), canonical, hashlib.sha256).hexdigest()


def create(state_dir: str, output_path: str, key: str) -> Dict[str, Any]:
    source = Path(state_dir).resolve()
    output = Path(output_path).resolve()
    if not source.is_dir():
        raise NotADirectoryError(str(source))
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("backup archive must be outside the state directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    with tempfile.TemporaryDirectory(prefix="easyshark-backup-") as folder, \
            zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        temporary = Path(folder)
        for path in sorted(source.rglob("*")):
            if not path.is_file() or path.is_symlink() \
                    or path.name.endswith(("-wal", "-shm")):
                continue
            relative = path.relative_to(source).as_posix()
            data = (_sqlite_snapshot(path, temporary)
                    if path.suffix.lower() == ".db" else path.read_bytes())
            archive.writestr(relative, data)
            entries.append({"path": relative, "size": len(data),
                            "sha256": _sha256(data)})
        manifest = {"schema": "easyshark.state-backup.v1",
                    "created": time.time(), "files": entries,
                    "authentication": "hmac-sha256",
                    "hmac_sha256": _signature(entries, key)}
        archive.writestr(MANIFEST,
                         json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass
    return {"archive": str(output), "files": len(entries),
            "sha256": _sha256(output.read_bytes())}


def verify(archive_path: str, key: str) -> Dict[str, Any]:
    path = Path(archive_path).resolve()
    failures: List[str] = []
    with zipfile.ZipFile(path, "r") as archive:
        try:
            manifest = json.loads(archive.read(MANIFEST))
        except (KeyError, ValueError) as exc:
            raise ValueError("backup manifest is missing or invalid") from exc
        if manifest.get("schema") != "easyshark.state-backup.v1":
            raise ValueError("unsupported backup schema")
        if manifest.get("authentication") != "hmac-sha256" or not hmac.compare_digest(
                str(manifest.get("hmac_sha256", "")),
                _signature(manifest.get("files", []), key)):
            failures.append("backup authentication failed")
        expected_names = {MANIFEST}
        for row in manifest.get("files", []):
            name = str(row.get("path", ""))
            candidate = Path(name)
            if not name or candidate.is_absolute() or ".." in candidate.parts:
                failures.append(f"unsafe path: {name}")
                continue
            expected_names.add(name)
            try:
                data = archive.read(name)
            except KeyError:
                failures.append(f"missing: {name}")
                continue
            if len(data) != int(row.get("size", -1)) \
                    or _sha256(data) != row.get("sha256"):
                failures.append(f"hash mismatch: {name}")
        extras = set(archive.namelist()) - expected_names
        failures.extend(f"unexpected: {name}" for name in sorted(extras))
    return {"valid": not failures, "failures": failures,
            "files": len(manifest.get("files", []))}


def restore(archive_path: str, target_dir: str, key: str) -> Dict[str, Any]:
    checked = verify(archive_path, key)
    if not checked["valid"]:
        raise ValueError("backup verification failed: " + "; ".join(checked["failures"]))
    target = Path(target_dir).resolve()
    if target.exists() and any(target.iterdir()):
        raise FileExistsError("restore target must be absent or empty")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".easyshark-restore-",
                                    dir=target.parent))
    try:
        with zipfile.ZipFile(Path(archive_path).resolve(), "r") as archive:
            manifest = json.loads(archive.read(MANIFEST))
            for row in manifest["files"]:
                destination = staging / row["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(row["path"]))
        if target.exists():
            target.rmdir()
        staging.replace(target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {"target": str(target), "files": checked["files"]}


def retention_candidates(state_dir: str, days: int) -> List[str]:
    if days < 1:
        raise ValueError("retention must be at least one day")
    root = Path(state_dir).resolve()
    cutoff = time.time() - days * 86400
    candidates = []
    for dirname in ("sessions", "reports"):
        directory = root / dirname
        if directory.is_dir():
            candidates.extend(str(path) for path in directory.iterdir()
                              if path.is_file() and path.stat().st_mtime < cutoff)
    return sorted(candidates)


def prune(state_dir: str, days: int, *, apply: bool = False) -> Dict[str, Any]:
    candidates = retention_candidates(state_dir, days)
    if apply:
        for name in candidates:
            Path(name).unlink()
    return {"applied": apply, "files": candidates, "count": len(candidates)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Manage verified EasyShark state archives")
    commands = parser.add_subparsers(dest="command", required=True)
    create_cmd = commands.add_parser("create")
    create_cmd.add_argument("state_dir")
    create_cmd.add_argument("archive")
    verify_cmd = commands.add_parser("verify")
    verify_cmd.add_argument("archive")
    restore_cmd = commands.add_parser("restore")
    restore_cmd.add_argument("archive")
    restore_cmd.add_argument("target_dir")
    prune_cmd = commands.add_parser("prune")
    prune_cmd.add_argument("state_dir")
    prune_cmd.add_argument("--days", type=int, required=True)
    prune_cmd.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    key = os.environ.get("EASYSHARK_BACKUP_HMAC_KEY", "")
    if args.command == "create":
        result = create(args.state_dir, args.archive, key)
    elif args.command == "verify":
        result = verify(args.archive, key)
    elif args.command == "restore":
        result = restore(args.archive, args.target_dir, key)
    else:
        result = prune(args.state_dir, args.days, apply=args.apply)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("valid", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
