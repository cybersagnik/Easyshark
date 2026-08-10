"""Controlled artifact inspection with traversal and resource limits."""
from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, List


def describe(path: str, max_bytes: int = 50 * 1024 * 1024) -> Dict[str, Any]:
    p = Path(path).resolve()
    if not p.is_file():
        raise FileNotFoundError(str(path))
    if p.stat().st_size > max_bytes:
        raise ValueError("artifact exceeds size limit")
    digest = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(p), "name": p.name, "size": p.stat().st_size,
            "sha256": digest.hexdigest(), "suffix": p.suffix.lower()}


def safe_zip_listing(path: str, max_members: int = 1000,
                     max_uncompressed: int = 100 * 1024 * 1024) -> List[Dict[str, Any]]:
    """List ZIP members without extracting or trusting archive paths."""
    p = Path(path).resolve()
    total = 0
    rows: List[Dict[str, Any]] = []
    with zipfile.ZipFile(p) as archive:
        infos = archive.infolist()
        if len(infos) > max_members:
            raise ValueError("archive contains too many members")
        for info in infos:
            member = Path(info.filename)
            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"unsafe archive member: {info.filename}")
            total += info.file_size
            if total > max_uncompressed:
                raise ValueError("archive exceeds uncompressed size limit")
            rows.append({"name": info.filename, "size": info.file_size,
                         "compressed": info.compress_size})
    return rows
