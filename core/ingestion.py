"""Small flow-log ingestion boundary with optional cloud backends."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def read_json_lines(source: str | Path) -> Iterable[dict[str, Any]]:
    with Path(source).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    yield value


def read_cloud(uri: str) -> list[dict[str, Any]]:
    """Read JSONL from s3:// or gs:// using an installed SDK only."""
    if uri.startswith("s3://"):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("s3 ingestion requires boto3") from exc
        bucket, _, key = uri[5:].partition("/")
        body = boto3.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    elif uri.startswith("gs://"):
        try:
            from google.cloud import storage
        except ImportError as exc:
            raise RuntimeError("gcs ingestion requires google-cloud-storage") from exc
        bucket, _, key = uri[5:].partition("/")
        body = storage.Client().bucket(bucket).blob(key).download_as_text()
    else:
        return list(read_json_lines(uri))
    return [json.loads(line) for line in body.splitlines() if line.strip()]
