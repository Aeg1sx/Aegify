"""S3 storage backend for archival/CI mode."""

from __future__ import annotations

import json
import logging
from typing import Any

from aegify.storage.backend import (
    CallRecord,
    FunctionRecord,
    GraphData,
    StorageBackend,
)

logger = logging.getLogger(__name__)


class S3Backend(StorageBackend):
    """S3-based storage backend for archival and CI pipelines.

    Requires boto3 to be installed:
        pip install aegify-sast[storage-s3]
    """

    def __init__(self, bucket: str, prefix: str = "aegify") -> None:
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "boto3 is required for S3 backend. "
                "Install with: pip install aegify-sast[storage-s3]"
            ) from e
        self._s3 = boto3.client("s3")
        self._bucket = bucket
        self._prefix = prefix

    def _key(self, project_id: str, name: str) -> str:
        return f"{self._prefix}/{project_id}/{name}.json"

    def _put(self, key: str, data: Any) -> None:
        self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=json.dumps(data).encode("utf-8"),
            ContentType="application/json",
        )

    def _get(self, key: str) -> Any | None:
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=key)
            return json.loads(resp["Body"].read().decode("utf-8"))
        except self._s3.exceptions.NoSuchKey:
            return None
        except Exception:
            logger.debug("S3 key not found: %s", key)
            return None

    def store_graph(self, project_id: str, graph_data: GraphData) -> None:
        data = {
            "functions": [
                {
                    "id": f.id,
                    "file_path": f.file_path,
                    "name": f.name,
                    "qualified_name": f.qualified_name,
                    "is_method": f.is_method,
                    "class_name": f.class_name,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                }
                for f in graph_data.functions
            ],
            "calls": [
                {
                    "caller_id": c.caller_id,
                    "callee_id": c.callee_id,
                    "file_path": c.file_path,
                    "line": c.line,
                }
                for c in graph_data.calls
            ],
            "edges": graph_data.edges,
        }
        self._put(self._key(project_id, "graph"), data)

    def load_graph(self, project_id: str) -> GraphData | None:
        data = self._get(self._key(project_id, "graph"))
        if not data:
            return None

        functions = [
            FunctionRecord(
                id=f["id"],
                file_path=f["file_path"],
                name=f["name"],
                qualified_name=f["qualified_name"],
                is_method=f.get("is_method", False),
                class_name=f.get("class_name"),
                start_line=f.get("start_line", 0),
                end_line=f.get("end_line", 0),
            )
            for f in data.get("functions", [])
        ]
        calls = [
            CallRecord(
                caller_id=c["caller_id"],
                callee_id=c["callee_id"],
                file_path=c["file_path"],
                line=c["line"],
            )
            for c in data.get("calls", [])
        ]
        return GraphData(functions=functions, calls=calls, edges=data.get("edges", []))

    def store_file_hash(self, project_id: str, file_path: str, file_hash: str) -> None:
        hashes = self.load_file_hashes(project_id)
        hashes[file_path] = file_hash
        self._put(self._key(project_id, "hashes"), hashes)

    def load_file_hashes(self, project_id: str) -> dict[str, str]:
        data = self._get(self._key(project_id, "hashes"))
        return data if isinstance(data, dict) else {}

    def store_index(self, project_id: str, index_data: dict[str, Any]) -> None:
        self._put(self._key(project_id, "index"), index_data)

    def load_index(self, project_id: str) -> dict[str, Any] | None:
        return self._get(self._key(project_id, "index"))

    def clear(self, project_id: str) -> None:
        for name in ("graph", "hashes", "index"):
            try:
                self._s3.delete_object(Bucket=self._bucket, Key=self._key(project_id, name))
            except Exception:
                pass
