"""PostgreSQL storage backend for remote/team mode."""

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

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    project_id TEXT NOT NULL,
    path TEXT NOT NULL,
    hash TEXT NOT NULL,
    last_scanned TIMESTAMPTZ,
    PRIMARY KEY (project_id, path)
);

CREATE TABLE IF NOT EXISTS functions (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    is_method BOOLEAN DEFAULT FALSE,
    class_name TEXT,
    start_line INTEGER DEFAULT 0,
    end_line INTEGER DEFAULT 0,
    PRIMARY KEY (id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_pg_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_pg_functions_qualified ON functions(qualified_name);

CREATE TABLE IF NOT EXISTS calls (
    id SERIAL PRIMARY KEY,
    project_id TEXT NOT NULL,
    caller_id TEXT NOT NULL,
    callee_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pg_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS idx_pg_calls_callee ON calls(callee_id);

CREATE TABLE IF NOT EXISTS graph_edges (
    id SERIAL PRIMARY KEY,
    project_id TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    call_site_file TEXT,
    call_site_line INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pg_edges_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS idx_pg_edges_target ON graph_edges(target);

CREATE TABLE IF NOT EXISTS indexes (
    project_id TEXT PRIMARY KEY,
    data JSONB NOT NULL
);
"""


class PostgreSQLBackend(StorageBackend):
    """PostgreSQL-based persistent storage backend for team/remote mode.

    Requires psycopg[binary] to be installed:
        pip install aegify-sast[storage-pg]
    """

    def __init__(self, db_url: str) -> None:
        try:
            import psycopg
        except ImportError as e:
            raise ImportError(
                "psycopg is required for PostgreSQL backend. "
                "Install with: pip install aegify-sast[storage-pg]"
            ) from e
        self._conn = psycopg.connect(db_url, autocommit=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)
        self._conn.commit()

    def store_graph(self, project_id: str, graph_data: GraphData) -> None:
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM functions WHERE project_id = %s", (project_id,))
            cur.execute("DELETE FROM calls WHERE project_id = %s", (project_id,))
            cur.execute("DELETE FROM graph_edges WHERE project_id = %s", (project_id,))

            for func in graph_data.functions:
                cur.execute(
                    "INSERT INTO functions (id, project_id, file_path, name, qualified_name, "
                    "is_method, class_name, start_line, end_line) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        func.id,
                        project_id,
                        func.file_path,
                        func.name,
                        func.qualified_name,
                        func.is_method,
                        func.class_name,
                        func.start_line,
                        func.end_line,
                    ),
                )

            for call in graph_data.calls:
                cur.execute(
                    "INSERT INTO calls (project_id, caller_id, callee_id, file_path, line) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (project_id, call.caller_id, call.callee_id, call.file_path, call.line),
                )

            for edge in graph_data.edges:
                cur.execute(
                    "INSERT INTO graph_edges (project_id, source, target, call_site_file, "
                    "call_site_line) VALUES (%s, %s, %s, %s, %s)",
                    (
                        project_id,
                        edge["source"],
                        edge["target"],
                        edge.get("file_path", ""),
                        edge.get("line", 0),
                    ),
                )

        self._conn.commit()

    def load_graph(self, project_id: str) -> GraphData | None:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, file_path, name, qualified_name, is_method, class_name, "
                "start_line, end_line FROM functions WHERE project_id = %s",
                (project_id,),
            )
            func_rows = cur.fetchall()
            if not func_rows:
                return None

            functions = [
                FunctionRecord(
                    id=r[0],
                    file_path=r[1],
                    name=r[2],
                    qualified_name=r[3],
                    is_method=bool(r[4]),
                    class_name=r[5],
                    start_line=r[6],
                    end_line=r[7],
                )
                for r in func_rows
            ]

            cur.execute(
                "SELECT caller_id, callee_id, file_path, line FROM calls WHERE project_id = %s",
                (project_id,),
            )
            calls = [
                CallRecord(caller_id=r[0], callee_id=r[1], file_path=r[2], line=r[3])
                for r in cur.fetchall()
            ]

            cur.execute(
                "SELECT source, target, call_site_file, call_site_line "
                "FROM graph_edges WHERE project_id = %s",
                (project_id,),
            )
            edges = [
                {"source": r[0], "target": r[1], "file_path": r[2], "line": r[3]}
                for r in cur.fetchall()
            ]

        return GraphData(functions=functions, calls=calls, edges=edges)

    def store_file_hash(self, project_id: str, file_path: str, file_hash: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO files (project_id, path, hash) VALUES (%s, %s, %s) "
                "ON CONFLICT (project_id, path) DO UPDATE SET hash = EXCLUDED.hash",
                (project_id, file_path, file_hash),
            )
        self._conn.commit()

    def load_file_hashes(self, project_id: str) -> dict[str, str]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT path, hash FROM files WHERE project_id = %s", (project_id,))
            return {r[0]: r[1] for r in cur.fetchall()}

    def store_index(self, project_id: str, index_data: dict[str, Any]) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO indexes (project_id, data) VALUES (%s, %s) "
                "ON CONFLICT (project_id) DO UPDATE SET data = EXCLUDED.data",
                (project_id, json.dumps(index_data)),
            )
        self._conn.commit()

    def load_index(self, project_id: str) -> dict[str, Any] | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT data FROM indexes WHERE project_id = %s", (project_id,))
            row = cur.fetchone()
            if row:
                return row[0] if isinstance(row[0], dict) else json.loads(row[0])
        return None

    def clear(self, project_id: str) -> None:
        with self._conn.cursor() as cur:
            for table in ("files", "functions", "calls", "graph_edges", "indexes"):
                cur.execute(f"DELETE FROM {table} WHERE project_id = %s", (project_id,))
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
