"""SQLite storage backend for local/Docker/dev mode."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from codeguard.storage.backend import (
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
    last_scanned TEXT,
    PRIMARY KEY (project_id, path)
);

CREATE TABLE IF NOT EXISTS functions (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    is_method INTEGER DEFAULT 0,
    class_name TEXT,
    start_line INTEGER DEFAULT 0,
    end_line INTEGER DEFAULT 0,
    PRIMARY KEY (id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_qualified ON functions(qualified_name);
CREATE INDEX IF NOT EXISTS idx_functions_project ON functions(project_id);

CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    caller_id TEXT NOT NULL,
    callee_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_id);
CREATE INDEX IF NOT EXISTS idx_calls_project ON calls(project_id);

CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    call_site_file TEXT,
    call_site_line INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_edges_project ON graph_edges(project_id);
CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target);

CREATE TABLE IF NOT EXISTS indexes (
    project_id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
"""


class SQLiteBackend(StorageBackend):
    """SQLite-based persistent storage backend."""

    def __init__(self, db_path: str | Path = ".codeguard.db") -> None:
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
        return self._conn

    def store_graph(self, project_id: str, graph_data: GraphData) -> None:
        conn = self._get_conn()
        # Clear existing data for this project
        conn.execute("DELETE FROM functions WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM calls WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM graph_edges WHERE project_id = ?", (project_id,))

        # Store functions
        for func in graph_data.functions:
            conn.execute(
                "INSERT INTO functions (id, project_id, file_path, name, qualified_name, "
                "is_method, class_name, start_line, end_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    func.id,
                    project_id,
                    func.file_path,
                    func.name,
                    func.qualified_name,
                    int(func.is_method),
                    func.class_name,
                    func.start_line,
                    func.end_line,
                ),
            )

        # Store calls
        for call in graph_data.calls:
            conn.execute(
                "INSERT INTO calls (project_id, caller_id, callee_id, file_path, line) "
                "VALUES (?, ?, ?, ?, ?)",
                (project_id, call.caller_id, call.callee_id, call.file_path, call.line),
            )

        # Store edges
        for edge in graph_data.edges:
            conn.execute(
                "INSERT INTO graph_edges (project_id, source, target, call_site_file, "
                "call_site_line) VALUES (?, ?, ?, ?, ?)",
                (
                    project_id,
                    edge["source"],
                    edge["target"],
                    edge.get("file_path", ""),
                    edge.get("line", 0),
                ),
            )

        conn.commit()
        logger.info(
            "Stored graph for %s: %d functions, %d calls, %d edges",
            project_id,
            len(graph_data.functions),
            len(graph_data.calls),
            len(graph_data.edges),
        )

    def load_graph(self, project_id: str) -> GraphData | None:
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row

        # Load functions
        rows = conn.execute(
            "SELECT * FROM functions WHERE project_id = ?", (project_id,)
        ).fetchall()
        if not rows:
            conn.row_factory = None
            return None

        functions = [
            FunctionRecord(
                id=r["id"],
                file_path=r["file_path"],
                name=r["name"],
                qualified_name=r["qualified_name"],
                is_method=bool(r["is_method"]),
                class_name=r["class_name"],
                start_line=r["start_line"],
                end_line=r["end_line"],
            )
            for r in rows
        ]

        # Load calls
        rows = conn.execute("SELECT * FROM calls WHERE project_id = ?", (project_id,)).fetchall()
        calls = [
            CallRecord(
                caller_id=r["caller_id"],
                callee_id=r["callee_id"],
                file_path=r["file_path"],
                line=r["line"],
            )
            for r in rows
        ]

        # Load edges
        rows = conn.execute(
            "SELECT * FROM graph_edges WHERE project_id = ?", (project_id,)
        ).fetchall()
        edges = [
            {
                "source": r["source"],
                "target": r["target"],
                "file_path": r["call_site_file"],
                "line": r["call_site_line"],
            }
            for r in rows
        ]

        conn.row_factory = None
        return GraphData(functions=functions, calls=calls, edges=edges)

    def store_file_hash(self, project_id: str, file_path: str, file_hash: str) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO files (project_id, path, hash) VALUES (?, ?, ?)",
            (project_id, file_path, file_hash),
        )
        conn.commit()

    def load_file_hashes(self, project_id: str) -> dict[str, str]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT path, hash FROM files WHERE project_id = ?", (project_id,)
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def store_index(self, project_id: str, index_data: dict[str, Any]) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO indexes (project_id, data) VALUES (?, ?)",
            (project_id, json.dumps(index_data)),
        )
        conn.commit()

    def load_index(self, project_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT data FROM indexes WHERE project_id = ?", (project_id,)
        ).fetchone()
        if row:
            loaded: Any = json.loads(row[0])
            return loaded if isinstance(loaded, dict) else None
        return None

    def clear(self, project_id: str) -> None:
        conn = self._get_conn()
        for table in ("files", "functions", "calls", "graph_edges", "indexes"):
            conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
        conn.commit()

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
