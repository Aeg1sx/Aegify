"""Tests for storage backends."""

import tempfile
from pathlib import Path

import pytest

from codeguard.storage.backend import (
    CallRecord,
    FunctionRecord,
    GraphData,
    InMemoryBackend,
)
from codeguard.storage.sqlite import SQLiteBackend


class TestInMemoryBackend:
    @pytest.fixture
    def backend(self):
        return InMemoryBackend()

    def test_store_and_load_graph(self, backend):
        graph_data = GraphData(
            functions=[
                FunctionRecord(
                    id="f1",
                    file_path="app.py",
                    name="handler",
                    qualified_name="app.handler",
                    start_line=1,
                    end_line=10,
                )
            ],
            calls=[CallRecord(caller_id="f1", callee_id="f2", file_path="app.py", line=5)],
            edges=[{"source": "app.handler", "target": "db.query", "line": 5}],
        )

        backend.store_graph("project1", graph_data)
        loaded = backend.load_graph("project1")

        assert loaded is not None
        assert len(loaded.functions) == 1
        assert loaded.functions[0].qualified_name == "app.handler"
        assert len(loaded.calls) == 1
        assert len(loaded.edges) == 1

    def test_load_graph_not_found(self, backend):
        assert backend.load_graph("nonexistent") is None

    def test_store_and_load_file_hashes(self, backend):
        backend.store_file_hash("p1", "file1.py", "abc123")
        backend.store_file_hash("p1", "file2.py", "def456")

        hashes = backend.load_file_hashes("p1")
        assert hashes == {"file1.py": "abc123", "file2.py": "def456"}

    def test_load_hashes_empty(self, backend):
        assert backend.load_file_hashes("nonexistent") == {}

    def test_store_and_load_index(self, backend):
        index = {"method_a": ["module.Class.method_a"]}
        backend.store_index("p1", index)

        loaded = backend.load_index("p1")
        assert loaded == index

    def test_load_index_not_found(self, backend):
        assert backend.load_index("nonexistent") is None

    def test_clear(self, backend):
        backend.store_graph("p1", GraphData())
        backend.store_file_hash("p1", "f.py", "hash")
        backend.store_index("p1", {"key": "val"})

        backend.clear("p1")

        assert backend.load_graph("p1") is None
        assert backend.load_file_hashes("p1") == {}
        assert backend.load_index("p1") is None

    def test_clear_does_not_affect_other_projects(self, backend):
        backend.store_file_hash("p1", "f.py", "hash1")
        backend.store_file_hash("p2", "f.py", "hash2")

        backend.clear("p1")

        assert backend.load_file_hashes("p1") == {}
        assert backend.load_file_hashes("p2") == {"f.py": "hash2"}


class TestSQLiteBackend:
    @pytest.fixture
    def backend(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        b = SQLiteBackend(db_path)
        yield b
        b.close()
        Path(db_path).unlink(missing_ok=True)

    def test_store_and_load_graph(self, backend):
        graph_data = GraphData(
            functions=[
                FunctionRecord(
                    id="f1",
                    file_path="app.py",
                    name="handler",
                    qualified_name="app.handler",
                    start_line=1,
                    end_line=10,
                ),
                FunctionRecord(
                    id="f2",
                    file_path="db.py",
                    name="query",
                    qualified_name="db.query",
                    is_method=True,
                    class_name="DB",
                    start_line=5,
                    end_line=20,
                ),
            ],
            calls=[CallRecord(caller_id="f1", callee_id="f2", file_path="app.py", line=5)],
            edges=[
                {"source": "app.handler", "target": "db.query", "file_path": "app.py", "line": 5}
            ],
        )

        backend.store_graph("project1", graph_data)
        loaded = backend.load_graph("project1")

        assert loaded is not None
        assert len(loaded.functions) == 2
        assert loaded.functions[0].qualified_name == "app.handler"
        assert loaded.functions[1].is_method is True
        assert loaded.functions[1].class_name == "DB"
        assert len(loaded.calls) == 1
        assert loaded.calls[0].caller_id == "f1"
        assert len(loaded.edges) == 1

    def test_load_graph_not_found(self, backend):
        assert backend.load_graph("nonexistent") is None

    def test_store_and_load_file_hashes(self, backend):
        backend.store_file_hash("p1", "file1.py", "abc123")
        backend.store_file_hash("p1", "file2.py", "def456")

        hashes = backend.load_file_hashes("p1")
        assert hashes == {"file1.py": "abc123", "file2.py": "def456"}

    def test_file_hash_update(self, backend):
        backend.store_file_hash("p1", "file1.py", "old_hash")
        backend.store_file_hash("p1", "file1.py", "new_hash")

        hashes = backend.load_file_hashes("p1")
        assert hashes["file1.py"] == "new_hash"

    def test_store_and_load_index(self, backend):
        index = {"method_a": ["module.Class.method_a"], "count": 42}
        backend.store_index("p1", index)

        loaded = backend.load_index("p1")
        assert loaded == index

    def test_clear(self, backend):
        backend.store_graph(
            "p1",
            GraphData(
                functions=[
                    FunctionRecord(id="f1", file_path="a.py", name="f", qualified_name="a.f")
                ]
            ),
        )
        backend.store_file_hash("p1", "a.py", "h")
        backend.store_index("p1", {"k": "v"})

        backend.clear("p1")

        assert backend.load_graph("p1") is None
        assert backend.load_file_hashes("p1") == {}
        assert backend.load_index("p1") is None

    def test_graph_overwrite(self, backend):
        """Storing a new graph replaces the old one."""
        graph1 = GraphData(
            functions=[FunctionRecord(id="f1", file_path="a.py", name="a", qualified_name="a")]
        )
        graph2 = GraphData(
            functions=[
                FunctionRecord(id="f2", file_path="b.py", name="b", qualified_name="b"),
                FunctionRecord(id="f3", file_path="c.py", name="c", qualified_name="c"),
            ]
        )

        backend.store_graph("p1", graph1)
        backend.store_graph("p1", graph2)

        loaded = backend.load_graph("p1")
        assert loaded is not None
        assert len(loaded.functions) == 2
        assert loaded.functions[0].name == "b"
