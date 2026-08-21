"""Storage backend abstraction and in-memory implementation."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FunctionRecord:
    """Stored function definition record."""

    id: str
    file_path: str
    name: str
    qualified_name: str
    is_method: bool = False
    class_name: str | None = None
    start_line: int = 0
    end_line: int = 0


@dataclass
class CallRecord:
    """Stored call edge record."""

    caller_id: str
    callee_id: str
    file_path: str
    line: int


@dataclass
class GraphData:
    """Serializable call graph data."""

    functions: list[FunctionRecord] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)


class StorageBackend(ABC):
    """Abstract storage backend for call graph and scan index data."""

    @abstractmethod
    def store_graph(self, project_id: str, graph_data: GraphData) -> None:
        """Store call graph data."""
        ...

    @abstractmethod
    def load_graph(self, project_id: str) -> GraphData | None:
        """Load call graph data. Returns None if not found."""
        ...

    @abstractmethod
    def store_file_hash(self, project_id: str, file_path: str, file_hash: str) -> None:
        """Store a file's content hash."""
        ...

    @abstractmethod
    def load_file_hashes(self, project_id: str) -> dict[str, str]:
        """Load all stored file hashes for a project. Returns {path: hash}."""
        ...

    @abstractmethod
    def store_index(self, project_id: str, index_data: dict[str, Any]) -> None:
        """Store suffix index data."""
        ...

    @abstractmethod
    def load_index(self, project_id: str) -> dict[str, Any] | None:
        """Load suffix index data."""
        ...

    @abstractmethod
    def clear(self, project_id: str) -> None:
        """Clear all stored data for a project."""
        ...


class InMemoryBackend(StorageBackend):
    """In-memory storage backend (default, non-persistent)."""

    def __init__(self) -> None:
        self._graphs: dict[str, GraphData] = {}
        self._file_hashes: dict[str, dict[str, str]] = {}
        self._indexes: dict[str, dict[str, Any]] = {}

    def store_graph(self, project_id: str, graph_data: GraphData) -> None:
        self._graphs[project_id] = graph_data

    def load_graph(self, project_id: str) -> GraphData | None:
        return self._graphs.get(project_id)

    def store_file_hash(self, project_id: str, file_path: str, file_hash: str) -> None:
        if project_id not in self._file_hashes:
            self._file_hashes[project_id] = {}
        self._file_hashes[project_id][file_path] = file_hash

    def load_file_hashes(self, project_id: str) -> dict[str, str]:
        return dict(self._file_hashes.get(project_id, {}))

    def store_index(self, project_id: str, index_data: dict[str, Any]) -> None:
        self._indexes[project_id] = index_data

    def load_index(self, project_id: str) -> dict[str, Any] | None:
        return self._indexes.get(project_id)

    def clear(self, project_id: str) -> None:
        self._graphs.pop(project_id, None)
        self._file_hashes.pop(project_id, None)
        self._indexes.pop(project_id, None)
