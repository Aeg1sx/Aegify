"""Persistent storage backends for call graph and scan data."""

from codeguard.storage.backend import (
    InMemoryBackend,
    StorageBackend,
)

__all__ = [
    "StorageBackend",
    "InMemoryBackend",
]
