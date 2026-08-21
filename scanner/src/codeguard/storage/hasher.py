"""File hashing utilities for incremental builds."""

from __future__ import annotations

import hashlib
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path


def compute_file_hash(path: Path) -> str:
    """Compute SHA256 hash of a file's content."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_worker(path_str: str) -> tuple[str, str]:
    """Worker function for parallel hashing (must be top-level for pickling)."""
    path = Path(path_str)
    return str(path), compute_file_hash(path)


def compute_hashes(paths: list[Path], max_workers: int | None = None) -> dict[str, str]:
    """Compute SHA256 hashes for multiple files in parallel."""
    if len(paths) <= 3:
        return {str(p): compute_file_hash(p) for p in paths}

    try:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(_hash_worker, [str(p) for p in paths])
            return dict(results)
    except (OSError, PermissionError):
        # Some hardened containers disallow process semaphores/sysconf calls.
        return {str(path): compute_file_hash(path) for path in paths}
