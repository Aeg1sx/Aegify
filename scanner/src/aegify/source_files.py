"""Bounded reads of regular source files from a canonical repository root."""

import hashlib
import os
import stat
from pathlib import Path

from aegify.models import FileAST


def read_regular_source(root: Path, relative: Path, limit: int) -> bytes:
    """Reject links at every component and special files, including blocking FIFOs."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise NotImplementedError("safe source capture requires descriptor-relative opens")
    if (
        not root.is_absolute()
        or not relative.parts
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        raise ValueError("invalid_source_path")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    absolute = root / relative
    directory = os.open(absolute.anchor, flags | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(absolute.name, flags, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError("source_type_or_size_limit")
            raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise ValueError("source_type_or_size_limit")
            return raw
    finally:
        os.close(directory)


def read_scanned_source(file: FileAST, limit: int) -> bytes | None:
    relative = Path(file.module_path)
    path = Path(file.file_path).absolute()
    if (
        not file.source_digest
        or not relative.parts
        or relative.is_absolute()
        or ".." in relative.parts
        or path.parts[-len(relative.parts) :] != relative.parts
    ):
        return None
    try:
        root = path.parents[len(relative.parts) - 1].resolve()
        source = read_regular_source(root, relative, limit)
        if hashlib.sha256(source).hexdigest() == file.source_digest:
            return source
    except OSError, ValueError, NotImplementedError:
        pass
    return None
