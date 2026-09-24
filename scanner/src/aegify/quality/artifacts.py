"""Bounded local evaluation artifacts; no imports or network requests."""

from __future__ import annotations

import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any


def read_regular_file(path: Path, *, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"artifact must be a regular file of at most {limit} bytes")
    with path.open("rb") as stream:
        material = stream.read(limit + 1)
    if len(material) > limit:
        raise ValueError("artifact grew beyond its byte limit")
    return material


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def parse_json_object(material: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            material,
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
            parse_float=_finite_float,
        )
    except RecursionError as error:
        raise ValueError("artifact JSON nesting exceeds the supported depth") from error
    if not isinstance(value, dict):
        raise ValueError("artifact must contain one JSON object")
    return value


def write_report(path: Path, rendered: str) -> None:
    """Publish a complete artifact atomically without following destination links."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".aegify-evaluation-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(rendered + "\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
