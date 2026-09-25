"""Immutable, bounded source evidence admitted by the scanner, never by the model."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from aegify.models import FileAST, Finding, ScanResult

MAX_SOURCE_FILES = 2_000
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_READ_LINES = 200
MAX_READ_BYTES = 16_384
MAX_SEARCH_FILES = 200
MAX_SEARCH_BYTES = 4 * 1024 * 1024
MAX_SEARCH_MATCHES = 20
_SHA256 = re.compile(r"[a-f0-9]{64}")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
)


@dataclass(frozen=True)
class SourceSymbol:
    name: str
    qualified_name: str
    symbol_id: str
    line_start: int
    line_end: int


@dataclass(frozen=True)
class SourceFile:
    repository_id: str
    path: str
    scan_path: str
    source_digest: str
    language: str
    lines: tuple[str, ...]
    symbols: tuple[SourceSymbol, ...]
    byte_count: int
    symbols_truncated: bool = False
    symbols_available: bool = True

    def metadata(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "path": self.path,
            "source_digest": self.source_digest,
            "language": self.language,
            "line_count": len(self.lines),
        }


@dataclass(frozen=True)
class SourceCatalog:
    """Only scanner-admitted UTF-8 source is retained; all tool reads are in memory."""

    files: Mapping[tuple[str, str], SourceFile]
    gap_counts: Mapping[str, int]
    manifest_digest: str

    def bind_scan(self, scan: ScanResult) -> SourceCatalog:
        """Check programmatic callers too; a catalog for a different scan is not evidence."""
        identities = Counter(
            (source.repository_id or "local", source.module_path)
            for source in scan.analyzed_sources
        )
        expected = {
            (source.repository_id or "local", source.module_path): source
            for source in scan.analyzed_sources
            if identities[(source.repository_id or "local", source.module_path)] == 1
        }
        entries = {}
        gaps = Counter(self.gap_counts)
        for identity, entry in self.files.items():
            source = expected.get(identity)
            if (
                source is None
                or source.language is None
                or entry.source_digest != "sha256:" + source.source_digest
                or entry.language != source.language.value
            ):
                gaps["source_scan_binding_mismatch"] += 1
            else:
                entries[identity] = replace(entry, scan_path=source.file_path)
        missing = len(set(identities) - set(entries))
        if missing:
            gaps["source_manifest_files_unavailable"] = missing
        if not expected:
            gaps["source_manifest_unavailable"] = 1
        digest = _digest(
            json.dumps(
                {"files": [entry.metadata() for entry in entries.values()], "gaps": gaps},
                sort_keys=True,
            )
        )
        return SourceCatalog(MappingProxyType(entries), MappingProxyType(dict(gaps)), digest)

    @classmethod
    def from_scan(cls, scan: ScanResult, roots: Mapping[str, Path]) -> SourceCatalog:
        """Reopen only digest-bound parsed files, including relocated CI checkouts.

        The scan artifact is trusted input. Its historical absolute paths never
        select filesystem reads. Symbol declarations were not saved in that
        artifact, so symbol queries report unavailable instead of an empty index.
        """
        identities = Counter(
            (source.repository_id or "local", source.module_path)
            for source in scan.analyzed_sources
        )
        gaps: Counter[str] = Counter()
        asts: list[FileAST] = []
        original_paths: dict[tuple[str, str], str] = {}
        for source in scan.analyzed_sources:
            repository = source.repository_id or "local"
            identity = (repository, source.module_path)
            root = roots.get(repository)
            if identities[identity] != 1:
                gaps["duplicate_source_identity"] += 1
            elif (
                root is None
                or source.language is None
                or not _SHA256.fullmatch(source.source_digest)
            ):
                gaps["unbound_source"] += 1
            elif not _valid_path(source.module_path):
                gaps["source_path_not_admitted"] += 1
            else:
                asts.append(
                    FileAST(
                        file_path=str(root.absolute() / source.module_path),
                        language=source.language,
                        repository_id=repository,
                        module_path=source.module_path,
                        source_digest=source.source_digest,
                    )
                )
                original_paths[identity] = source.file_path
        if not scan.analyzed_sources:
            gaps["source_manifest_unavailable"] += 1
        captured = cls.capture(asts, roots)
        gaps.update(captured.gap_counts)
        entries = {
            identity: replace(entry, scan_path=original_paths[identity], symbols_available=False)
            for identity, entry in captured.files.items()
        }
        digest = _digest(
            json.dumps(
                {"files": [entry.metadata() for entry in entries.values()], "gaps": gaps},
                sort_keys=True,
            )
        )
        return cls(MappingProxyType(entries), MappingProxyType(dict(gaps)), digest)

    @classmethod
    def capture(cls, asts: Sequence[FileAST], roots: Mapping[str, Path]) -> SourceCatalog:
        from aegify.scanner.ast_parser import detect_language

        entries: dict[tuple[str, str], SourceFile] = {}
        gaps: Counter[str] = Counter()
        remaining = MAX_TOTAL_BYTES
        for ast in sorted(asts, key=lambda item: (item.repository_id, item.file_path)):
            if len(entries) >= MAX_SOURCE_FILES or remaining <= 0:
                gaps["source_catalog_limit"] += 1
                continue
            repository_id = ast.repository_id or "local"
            root = roots.get(repository_id)
            if root is None or len(repository_id) > 256 or not _SHA256.fullmatch(ast.source_digest):
                gaps["unbound_source"] += 1
                continue
            try:
                # Keep lexical components until the descriptor-based open, so a
                # symlink inside the selected root cannot become an admitted path.
                relative = Path(ast.file_path).absolute().relative_to(root.absolute())
            except ValueError:
                gaps["source_outside_root"] += 1
                continue
            try:
                path = relative.as_posix()
                if not _valid_path(path) or detect_language(relative) != ast.language:
                    raise ValueError("source_path_not_admitted")
                if (repository_id, path) in entries:
                    raise ValueError("duplicate_source_identity")
                raw = _read_regular_source(root.resolve(), relative, min(MAX_FILE_BYTES, remaining))
                if hashlib.sha256(raw).hexdigest() != ast.source_digest:
                    raise ValueError("source_changed_after_parse")
                text = raw.decode("utf-8")
                if "\x00" in text:
                    raise ValueError("binary_source")
                lines = _redacted_lines(text)
            except UnicodeError:
                gaps["invalid_source_encoding"] += 1
                continue
            except ValueError as error:
                gaps[str(error)] += 1
                continue
            except OSError, NotImplementedError:
                gaps["source_unavailable_or_linked"] += 1
                continue
            functions = sorted(ast.functions, key=lambda item: (item.line_start, item.name))
            symbols = tuple(
                SourceSymbol(
                    name=function.name[:256],
                    qualified_name=function.qualified_name[:512],
                    symbol_id=function.symbol_id[:1_024],
                    line_start=function.line_start,
                    line_end=function.line_end,
                )
                for function in functions[:200]
                if 1 <= function.line_start <= function.line_end <= len(lines)
            )
            entries[(repository_id, path)] = SourceFile(
                repository_id=repository_id,
                path=path,
                scan_path=ast.file_path,
                source_digest="sha256:" + ast.source_digest,
                language=ast.language.value,
                lines=lines,
                symbols=symbols,
                byte_count=len(raw),
                symbols_truncated=len(functions) > 200,
            )
            remaining -= len(raw)
        material = [entry.metadata() for entry in entries.values()]
        digest = _digest(json.dumps({"files": material, "gaps": gaps}, sort_keys=True))
        return cls(MappingProxyType(entries), MappingProxyType(dict(gaps)), digest)

    def summary(self) -> dict[str, Any]:
        return {
            "manifest_digest": self.manifest_digest,
            "repositories": sorted({key[0] for key in self.files}),
            "admitted_files": len(self.files),
            "gap_counts": dict(self.gap_counts),
            "scope": "scanner-admitted source snapshot; excluded/unparsed files are unavailable",
        }

    def valid_citation(self, value: Mapping[str, Any]) -> bool:
        repository = value.get("repository_id")
        path = value.get("path")
        if not isinstance(repository, str) or not isinstance(path, str):
            return False
        entry = self.files.get((repository, path))
        start, end = value.get("line_start"), value.get("line_end")
        if (
            entry is None
            or type(start) is not int
            or type(end) is not int
            or not 1 <= start <= end <= len(entry.lines)
            or end - start >= MAX_READ_LINES
        ):
            return False
        expected = _citation(entry, start, end, "\n".join(entry.lines[start - 1 : end]))
        return dict(value) == expected

    def finding_location(self, finding: Finding) -> dict[str, Any] | None:
        repository = finding.provenance.repository_id or "local"
        for (repo, path), entry in self.files.items():
            if repo == repository and finding.file_path in (path, entry.scan_path):
                return entry.metadata()
        return None

    def _select(self, arguments: dict[str, Any]) -> list[SourceFile]:
        repository_id = _text(arguments, "repository_id", 256)
        prefix = _text(arguments, "path_prefix", 1_024, required=False)
        if prefix and (".." in prefix.split("/") or prefix.startswith("/") or "\\" in prefix):
            raise ValueError("path_prefix must be repository-relative")
        if repository_id not in {key[0] for key in self.files}:
            raise ValueError("repository_id is not in the source snapshot")
        return [
            entry
            for (repo, path), entry in self.files.items()
            if repo == repository_id and path.startswith(prefix)
        ]

    def list_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        selected = self._select(arguments)
        offset = _integer(arguments, "offset", 0, MAX_SOURCE_FILES, default=0)
        page = selected[offset : offset + 25]
        return {
            "files": [entry.metadata() for entry in page],
            "total": len(selected),
            "next_offset": offset + len(page) if offset + len(page) < len(selected) else None,
            "catalog": self.summary(),
        }

    def read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        key = (_text(arguments, "repository_id", 256), _text(arguments, "path", 1_024))
        entry = self.files.get(key)
        if entry is None:
            raise ValueError("path is not in this repository's source snapshot")
        start = _integer(arguments, "line_start", 1, 1_000_000, default=1)
        end = _integer(arguments, "line_end", start, 1_000_000, default=start + 79)
        if start > len(entry.lines):
            raise ValueError("line_start is beyond the source file")
        selected: list[str] = []
        byte_count = 0
        requested_end = min(end, len(entry.lines))
        for line in entry.lines[start - 1 : min(requested_end, start - 1 + MAX_READ_LINES)]:
            size = len(line.encode()) + 1
            if byte_count + size > MAX_READ_BYTES:
                break
            selected.append(line)
            byte_count += size
        actual_end = start + len(selected) - 1
        output = {
            **entry.metadata(),
            "line_start": start,
            "line_end": actual_end,
            "content": "\n".join(selected),
            "truncated": actual_end < requested_end,
        }
        if selected:
            output["citation"] = _citation(entry, start, actual_end, output["content"])
        return output

    def search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        selected = self._select(arguments)
        query = _text(arguments, "query", 128)
        file_offset = _integer(arguments, "file_offset", 0, MAX_SOURCE_FILES, default=0)
        line_start = _integer(arguments, "line_start", 1, 1_000_000, default=1)
        matches: list[dict[str, Any]] = []
        searched_bytes = 0
        searched_files = 0
        skipped_long_lines = 0
        cursor: dict[str, int] | None = None
        for index in range(file_offset, len(selected)):
            entry = selected[index]
            first = line_start if index == file_offset else 1
            if (
                searched_files >= MAX_SEARCH_FILES
                or searched_bytes + entry.byte_count > MAX_SEARCH_BYTES
            ):
                cursor = {"file_offset": index, "line_start": first}
                break
            searched_files += 1
            searched_bytes += entry.byte_count
            for number, line in enumerate(entry.lines[first - 1 :], first):
                if len(matches) >= MAX_SEARCH_MATCHES:
                    cursor = {"file_offset": index, "line_start": number}
                    break
                if query not in line:
                    continue
                if len(line.encode()) > 1_024:
                    skipped_long_lines += 1
                    continue
                matches.append(
                    {
                        "content": line,
                        "citation": _citation(entry, number, number, line),
                    }
                )
            if cursor is not None:
                break
        return {
            "matches": matches,
            "next_cursor": cursor,
            "searched_files": searched_files,
            "searched_bytes": searched_bytes,
            "skipped_long_lines": skipped_long_lines,
            "truncated": skipped_long_lines > 0,
            "complete_from_cursor": cursor is None and skipped_long_lines == 0,
            "scope": "literal, case-sensitive search of redacted admitted source only",
        }

    def symbols(self, arguments: dict[str, Any]) -> dict[str, Any]:
        selected = self._select(arguments)
        if any(not entry.symbols_available for entry in selected):
            raise ValueError("source_symbols_unavailable_for_restored_snapshot")
        query = _text(arguments, "query", 128)
        offset = _integer(arguments, "offset", 0, MAX_SOURCE_FILES * 200, default=0)
        page: list[dict[str, Any]] = []
        total = 0
        for entry in selected:
            for symbol in entry.symbols:
                if query in symbol.qualified_name or query in symbol.name:
                    if offset <= total < offset + 10:
                        page.append({**entry.metadata(), **symbol.__dict__})
                    total += 1
        return {
            "symbols": page,
            "total": total,
            "next_offset": offset + len(page) if offset + len(page) < total else None,
            "truncated": any(entry.symbols_truncated for entry in selected),
            "evidence_kind": "parsed_declaration; read source before citing a conclusion",
        }


def _valid_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        0 < len(value) <= 1_024
        and bool(path.parts)
        and path.as_posix() == value
        and not path.is_absolute()
        and "\\" not in value
        and all(part not in ("", ".", "..") and not part.startswith(".") for part in path.parts)
        and all(ord(char) >= 32 for char in value)
    )


def _read_regular_source(root: Path, relative: Path, limit: int) -> bytes:
    """Reject links at every component and special files, including blocking FIFOs."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise NotImplementedError("safe source capture requires descriptor-relative opens")
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


def _redacted_lines(text: str) -> tuple[str, ...]:
    from aegify.llm.tools import redact_sensitive

    # Redact complete key blocks before slicing, including a slice requested from
    # the middle of a block, without changing the original line numbering.
    text = _PRIVATE_KEY.sub(
        lambda match: "\n".join("[REDACTED_PRIVATE_KEY]" for _ in match[0].split("\n")), text
    )
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return tuple(str(redact_sensitive(line.removesuffix("\r"))) for line in lines)


def _citation(entry: SourceFile, start: int, end: int, content: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "repository_id": entry.repository_id,
        "path": entry.path,
        "source_digest": entry.source_digest,
        "line_start": start,
        "line_end": end,
        "excerpt_digest": _digest(content),
    }
    return {"citation_id": _digest(json.dumps(value, sort_keys=True)), **value}


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _text(arguments: dict[str, Any], name: str, limit: int, *, required: bool = True) -> str:
    value = arguments.get(name, "")
    if not isinstance(value, str) or len(value) > limit or (required and not value):
        raise ValueError(f"{name} must be a {'non-empty ' if required else ''}bounded string")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _integer(arguments: dict[str, Any], name: str, low: int, high: int, *, default: int) -> int:
    value = arguments.get(name, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value
