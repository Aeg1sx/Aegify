"""Import SCIP protobuf JSON into a normalized semantic graph.

Native ``.scip`` protobuf indexes are converted with the upstream SCIP CLI's
stable JSON mode (``scip print --json``). JSON fixtures can be consumed
directly, which keeps the importer deterministic and easy to test.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from aegify.models import SemanticRelationship
from aegify.semantic.scip_symbol import (
    ScipPackageCoordinate,
    parse_scip_symbol,
)


class ScipImportError(ValueError):
    """Raised when an index cannot be converted or does not match SCIP shape."""


@dataclass
class ScipImport:
    """Normalized facts from one repository-scoped SCIP index."""

    repository_id: str
    provider: str = "scip"
    provider_version: str = ""
    documents: int = 0
    symbols: set[str] = field(default_factory=set)
    occurrences: int = 0
    relationships: list[SemanticRelationship] = field(default_factory=list)
    packages: set[ScipPackageCoordinate] = field(default_factory=set)
    defined_symbols: set[str] = field(default_factory=set)
    referenced_symbols: set[str] = field(default_factory=set)
    external_symbols: set[str] = field(default_factory=set)
    content_sha256: str = ""
    cache_hit: bool = False


class _ScipCacheRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    repository_id: str
    content_sha256: str
    provider: str
    provider_version: str
    documents: int
    symbols: list[str]
    occurrences: int
    relationships: list[SemanticRelationship]
    packages: list[tuple[str, str, str, str]]
    defined_symbols: list[str]
    referenced_symbols: list[str]
    external_symbols: list[str]


class ScipImporter:
    """Read native or protobuf-JSON SCIP indexes without trusting shell text."""

    _DEFINITION_ROLE = 0x1

    def __init__(self, cache_dir: Path | None = None) -> None:
        self.cache_dir = cache_dir

    def load(self, path: Path, repository_id: str) -> ScipImport:
        try:
            source_bytes = path.read_bytes()
        except OSError as error:
            raise ScipImportError(f"unable to read SCIP index {path}: {error}") from error
        content_sha256 = hashlib.sha256(source_bytes).hexdigest()
        cached = self._load_cache(repository_id, content_sha256)
        if cached is not None:
            return cached

        payload = self._load_payload(path, source_bytes)
        if not isinstance(payload, dict):
            raise ScipImportError(f"SCIP root must be a JSON object: {path}")

        metadata = self._dict(payload.get("metadata"))
        tool_info = self._dict(metadata.get("toolInfo", metadata.get("tool_info", {})))
        provider_name = str(tool_info.get("name", "scip")).strip() or "scip"
        result = ScipImport(
            repository_id=repository_id,
            provider=f"scip:{provider_name}",
            provider_version=str(tool_info.get("version", "")),
            content_sha256=content_sha256,
        )

        documents = payload.get("documents", [])
        if not isinstance(documents, list):
            raise ScipImportError(f"SCIP documents must be a list: {path}")
        result.documents = len(documents)

        for document in documents:
            doc = self._dict(document)
            relative_path = str(doc.get("relativePath", doc.get("relative_path", "")))
            self._validate_relative_path(relative_path, path)

            occurrences = doc.get("occurrences", [])
            if not isinstance(occurrences, list):
                raise ScipImportError(f"SCIP occurrences must be a list in {relative_path}")
            result.occurrences += len(occurrences)
            for occurrence in occurrences:
                item = self._dict(occurrence)
                symbol = str(item.get("symbol", ""))
                if not symbol:
                    continue
                result.symbols.add(symbol)
                self._record_symbol_package(result, symbol)
                roles = int(item.get("symbolRoles", item.get("symbol_roles", 0)) or 0)
                range_value = item.get("range", [])
                line = 0
                if isinstance(range_value, list) and range_value:
                    line = int(range_value[0]) + 1
                kind = "definition" if roles & self._DEFINITION_ROLE else "reference"
                if kind == "definition":
                    result.defined_symbols.add(symbol)
                else:
                    result.referenced_symbols.add(symbol)
                result.relationships.append(
                    SemanticRelationship(
                        source=f"repo:{repository_id}:file:{relative_path}",
                        target=symbol,
                        kind=kind,
                        repository_id=repository_id,
                        file_path=relative_path,
                        line=line,
                        confidence=1.0,
                        provider=result.provider,
                        fidelity="compiler-index",
                    )
                )
                if kind == "definition":
                    # Reverse resolution edge makes a reference in repository A
                    # traversable through the canonical symbol to its concrete
                    # definition document in repository B.
                    result.relationships.append(
                        SemanticRelationship(
                            source=symbol,
                            target=f"repo:{repository_id}:file:{relative_path}",
                            kind="defined-in",
                            repository_id=repository_id,
                            file_path=relative_path,
                            line=line,
                            confidence=1.0,
                            provider=result.provider,
                            fidelity="compiler-index",
                        )
                    )

            symbols = doc.get("symbols", [])
            if not isinstance(symbols, list):
                raise ScipImportError(f"SCIP symbols must be a list in {relative_path}")
            for symbol_info in symbols:
                self._add_symbol_info(
                    result,
                    self._dict(symbol_info),
                    relative_path,
                    external=False,
                )

        external_symbols = payload.get("externalSymbols", payload.get("external_symbols", []))
        if isinstance(external_symbols, list):
            for symbol_info in external_symbols:
                self._add_symbol_info(
                    result,
                    self._dict(symbol_info),
                    "",
                    external=True,
                )
        self._write_cache(result)
        return result

    def _load_payload(self, path: Path, source_bytes: bytes) -> Any:
        if path.suffix.lower() == ".json":
            try:
                return json.loads(source_bytes.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as error:
                raise ScipImportError(f"unable to read SCIP JSON {path}: {error}") from error

        scip = shutil.which("scip")
        if not scip:
            raise ScipImportError(
                "native SCIP index requires the upstream `scip` CLI; "
                "install it or provide `scip print --json index.scip` output"
            )
        try:
            completed = subprocess.run(
                [scip, "print", "--json", str(path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ScipImportError(f"SCIP conversion failed for {path}: {error}") from error
        if completed.returncode != 0:
            detail = completed.stderr.strip()[:1000]
            raise ScipImportError(
                f"SCIP conversion exited {completed.returncode} for {path}: {detail}"
            )
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ScipImportError(f"SCIP CLI returned invalid JSON for {path}") from error

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        return {}

    @staticmethod
    def _validate_relative_path(relative_path: str, source: Path) -> None:
        candidate = Path(relative_path)
        if (
            not relative_path
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "." in candidate.parts
        ):
            raise ScipImportError(
                f"non-canonical SCIP document path in {source}: {relative_path!r}"
            )

    def _add_symbol_info(
        self,
        result: ScipImport,
        info: dict[str, Any],
        relative_path: str,
        *,
        external: bool,
    ) -> None:
        symbol = str(info.get("symbol", ""))
        if not symbol:
            return
        result.symbols.add(symbol)
        self._record_symbol_package(result, symbol)
        if external:
            result.external_symbols.add(symbol)
            result.referenced_symbols.add(symbol)
        else:
            result.defined_symbols.add(symbol)
        relationships = info.get("relationships", [])
        if not isinstance(relationships, list):
            return
        for raw_relationship in relationships:
            relationship = self._dict(raw_relationship)
            target = str(relationship.get("symbol", ""))
            if not target:
                continue
            result.symbols.add(target)
            self._record_symbol_package(result, target)
            result.referenced_symbols.add(target)
            flags = (
                ("implementation", "isImplementation", "is_implementation"),
                ("reference-alias", "isReference", "is_reference"),
                ("type-definition", "isTypeDefinition", "is_type_definition"),
                ("definition-alias", "isDefinition", "is_definition"),
            )
            for kind, camel_key, snake_key in flags:
                if relationship.get(camel_key, relationship.get(snake_key, False)):
                    result.relationships.append(
                        SemanticRelationship(
                            source=symbol,
                            target=target,
                            kind=kind,
                            repository_id=result.repository_id,
                            file_path=relative_path,
                            confidence=1.0,
                            provider=result.provider,
                            fidelity="compiler-index",
                        )
                    )

    @staticmethod
    def _record_symbol_package(result: ScipImport, symbol: str) -> None:
        parsed = parse_scip_symbol(symbol)
        if parsed is not None and parsed.package is not None:
            result.packages.add(parsed.package)

    def _cache_path(self, repository_id: str, content_sha256: str) -> Path | None:
        if self.cache_dir is None:
            return None
        key_source = f"1\0{repository_id}\0{content_sha256}".encode()
        key = hashlib.sha256(key_source).hexdigest()
        return self.cache_dir / f"{key}.json"

    def _load_cache(
        self,
        repository_id: str,
        content_sha256: str,
    ) -> ScipImport | None:
        cache_path = self._cache_path(repository_id, content_sha256)
        if cache_path is None or not cache_path.is_file():
            return None
        try:
            record = _ScipCacheRecord.model_validate_json(cache_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            return None
        if record.repository_id != repository_id or record.content_sha256 != content_sha256:
            return None
        return ScipImport(
            repository_id=record.repository_id,
            provider=record.provider,
            provider_version=record.provider_version,
            documents=record.documents,
            symbols=set(record.symbols),
            occurrences=record.occurrences,
            relationships=record.relationships,
            packages={ScipPackageCoordinate(*coordinate) for coordinate in record.packages},
            defined_symbols=set(record.defined_symbols),
            referenced_symbols=set(record.referenced_symbols),
            external_symbols=set(record.external_symbols),
            content_sha256=record.content_sha256,
            cache_hit=True,
        )

    def _write_cache(self, result: ScipImport) -> None:
        cache_path = self._cache_path(result.repository_id, result.content_sha256)
        if cache_path is None:
            return
        record = _ScipCacheRecord(
            repository_id=result.repository_id,
            content_sha256=result.content_sha256,
            provider=result.provider,
            provider_version=result.provider_version,
            documents=result.documents,
            symbols=sorted(result.symbols),
            occurrences=result.occurrences,
            relationships=result.relationships,
            packages=[
                (item.scheme, item.manager, item.name, item.version)
                for item in sorted(result.packages)
            ],
            defined_symbols=sorted(result.defined_symbols),
            referenced_symbols=sorted(result.referenced_symbols),
            external_symbols=sorted(result.external_symbols),
        )
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = cache_path.with_suffix(f".tmp-{uuid.uuid4().hex}")
            temporary.write_text(record.model_dump_json(), encoding="utf-8")
            temporary.replace(cache_path)
        except OSError:
            return
