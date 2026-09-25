"""Reopen an analysis snapshot by logical identity, never historical absolute paths."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.llm.sources import SourceCatalog
from aegify.models import AnalyzedSource, ScanResult
from aegify.scanner.engine import ScanEngine
from tests.test_agent_source_loop import source_scan


def test_scanner_persists_parser_content_hash_for_later_agent_binding(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def greet(name):\n    return name\n")
    config = AegifyConfig()
    config.scan.max_workers = 1
    scan = ScanEngine(config).scan(tmp_path)
    assert len(scan.analyzed_sources) == 1
    item = scan.analyzed_sources[0]
    assert item.source_digest == hashlib.sha256(source.read_bytes()).hexdigest()
    assert item.language and item.language.value == "python"
    restored = SourceCatalog.from_scan(
        ScanResult.model_validate_json(scan.model_dump_json()), {"local": tmp_path}
    )
    assert list(restored.files) == [("local", "app.py")]
    assert not restored.gap_counts


def test_relocated_root_reads_only_scanned_files_with_matching_hash(tmp_path: Path) -> None:
    before, after = tmp_path / "old", tmp_path / "checkout"
    scan, original = source_scan(before)
    target = after / "src/app.py"
    target.parent.mkdir(parents=True)
    target.write_bytes((before / "src/app.py").read_bytes())
    (before / "src/app.py").write_text("historical_path_must_not_be_opened = True\n")
    (after / "unparsed.py").write_text("excluded_material = True\n")
    restored = SourceCatalog.from_scan(scan, {"service": after})
    assert not restored.gap_counts and restored.manifest_digest == original.manifest_digest
    assert list(restored.files) == [("service", "src/app.py")]
    assert restored.finding_location(scan.findings[0])["path"] == "src/app.py"  # type: ignore[index]
    target.write_text("changed_after_capture = True\n")
    assert restored.read({"repository_id": "service", "path": "src/app.py"})["content"].endswith(
        "return name"
    )
    with pytest.raises(ValueError, match="unavailable"):
        restored.symbols({"repository_id": "service", "query": "greet"})


@pytest.mark.parametrize(
    "case",
    [
        "changed",
        "missing_hash",
        "missing_language",
        "missing_root",
        "duplicate",
        "wrong_language",
        "absolute",
        "dotdot",
        "hidden",
        "noncanonical",
        "file_symlink",
        "directory_symlink",
    ],
)
def test_source_manifest_rejects_ambiguous_or_unbound_files(tmp_path: Path, case: str) -> None:
    root = tmp_path / "repo"
    scan, _catalog = source_scan(root)
    roots = {"service": root}
    source = scan.analyzed_sources[0]
    if case == "changed":
        (root / "src/app.py").write_text("different = True\n")
    elif case == "missing_hash":
        source.source_digest = ""
    elif case == "missing_language":
        source.language = None
    elif case == "missing_root":
        roots = {"other": root}
    elif case == "duplicate":
        scan.analyzed_sources.append(source.model_copy())
    elif case == "wrong_language":
        source.language = "java"  # type: ignore[assignment]
    elif case in {"absolute", "dotdot", "hidden", "noncanonical"}:
        source.module_path = {
            "absolute": str(root / "src/app.py"),
            "dotdot": "../src/app.py",
            "hidden": ".private/app.py",
            "noncanonical": "src//app.py",
        }[case]
    elif case == "file_symlink":
        (root / "src/app.py").rename(tmp_path / "owned.py")
        (root / "src/app.py").symlink_to(tmp_path / "owned.py")
    else:
        (root / "src").rename(tmp_path / "owned-dir")
        (root / "src").symlink_to(tmp_path / "owned-dir", target_is_directory=True)
    restored = SourceCatalog.from_scan(scan, roots)
    assert not restored.files and restored.gap_counts


def test_legacy_scan_has_no_filesystem_fallback(tmp_path: Path) -> None:
    target = tmp_path / "unbound.py"
    target.write_text("unbound = True\n")
    scan = ScanResult(analyzed_files=[str(target)])
    restored = SourceCatalog.from_scan(scan, {"local": tmp_path})
    assert not restored.files
    assert restored.gap_counts == {"source_manifest_unavailable": 1}


def test_multi_repository_same_path_keeps_namespace_and_citation_identity(tmp_path: Path) -> None:
    left, _catalog = source_scan(tmp_path / "one", "one")
    right, _catalog = source_scan(tmp_path / "two", "two")
    left.analyzed_sources.extend(right.analyzed_sources)
    roots = {"one": tmp_path / "one", "two": tmp_path / "two"}
    restored = SourceCatalog.from_scan(left, roots)
    assert sorted(restored.files) == [("one", "src/app.py"), ("two", "src/app.py")]
    citations = [
        restored.read({"repository_id": repo, "path": "src/app.py"})["citation"] for repo in roots
    ]
    assert citations[0]["citation_id"] != citations[1]["citation_id"]
    assert restored.valid_citation(citations[0])
    assert not restored.valid_citation({**citations[0], "repository_id": "two"})


def test_legacy_source_records_remain_readable() -> None:
    parsed = AnalyzedSource.model_validate({"file_path": "old.py", "module_path": "old.py"})
    assert parsed.source_digest == "" and parsed.language is None


def test_programmatic_catalog_cannot_be_reused_for_another_scan(tmp_path: Path) -> None:
    scan, catalog = source_scan(tmp_path)
    scan.analyzed_sources[0].source_digest = "e" * 64
    bound = catalog.bind_scan(scan)
    assert not bound.files
    assert bound.gap_counts["source_scan_binding_mismatch"] == 1


def test_programmatic_subset_records_omitted_manifest_files(tmp_path: Path) -> None:
    scan, catalog = source_scan(tmp_path)
    scan.analyzed_sources.append(
        scan.analyzed_sources[0].model_copy(update={"module_path": "other.py"})
    )
    bound = catalog.bind_scan(scan)
    assert len(bound.files) == 1
    assert bound.gap_counts["source_manifest_files_unavailable"] == 1
