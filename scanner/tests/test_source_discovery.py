"""Coverage must distinguish unreadable directory trees from excluded or empty ones."""

import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

from aegify.config import AegifyConfig
from aegify.models import ScanResult, ScanStatus
from aegify.reporter.sarif import SARIFReporter
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine


def _deny_directories(monkeypatch, directories):
    scandir = os.scandir
    attempted = []

    def guarded(path):
        if not isinstance(path, int) and Path(path) in directories:
            attempted.append(Path(path))
            raise PermissionError("simulated enumeration failure")
        return scandir(path)

    monkeypatch.setattr(os, "scandir", guarded)
    return attempted


def test_workspace_counts_include_partial_unreadable_and_empty_repositories(tmp_path, monkeypatch):
    repos = ["api", "web", "offline", "empty"]
    for repo in repos:
        (tmp_path / repo).mkdir()
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "repositories:\n" + "".join(f"  - id: {repo}\n    path: {repo}\n" for repo in repos)
    )
    hidden = tmp_path / "api" / "subdir"
    hidden.mkdir()
    for root in (tmp_path / "api", tmp_path / "web", tmp_path / "offline", hidden):
        (root / "app.py").write_text("value = 1\n")
    (tmp_path / "empty" / "README.md").write_text("Only documentation.\n")
    config = AegifyConfig()
    config.scan.max_workers = 1
    scanner = ScanEngine(config)
    with monkeypatch.context() as patch:
        _deny_directories(patch, {tmp_path / "offline", hidden})
        partial = scanner.scan_workspace(manifest)
    assert partial.status == ScanStatus.PARTIAL
    assert [(g.code, g.stage, g.affected_count) for g in partial.analysis_gaps] == [
        ("source_discovery_error", "discovery", 2)
    ]
    assert partial.files_scanned == 2
    run = SARIFReporter().generate(partial)["runs"][0]
    assert not run["invocations"][0]["executionSuccessful"]
    props = run["properties"]
    assert props["sourceIdentityVersion"] == 1
    assert {(s["repositoryId"], s["modulePath"]) for s in props["analyzedSources"]} == {
        ("api", "app.py"),
        ("web", "app.py"),
    }
    assert props["repositoryCoverage"] == {
        "version": 1,
        "repositories": [
            {"repositoryId": "api", "analyzedFiles": 1, "discoveryErrors": 1},
            {"repositoryId": "web", "analyzedFiles": 1, "discoveryErrors": 0},
            {"repositoryId": "offline", "analyzedFiles": 0, "discoveryErrors": 1},
            {"repositoryId": "empty", "analyzedFiles": 0, "discoveryErrors": 0},
        ],
    }
    healthy = scanner.scan_workspace(manifest)
    assert healthy.status == ScanStatus.COMPLETED and not healthy.analysis_gaps
    assert healthy.files_scanned == 4
    assert [
        (r.repository_id, r.analyzed_files, r.discovery_errors) for r in healthy.repository_coverage
    ] == [("api", 2, 0), ("web", 1, 0), ("offline", 1, 0), ("empty", 0, 0)]


def test_workspace_with_no_sources_explicitly_exports_empty_source_set(tmp_path):
    root = tmp_path / "docs"
    root.mkdir()
    manifest = tmp_path / "workspace.yml"
    manifest.write_text("repositories:\n  - id: docs\n    path: docs\n")
    result = ScanEngine().scan_workspace(manifest)
    assert result.status == ScanStatus.PARTIAL
    assert [g.code for g in result.analysis_gaps] == ["no_source_files"]
    props = SARIFReporter().generate(result)["runs"][0]["properties"]
    assert props["repositoryCoverage"]["repositories"] == [
        {"repositoryId": "docs", "analyzedFiles": 0, "discoveryErrors": 0}
    ]
    assert props["sourceIdentityVersion"] == 1 and props["analyzedSources"] == []


def test_single_repo_partial_and_legacy_sarif_preserve_available_evidence(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    _deny_directories(monkeypatch, {unreadable})
    result = ScanEngine().scan(tmp_path)
    assert result.status == ScanStatus.PARTIAL and result.files_scanned == 1
    assert [(g.code, g.affected_count) for g in result.analysis_gaps] == [
        ("source_discovery_error", 1)
    ]
    props = SARIFReporter().generate(result)["runs"][0]["properties"]
    assert [s["modulePath"] for s in props["analyzedSources"]] == ["app.py"]
    assert "repositoryCoverage" not in props
    old = ScanResult.model_validate({"analyzed_files": [str(source)]})
    legacy = SARIFReporter().generate(old)["runs"][0]["properties"]
    assert legacy["analyzedFiles"] == [str(source)]
    assert not {"repositoryCoverage", "analyzedSources", "sourceIdentityVersion"} & legacy.keys()


def test_directory_pruning_preserves_file_globs_and_skips_directory_symlinks(tmp_path, monkeypatch):
    root, outside = tmp_path / "root", tmp_path / "outside"
    source = root / "generated.py" / "keep.js"
    source.parent.mkdir(parents=True)
    source.write_text("const value = 1;\n")
    outside.mkdir()
    (outside / "external.py").write_text("value = 1\n")
    alias = root / "linked"
    alias.symlink_to(outside, target_is_directory=True)
    excluded = {root / "vendor", root / "service" / "cache"}
    for directory in excluded:
        directory.mkdir(parents=True)
    attempted = _deny_directories(monkeypatch, excluded | {alias})
    errors = []
    files = ASTParser()._collect_files(
        root, {"vendor/**", "**/cache/*", "*.py"}, on_error=errors.append
    )
    assert files == [source]
    assert attempted == [] and errors == []


def test_entry_type_failure_is_reported_without_discarding_other_sources(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    (tmp_path / "unknown").mkdir()
    scandir = os.scandir

    @contextmanager
    def with_unknown(path):
        with scandir(path) as entries:

            def classify(entry):
                if entry.name == "unknown":
                    unknown = Mock(wraps=entry, name="unknown directory entry")
                    unknown.name = entry.name
                    unknown.is_dir.side_effect = PermissionError("unreadable entry type")
                    return unknown
                return entry

            yield (classify(entry) for entry in entries)

    monkeypatch.setattr(os, "scandir", with_unknown)
    errors = []
    assert ASTParser()._collect_files(tmp_path, set(), on_error=errors.append) == [source]
    assert len(errors) == 1 and isinstance(errors[0], PermissionError)


def test_nested_checkout_has_one_owner_and_keeps_parsed_identity_on_later_failure(
    tmp_path, monkeypatch
):
    from aegify.semantic import SemanticAnalyzer

    parent = tmp_path / "monorepo"
    child = parent / "services" / "api"
    child.mkdir(parents=True)
    for root in (parent, child):
        (root / "app.py").write_text("value = 1\n")
    manifest = tmp_path / "workspace.yml"
    manifest.write_text(
        "repositories:\n  - id: child\n    path: monorepo/services/api\n"
        "  - id: parent\n    path: monorepo\n"
    )
    scanner = ScanEngine()
    completed = scanner.scan_workspace(manifest)
    monkeypatch.setattr(
        SemanticAnalyzer, "analyze", Mock(side_effect=ValueError("analysis failed"))
    )
    failed = scanner.scan_workspace(manifest)
    assert (completed.status, failed.status) == (ScanStatus.COMPLETED, ScanStatus.FAILED)
    for result in (completed, failed):
        props = SARIFReporter().generate(result)["runs"][0]["properties"]
        assert result.files_scanned == 2
        assert {r.repository_id: r.analyzed_files for r in result.repository_coverage} == {
            "child": 1,
            "parent": 1,
        }
        assert set(props["analyzedFiles"]) == {str(parent / "app.py"), str(child / "app.py")}
        assert [(s["repositoryId"], s["modulePath"]) for s in props["analyzedSources"]] == [
            ("child", "app.py"),
            ("parent", "app.py"),
        ]
