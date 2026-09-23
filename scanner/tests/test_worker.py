"""Static-only worker contract: no target application is executed."""

import hashlib
from pathlib import Path

import pytest

from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.worker import run_snapshot, snapshot_digest, validate_snapshot, worker_config


def _payload(path: str = "app.py", content: str = "value = 1\n"):
    payload = {
        "version": 1,
        "provider": "github",
        "repository": "fixture/repository",
        "commit": "a" * 40,
        "truncated": False,
        "files": [
            {
                "path": path,
                "content": content,
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
            }
        ],
    }
    payload["sourceDigest"] = snapshot_digest(payload)
    return payload


@pytest.mark.parametrize(
    "path",
    [
        "../escape.py",
        "/absolute.py",
        "a//b.py",
        "a/./b.py",
        ".git/config",
        "C:/x.py",
        "a\\b.py",
        "a\0b.py",
    ],
)
def test_snapshot_rejects_paths_outside_the_explicit_source_tree(path: str):
    with pytest.raises(ValueError):
        validate_snapshot(_payload(path))


def test_snapshot_rejects_changed_content_duplicate_paths_and_byte_limits():
    payload = _payload()
    payload["files"][0]["content"] = "changed"
    with pytest.raises(ValueError, match="digest"):
        validate_snapshot(payload)
    duplicate = _payload()
    duplicate["files"].append(duplicate["files"][0].copy())
    with pytest.raises(ValueError, match="duplicate"):
        validate_snapshot(duplicate)
    with pytest.raises(ValueError, match="bytes"):
        validate_snapshot(_payload(content="x" * (500 * 1024 + 1)))


def test_worker_does_not_execute_source_or_load_repository_configuration(tmp_path: Path):
    marker = tmp_path / "must-not-exist"
    payload = _payload(content=f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    report = run_snapshot(payload, tmp_path / "source")
    assert not marker.exists()
    assert report["runs"][0]["properties"]["analysisScope"] == "files"
    manifest = report["runs"][0]["properties"]["workerManifest"]
    assert manifest["sourceDigest"] == payload["sourceDigest"]
    assert manifest["config"]["llm"]["enabled"] is False
    assert manifest["engineDigest"].startswith("sha256:")
    assert manifest["rulesDigest"].startswith("sha256:")


def test_worker_configuration_overrides_ambient_integrations(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AEGIFY_STORAGE__BACKEND", "s3")
    monkeypatch.setenv("AEGIFY_RULES__CUSTOM_RULES", "/untrusted/rules")
    monkeypatch.setenv("AEGIFY_LLM__ENABLED", "true")
    monkeypatch.setenv("AEGIFY_ANTHROPIC_API_KEY", "synthetic-not-for-export")
    config = worker_config()
    assert config.storage.backend == "memory"
    assert config.rules.custom_rules is None
    assert not config.llm.enabled and not config.anthropic_api_key


def test_workspace_digest_stays_bound_to_the_parsed_bytes(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n")
    ast = ASTParser().parse_file(source, repository_root=tmp_path)
    assert ast is not None
    initial = ScanEngine._compute_workspace_snapshot([ast], [tmp_path])
    source.write_text("value = 2\n")
    assert ScanEngine._compute_workspace_snapshot([ast], [tmp_path]) == initial
    changed = ASTParser().parse_file(source, repository_root=tmp_path)
    assert changed is not None
    assert ScanEngine._compute_workspace_snapshot([changed], [tmp_path]) != initial
