"""Owned, non-executable controls for benchmark admission and evidence."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegify.cli import app
from aegify.models import Finding, ScanResult, ScanStatus, Severity
from aegify.quality import benchmark_runner
from aegify.quality.artifacts import parse_json_object, read_regular_file, write_report
from aegify.quality.benchmark import digest_source_tree
from aegify.quality.benchmark_runner import run_owned_benchmark
from aegify.scanner.engine import ScanEngine


def _fixture(tmp_path: Path) -> tuple[Path, Path, ScanResult]:
    root = tmp_path / "corpus"
    root.mkdir()
    source = root / "control.py"
    source.write_text("value = 1\n")
    labels = tmp_path / "labels.json"
    labels.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "corpus_id": "owned-controls",
                "corpus_version": "1.0.0",
                "rule_scope": ["AEG-DEMO"],
                "expected": [{"rule_id": "AEG-DEMO", "file_path": "control.py", "line_start": 1}],
            }
        )
    )
    finding = Finding(
        rule_id="AEG-DEMO",
        rule_name="Synthetic evaluation observation",
        severity=Severity.LOW,
        confidence=0.5,
        file_path=str(source),
        line_start=1,
        line_end=1,
    )
    scan = ScanResult(
        findings=[finding], evaluated_rules=["AEG-DEMO"], analyzed_files=[str(source)]
    )
    return root, labels, scan


def test_real_runner_freezes_config_and_preserves_core_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corpus = Path(__file__).resolve().parents[1] / "benchmarks" / "core-v1"
    root = tmp_path / "corpus"
    shutil.copytree(corpus / "sources", root)
    (root / ".aegify.yml").write_text("invalid: [repo configuration must not be loaded\n")
    monkeypatch.setenv("AEGIFY_RULES__DISABLED_RULES", '["AEG-SQL-001"]')
    monkeypatch.setenv("AEGIFY_LLM__ENABLED", "true")
    monkeypatch.setenv("AEGIFY_STORAGE__BACKEND", "postgresql")
    monkeypatch.setenv("AEGIFY_ANTHROPIC_API_KEY", "owned-unused-test-value")
    report = run_owned_benchmark(root, corpus / "ground-truth.json")
    assert report.evaluation_complete
    assert report.metrics.true_positives == 9
    assert report.metrics.false_positives == report.metrics.false_negatives == 0
    assert report.schema_version == 2
    config = report.provenance["config"]
    assert config["storage"]["backend"] == "memory"
    assert config["llm"]["enabled"] is False
    assert config["rules"]["disabled_rules"] == []
    assert config["scan"]["max_findings_per_rule"] == config["scan"]["max_findings_per_file"] == 0
    assert "anthropic_api_key" not in config
    assert "owned-unused-test-value" not in report.model_dump_json()
    assert report.outcomes_digest.startswith("sha256:")


@pytest.mark.parametrize(
    "changed", ["source", "auxiliary", "labels", "implementation", "configuration"]
)
def test_runner_rejects_inputs_changed_during_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    root, labels, scan = _fixture(tmp_path)
    manifest_calls = 0
    if changed == "implementation":

        def implementation(_engine):
            nonlocal manifest_calls
            manifest_calls += 1
            return {"revision": manifest_calls}

        monkeypatch.setattr(benchmark_runner, "implementation_manifest", implementation)

    def mutate(self, target):
        if changed == "source":
            (root / "control.py").write_text("value = 2\n")
        elif changed == "auxiliary":
            (root / "openapi.json").write_text("{}\n")
        elif changed == "labels":
            labels.write_text(labels.read_text() + "\n")
        elif changed == "configuration":
            self.config.scan.max_findings_per_rule = 1
        return scan

    monkeypatch.setattr(ScanEngine, "scan", mutate)
    with pytest.raises(ValueError, match="changed during analysis"):
        run_owned_benchmark(root, labels)


@pytest.mark.parametrize("missing", ["rules", "files"])
def test_missing_executed_scope_is_incomplete_even_with_perfect_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    root, labels, scan = _fixture(tmp_path)
    if missing == "rules":
        scan.evaluated_rules = []
    else:
        scan.analyzed_files = []
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    output = tmp_path / "report.json"
    invocation = CliRunner().invoke(
        app, ["benchmark", str(root), "--ground-truth", str(labels), "-o", str(output)]
    )
    assert invocation.exit_code == 3, invocation.output
    report = json.loads(output.read_text())
    assert report["metrics"]["precision"] == report["metrics"]["recall"] == 1
    assert not report["evaluation_complete"]
    assert report["missing_" + missing]


@pytest.mark.parametrize(
    "status,exit_code", [(ScanStatus.FAILED, 2), (ScanStatus.PARTIAL, 3), (ScanStatus.RUNNING, 2)]
)
def test_scanner_health_has_priority_over_quality(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: ScanStatus, exit_code: int
) -> None:
    root, labels, scan = _fixture(tmp_path)
    scan.status = status
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app, ["benchmark", str(root), "--ground-truth", str(labels), "-o", str(output)]
    )
    assert result.exit_code == exit_code
    assert not json.loads(output.read_text())["evaluation_complete"]


def test_undefined_precision_cannot_pass_a_zero_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels, scan = _fixture(tmp_path)
    scan.findings = []
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        [
            "benchmark",
            str(root),
            "--ground-truth",
            str(labels),
            "-o",
            str(output),
            "--min-precision",
            "0",
            "--min-recall",
            "0",
        ],
    )
    assert result.exit_code == 1
    assert json.loads(output.read_text())["metrics"]["precision"] is None


@pytest.mark.parametrize(
    "issue",
    [
        "missing_file",
        "line_outside",
        "path_outside",
        "drive_path",
        "duplicate_key",
        "root_link",
        "source_link",
        "label_link",
        "oversized_source",
    ],
)
def test_invalid_inputs_fail_before_scanner_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issue: str
) -> None:
    root, labels, scan = _fixture(tmp_path)
    source = root / "control.py"
    payload = json.loads(labels.read_text())
    if issue == "missing_file":
        source.unlink()
    elif issue == "line_outside":
        payload["expected"][0]["line_start"] = 2
    elif issue == "path_outside":
        payload["expected"][0]["file_path"] = "../labels.json"
    elif issue == "drive_path":
        payload["expected"][0]["file_path"] = "C:/control.py"
    elif issue == "root_link":
        link = tmp_path / "linked"
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif issue == "source_link":
        source.unlink()
        source.symlink_to(labels)
    elif issue == "label_link":
        link = tmp_path / "linked.json"
        link.symlink_to(labels)
        labels = link
    elif issue == "oversized_source":
        with source.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
    if issue in {"line_outside", "path_outside", "drive_path"}:
        labels.write_text(json.dumps(payload))
    elif issue == "duplicate_key":
        labels.write_text(
            labels.read_text().replace(
                '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
            )
        )

    def forbidden(*args):
        pytest.fail("invalid input reached scanner dispatch")

    monkeypatch.setattr(ScanEngine, "scan", forbidden)
    with pytest.raises((ValueError, OSError)):
        run_owned_benchmark(root, labels)


@pytest.mark.parametrize("destination", ["corpus", "labels", "directory"])
def test_cli_rejects_input_overwrite_and_report_write_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, destination: str
) -> None:
    root, labels, scan = _fixture(tmp_path)
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    output = (
        root / "report.json"
        if destination == "corpus"
        else labels
        if destination == "labels"
        else tmp_path
    )
    label_bytes = labels.read_bytes()
    result = CliRunner().invoke(
        app, ["benchmark", str(root), "--ground-truth", str(labels), "-o", str(output)]
    )
    assert result.exit_code == 2, result.output
    assert labels.read_bytes() == label_bytes


def test_repeated_observations_ignore_timings_and_bind_duplicate_hits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels, scan = _fixture(tmp_path)
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    first = run_owned_benchmark(root, labels)
    scan.duration_seconds = 900
    second = run_owned_benchmark(root, labels)
    assert first.outcomes_digest == second.outcomes_digest
    assert first.provenance == second.provenance
    scan.findings.append(scan.findings[0].model_copy())
    assert run_owned_benchmark(root, labels).outcomes_digest != first.outcomes_digest


def test_file_target_binds_auxiliary_inputs_and_rejects_other_file_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels, scan = _fixture(tmp_path)
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    first = run_owned_benchmark(root / "control.py", labels)
    (root / "openapi.json").write_text("{}")
    second = run_owned_benchmark(root / "control.py", labels)
    assert first.source_digest != second.source_digest
    (root / "other.py").write_text("value = 2\n")
    with pytest.raises(ValueError, match="outside the selected file"):
        run_owned_benchmark(root / "other.py", labels)


@pytest.mark.parametrize(
    "material",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e9999}', b"[]", b"[" * 2000],
)
def test_artifact_json_rejects_ambiguous_or_nonfinite_values(material: bytes) -> None:
    with pytest.raises(ValueError):
        parse_json_object(material)


def test_bounded_artifact_and_atomic_report_keep_original_hardlinks(tmp_path: Path) -> None:
    original = tmp_path / "input.json"
    original.write_text("unchanged")
    with pytest.raises(ValueError):
        read_regular_file(original, limit=3)
    output = tmp_path / "output.json"
    output.hardlink_to(original)
    write_report(output, '{"result":true}')
    assert original.read_text() == "unchanged"
    assert json.loads(output.read_text()) == {"result": True}


def test_unicode_source_paths_have_unambiguous_byte_lengths(tmp_path: Path) -> None:
    (tmp_path / "검사.py").write_text("value = 1\n")
    assert digest_source_tree(tmp_path).startswith("sha256:")


def test_many_labels_share_one_bounded_file_read_for_line_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, labels, scan = _fixture(tmp_path)
    source = root / "control.py"
    source.write_text("value = 1\n" * 1000)
    payload = json.loads(labels.read_text())
    payload["expected"] = [
        {"rule_id": "AEG-DEMO", "file_path": "control.py", "line_start": line}
        for line in range(1, 1001)
    ]
    labels.write_text(json.dumps(payload))
    source_reads = 0
    original = benchmark_runner.read_regular_file

    def counted(path, *, limit):
        nonlocal source_reads
        source_reads += path == source
        return original(path, limit=limit)

    monkeypatch.setattr(benchmark_runner, "read_regular_file", counted)
    monkeypatch.setattr(ScanEngine, "scan", lambda *args: scan)
    report = run_owned_benchmark(root, labels)
    assert source_reads == 1
    assert report.metrics.false_negatives == 999


def test_descriptor_admission_rejects_symlinks_without_reading_the_target(tmp_path: Path) -> None:
    original = tmp_path / "owned.json"
    original.write_text('{"owned":true}')
    alias = tmp_path / "link.json"
    alias.symlink_to(original)
    with pytest.raises(OSError):
        read_regular_file(alias, limit=1024)
    assert read_regular_file(original, limit=1024) == b'{"owned":true}'
    with pytest.raises(ValueError, match="regular file"):
        read_regular_file(tmp_path, limit=1024)


@pytest.mark.skipif(os.name != "posix", reason="bounded FIFO admission requires POSIX")
def test_descriptor_admission_rejects_fifo_without_waiting_for_a_writer(tmp_path: Path) -> None:
    fifo = tmp_path / "owned-fifo"
    os.mkfifo(fifo)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path\n"
            "import sys\n"
            "from aegify.quality.artifacts import read_regular_file\n"
            "try:\n"
            "    read_regular_file(Path(sys.argv[1]), limit=1024)\n"
            "except ValueError:\n"
            "    sys.exit(0)\n"
            "sys.exit(1)\n",
            str(fifo),
        ],
        capture_output=True,
        timeout=3,
    )
    assert child.returncode == 0, child.stderr.decode()


def test_cli_artifact_diagnostics_remain_literal_and_bounded(tmp_path: Path) -> None:
    root, labels, _ = _fixture(tmp_path)
    key = "[bold]owned[/bold]\nlabel"
    encoded = json.dumps(key)
    labels.write_text("{" + encoded + ":1," + encoded + ":2}")
    result = CliRunner().invoke(app, ["benchmark", str(root), "--ground-truth", str(labels)])
    assert result.exit_code == 2
    assert "[bold]owned[/bold]\\nlabel" in result.output
    huge = json.dumps("x" * 8000)
    labels.write_text("{" + huge + ":1," + huge + ":2}")
    result = CliRunner().invoke(app, ["benchmark", str(root), "--ground-truth", str(labels)])
    assert result.exit_code == 2
    assert "(truncated)" in result.output
    assert len(result.output) < 3000
