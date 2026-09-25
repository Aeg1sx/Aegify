"""Owned scoring, provider-conformance and performance failure controls."""

import json
import math
import subprocess
from pathlib import Path

import pytest

from aegify.models import ScanResult
from aegify.quality.owasp import evaluate_cases, inventory_sources, read_labels
from aegify.quality.performance import distribution, identity, measure
from aegify.quality.provider_acceptance import check_provider
from tests.test_agent_source_loop import ScriptedBackend, final, requests


def test_java_scoring_uses_exact_upstream_path_not_python_or_basename(tmp_path):
    cases = read_labels(b"BenchmarkTest00001,sqli,true,89\n", language="java")
    assert (
        cases[0].file_path == "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
    )
    report = evaluate_cases(
        ScanResult(analyzed_files=[cases[0].file_path], evaluated_rules=["sql"]),
        cases,
        target_root=tmp_path,
        rule_cwes={"sql": 89},
    )
    assert report["evaluation"] == "owasp-java-exact-case-cwe-v1"
    assert report["metrics"]["all_candidates"]["false_negatives"] == 1
    report = evaluate_cases(
        ScanResult(analyzed_files=["testcode/BenchmarkTest00001.py"], evaluated_rules=["sql"]),
        cases,
        target_root=tmp_path,
        rule_cwes={"sql": 89},
    )
    assert report["metrics"]["all_candidates"]["unscored_cases"] == 1
    with pytest.raises(ValueError):
        read_labels(b"BenchmarkTest00001,sqli,true,89\n", language="javascript")


def test_java_inventory_hashes_auxiliary_inputs_and_rejects_links(tmp_path):
    (tmp_path / "Example.java").write_text("class Example {}")
    config = tmp_path / "pom.xml"
    config.write_text("<project />")
    files, digest = inventory_sources(tmp_path, language="java")
    assert files == [tmp_path / "Example.java"]
    config.write_text("<project>changed</project>")
    assert inventory_sources(tmp_path, language="java")[1] != digest
    (tmp_path / "link.java").symlink_to(files[0])
    with pytest.raises(ValueError, match="symbolic links"):
        inventory_sources(tmp_path, language="java")


def test_provider_acceptance_requires_real_reads_and_issued_citations(tmp_path):
    def handler(payload):
        if payload["round"] == 1:
            return requests(("source_read", {"repository_id": "fixture", "path": "example.py"}))
        result = final([payload["tool_results"][0]["output"]["citation"]["citation_id"]])
        result["narrative"]["evidence_gaps"] = ["No runtime observation"]
        return result

    backend = ScriptedBackend(handler)
    report = check_provider(backend, tmp_path)
    assert report["passed"] and len(backend.calls) == 12
    assert not check_provider(ScriptedBackend(lambda _payload: final([])), tmp_path)["passed"]


def test_percentiles_do_not_imply_large_sample_evidence():
    summary = distribution([5, 1, 2, 4, 3])
    assert summary["median"] == 3 and summary["p95_nearest_rank"] == 5
    for invalid in ([], [math.nan], [0], [-1], [math.inf]):
        with pytest.raises(ValueError):
            distribution(invalid)


def _report():
    return {
        "analysis_status": "completed",
        "analysis_gaps": [],
        "outcomes_digest": "same",
        "source_digest": "source",
        "ground_truth_digest": "labels",
        "provenance": {"implementation": {"code": "frozen"}, "config_digest": "config"},
        "measurement": {"scan_seconds": 1, "peak_rss_self_bytes": 1234},
    }


def test_performance_rejects_changed_outcomes_and_retains_failed_sample(tmp_path, monkeypatch):
    calls = []

    class Process:
        def __init__(self, command, **kwargs):
            calls.append(command)
            report = _report()
            if len(calls) == 2:
                report["outcomes_digest"] = "changed"
            Path(command[-1]).write_text(json.dumps(report))

        def wait(self, timeout):
            return 0

    monkeypatch.setattr("aegify.quality.performance.subprocess.Popen", Process)
    report = measure("owned", tmp_path, tmp_path / "labels.json", repeats=3)
    assert not report["valid"] and report["statistics"] is None
    assert len(report["samples"]) == 2 and not report["samples"][1]["valid"]
    changed = _report()
    changed["ground_truth_digest"] = "different"
    assert identity(changed) != identity(_report())


def test_performance_timeout_kills_owned_group_and_never_reports_percentiles(tmp_path, monkeypatch):
    killed = []

    class Process:
        pid = 123456

        def __init__(self, *_args, **_kwargs):
            pass

        def wait(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired("owned worker", timeout)
            return -9

    monkeypatch.setattr("aegify.quality.performance.subprocess.Popen", Process)
    monkeypatch.setattr("aegify.quality.performance.os.killpg", lambda pid, sig: killed.append(pid))
    report = measure("owned", tmp_path, tmp_path / "labels.json", repeats=2, timeout=1)
    assert killed == [Process.pid]
    assert report["samples"][0]["timed_out"]
    assert not report["valid"] and report["statistics"] is None
