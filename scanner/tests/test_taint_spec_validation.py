"""Previously ignored taint fields must not broaden a submitted rule."""

from pathlib import Path

import pytest
import yaml

from aegify.rules.audit import audit_rules
from aegify.rules.yaml_rule import TaintSpec, load_yaml_rules


@pytest.mark.parametrize(
    "taint",
    [
        None,
        False,
        [],
        "source",
        {},
        {"sources": [{"type": "http_param"}], "sinks": [{"type": "sql_query"}]},
        {"source_types": "http_param"},
        {"sink_types": [False]},
        {"sink_types": [" "]},
        {"sink_types": ["x" * 257]},
        {"sink_types": ["sql_query"] * 101},
        {"source_types": []},
        {"sink_pattern": ""},
        {"sink_pattern": False},
        {"sink_pattern": "("},
        {"sink_pattern": "x" * 4097},
        {"sink_pattern": "(" * 800},
        {"sink_types": ["sql_query"], "propagation": [{"through": "assignment"}]},
        {"sink_types": ["sql_query"], "ignore_sanitizers": "false"},
    ],
)
def test_invalid_taint_cannot_be_loaded_or_pass_strict_audit(tmp_path: Path, taint):
    data = {
        "id": "AEG-TAINT-VALIDATION",
        "name": "Test",
        "severity": "high",
        "languages": ["python"],
        "patterns": [{"callee": "review_target"}],
        "taint": taint,
    }
    path = tmp_path / "rule.yml"
    path.write_text(yaml.safe_dump(data))
    report = audit_rules(path)
    assert any(issue.code == "invalid-taint" for issue in report.issues)
    assert load_yaml_rules(path) == []  # no partial fallback to the otherwise valid pattern
    with pytest.raises(ValueError):
        TaintSpec(taint)


def test_supported_selector_compilation_and_sanitizer_flag():
    spec = TaintSpec(
        {
            "source_types": ["http_param"],
            "sink_types": ["sql_query"],
            "source_pattern": "value",
            "sink_pattern": "(?i:execute|query)",
            "ignore_sanitizers": False,
        }
    )
    assert spec._sink_pattern_re is not None
    assert spec._sink_pattern_re.search("cursor.EXECUTE")
    assert spec._source_types_set == {"http_param"}
    assert spec.ignore_sanitizers is False


def test_dashboard_taint_template_passes_actual_audit(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    page = (root / "dashboard/src/app/rules/new/page.tsx").read_text()
    template = page.split("const YAML_TEMPLATE = `", 1)[1].split("`;", 1)[0]
    rule = yaml.safe_load(template)
    rule.pop("patterns")
    block = template.split("# taint:\n", 1)[1].split("\n\n", 1)[0]
    rule["taint"] = yaml.safe_load(
        "taint:\n" + "\n".join(line.removeprefix("# ") for line in block.splitlines())
    )["taint"]
    path = tmp_path / "template.yml"
    path.write_text(yaml.safe_dump(rule))
    report = audit_rules(path)
    assert report.errors == report.warnings == 0
    parsed = load_yaml_rules(path)
    assert len(parsed) == 1 and parsed[0].spec.taint is not None
    assert parsed[0].spec.taint._source_types_set == {"http_param", "http_body"}
    assert parsed[0].spec.taint._sink_types_set == {"sql_query"}


@pytest.mark.parametrize("mode", ["scan", "files", "workspace"])
def test_invalid_custom_rules_cannot_produce_complete_analysis(tmp_path: Path, mode):
    from aegify.models import ScanStatus
    from aegify.scanner.engine import ScanEngine
    from aegify.worker import worker_config

    source = tmp_path / "main.py"
    source.write_text("def noop():\n    return 1\n")
    rule = tmp_path / "custom.yml"
    rule.write_text(
        "id: AEG-CUSTOM-LOAD-CONTROL\nlanguages: [python]\n"
        "taint:\n  sources: [{type: http_param}]\n"
    )
    config = worker_config()
    config.rules.custom_rules = str(rule)
    engine = ScanEngine(config=config)
    if mode == "workspace":
        manifest = tmp_path / "workspace.yml"
        manifest.write_text(
            "version: 1\nname: owned-workspace\nrepositories:\n  - id: owned\n    path: .\n"
        )
        result = engine.scan_workspace(manifest)
    elif mode == "files":
        result = engine.scan_files(tmp_path, [source])
    else:
        result = engine.scan(source)
    assert result.status == ScanStatus.PARTIAL
    assert any(gap.code == "custom_rule_load_failed" for gap in result.analysis_gaps)


def test_real_scan_cli_exits_partial_when_custom_rules_fail_audit(tmp_path: Path):
    import json

    from typer.testing import CliRunner

    from aegify.cli import app

    source = tmp_path / "main.py"
    source.write_text("def noop():\n    return 1\n")
    rule = tmp_path / "custom.yml"
    rule.write_text("id: AEG-CUSTOM-LOAD-CONTROL\nlanguages: [python]\ntaint: {}\n")
    config = tmp_path / "config.yml"
    config.write_text(yaml.safe_dump({"rules": {"custom_rules": str(rule)}}))
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(source),
            "--config",
            str(config),
            "--output",
            "json",
            "--output-file",
            str(output),
            "--no-llm",
        ],
    )
    assert result.exit_code == 3, result.output
    assert json.loads(output.read_text())["status"] == "partial"
