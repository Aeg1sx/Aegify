"""Contrast local file selection, unbound fields, and actual request-to-path flows."""

from pathlib import Path
from textwrap import dedent

from aegify.config import AegifyConfig
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine


def _paths(root: Path, source: str):
    path = root / "reader.py"
    path.write_text(dedent(source).lstrip())
    config = AegifyConfig()
    config.scan.max_workers = 1
    scan = ScanEngine(config=config).scan_files(root, [path])
    assert scan.status == "completed"
    return [item for item in scan.findings if item.rule_id == "AEG-PATH-001"]


def test_stdin_requires_a_bound_call_and_ignores_literal_words(tmp_path: Path):
    findings = _paths(
        tmp_path,
        """
        from builtins import input as ask
        def ordinary():
            with context():
                message = "complete counters need both input and output"
                label = "input()"
                return open(message)
        def actual():
            value = ask()
            return open(value)
        def shadowed(input):
            value = input()
            return open(value)
        def member(obj):
            value = obj.input()
            return open(value)
    """,
    )
    assert [(f.line_start, f.taint_flow.source.source_type) for f in findings] == [(9, "stdin")]
    ast = ASTParser().parse_file(tmp_path / "reader.py")
    assert [
        (call.callee, call.line) for call in ast.calls if call.resolved_source == "builtins.input"
    ] == [("ask", 8)]


def test_only_direct_cli_path_or_fixed_sibling_is_annotated(tmp_path: Path):
    findings = _paths(
        tmp_path,
        """
        from pathlib import Path
        import sys
        def convert():
            selected = Path(sys.argv[1])
            selected.read_text()
            selected.with_name("summary.txt").write_text("summary")
            (Path("catalog") / sys.argv[1]).read_text()
            selected.with_name(sys.argv[2]).read_text()
        def secondary():
            Path(sys.argv[1]).read_text()
        if __name__ == "__main__":
            raise SystemExit(convert())
    """,
    )
    by_line = {f.line_start: f for f in findings}
    assert set(by_line) == {5, 6, 7, 8, 10}
    for line in (5, 6):
        assert not by_line[line].blocks_ci
        assert by_line[line].evidence_state == "reachable"
        assert "caller" in by_line[line].message
    assert all(by_line[line].blocks_ci for line in (7, 8, 10))


def test_remote_caller_path_remains_blocking_across_package_helper(tmp_path: Path):
    (tmp_path / "storage.py").write_text(
        "from pathlib import Path\n"
        "def load_document(name):\n"
        '    return (Path("documents") / name).read_text()\n'
    )
    path = tmp_path / "routes.py"
    path.write_text(
        "from flask import request\nfrom storage import load_document\n"
        'def handler():\n    return load_document(request.args.get("document"))\n'
    )
    config = AegifyConfig()
    config.scan.max_workers = 1
    scan = ScanEngine(config=config).scan(tmp_path)
    selected = [f for f in scan.findings if f.rule_id == "AEG-PATH-001"]
    assert len(selected) == 1
    [finding] = selected
    assert finding.blocks_ci and finding.evidence_state == "reachable"
    assert finding.line_start == 3 and Path(finding.file_path).name == "storage.py"
    assert finding.taint_flow.source.source_type == "http_param"
    assert Path(finding.taint_flow.source.file_path).name == "routes.py"


def test_environment_field_summary_and_proven_operand_are_distinct(tmp_path: Path):
    findings = _paths(
        tmp_path,
        """
        import os
        from vendor import Options
        def opaque():
            options = Options(os.environ.get("CONFIG_VALUE"))
            return open(options.document)
        def explicit():
            options = Options()
            options.document = os.environ.get("DOCUMENT_NAME")
            return open(options.document)
        def direct():
            return open(os.environ.get("DOCUMENT_NAME"))
    """,
    )
    by_line = {f.line_start: f for f in findings}
    assert set(by_line) == {5, 9, 11}
    assert by_line[5].evidence_state == "candidate" and not by_line[5].blocks_ci
    assert "could not bind" in by_line[5].message
    assert by_line[9].blocks_ci and by_line[11].blocks_ci
    assert "field-store" in {s.propagation_type for s in by_line[9].taint_flow.path}
