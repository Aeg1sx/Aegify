"""Static subprocess operand controls for the general command-injection rule."""

from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import EvidenceState, FindingDisposition
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_process import process_calls

ARGV = (
    "['git', 'diff', '--name-only', '-z', '--diff-filter=ACMR', '--no-ext-diff', "
    "'--no-textconv', '--end-of-options', revision, 'HEAD', '--']"
)


def fact(command):
    source = f"import subprocess as sp\ndef inspect(revision, other):\n    {command}\n"
    return next(iter(process_calls(source.encode()).values()))


@pytest.mark.parametrize(
    "command",
    [
        f"sp.run({ARGV})",
        f"sp.run(args={ARGV}, shell=False, text=True, capture_output=True)",
        f"sp.run({ARGV.replace('[', '(').replace(']', ')')}, timeout=3)",
    ],
)
def test_revision_operands_have_separate_boundaries(command):
    assert fact(command).git_diff_revision_only


@pytest.mark.parametrize(
    "command",
    [
        f"sp.run({ARGV}, shell=True)",
        f"sp.run({ARGV}, shell=other)",
        f"sp.run({ARGV}, executable=other)",
        f"sp.run({ARGV}, env=other)",
        f"sp.run({ARGV}, cwd=revision)",
        f"sp.run({ARGV}, cwd=revision.directory)",
        f"sp.run({ARGV}, cwd=other)",
        f"sp.run({ARGV}, capture_output=other)",
        f"sp.run({ARGV}, **other)",
        "sp.run(" + ARGV.replace("'git'", "other") + ")",
        "sp.run(" + ARGV.replace("'diff'", "other") + ")",
        "sp.run(" + ARGV.replace("'-z'", "other") + ")",
        "sp.run(" + ARGV.replace("'-z'", "'--ext-diff'") + ")",
        "sp.run(" + ARGV.replace("'-z'", "'--textconv'") + ")",
        "sp.run(" + ARGV.replace("'-z'", "'--no-index'") + ")",
        "sp.run(" + ARGV.replace("'--no-ext-diff', ", "") + ")",
        "sp.run(" + ARGV.replace("'--no-textconv', ", "") + ")",
        "sp.run(" + ARGV.replace("'--end-of-options', ", "") + ")",
        "sp.run(" + ARGV.replace(", '--']", "]") + ")",
        "sp.run(" + ARGV.replace("revision, 'HEAD', '--'", "'HEAD', '--', revision") + ")",
        "sp.run(" + ARGV.replace("revision,", "*revision,") + ")",
        "sp.run(revision)",
    ],
)
def test_unknown_launch_options_keep_the_generic_command_gate(command):
    assert not fact(command).git_diff_revision_only


@pytest.mark.parametrize(
    ("command", "advisory"),
    [
        (f"sp.run({ARGV})", True),
        ("sp.run(" + ARGV.replace("'--end-of-options', ", "") + ")", False),
        (f"sp.run({ARGV}); sp.run(revision)", False),
        (f"sp.run({ARGV}, shell=shell)", False),
        ("sp.run(['sh', '-c', revision])", False),
    ],
)
def test_report_retains_revision_taint_and_other_command_findings(
    tmp_path: Path, command: str, advisory: bool
):
    source = tmp_path / "review.py"
    source.write_text(
        "import subprocess as sp\nfrom flask import request\ndef show(shell):\n"
        "    revision = request.args.get('version')\n"
        f"    {command}\n"
    )
    scan = ScanEngine(
        config=AegifyConfig.model_validate(
            {"storage": {"backend": "memory"}, "llm": {"enabled": False}}
        )
    ).scan_files(tmp_path, [source])
    (finding,) = [f for f in scan.findings if f.rule_id == "AEG-CMD-001"]
    assert finding.taint_flow and finding.taint_flow.source.line == 4
    assert finding.evidence_state == EvidenceState.REACHABLE
    assert finding.blocks_ci is not advisory
    assert (finding.disposition == FindingDisposition.ADVISORY) is advisory
    assert ("revision operand" in finding.message) is advisory
