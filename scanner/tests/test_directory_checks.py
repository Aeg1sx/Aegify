"""Static source fixtures for directory decisions, aliases and negative controls."""

import textwrap

import pytest

from aegify.config import AegifyConfig
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_files import directory_checks


def module(imports, body):
    return (
        imports + "\nasync def accepts(base, item, other):\n" + textwrap.indent(body, "    ")
    ).encode()


@pytest.mark.parametrize(
    ("imports", "body", "api", "line", "end", "comparison"),
    [
        (
            "from os import path as fs",
            "root = fs.abspath(base)\nreturn root == fs.commonprefix([root, item])",
            "os.path.commonprefix",
            4,
            4,
            4,
        ),
        (
            "from posixpath import commonprefix as prefix, realpath",
            "root = realpath(base)\n"
            "paths = (root, item)\n"
            "shared = prefix(\n"
            "    paths\n"
            ")\n"
            "return root == shared",
            "posixpath.commonprefix",
            5,
            7,
            8,
        ),
        (
            "import ntpath as paths",
            "root = paths.normpath(base)\n"
            "if paths.commonprefix((root, item)) != root:\n"
            "    return False\n"
            "return True",
            "ntpath.commonprefix",
            4,
            4,
            4,
        ),
        (
            "from os.path import commonprefix, abspath",
            "return commonprefix([abspath(base), item]) == abspath(base)",
            "os.path.commonprefix",
            3,
            3,
            3,
        ),
        (
            "import os.path",
            "def check(name):\n"
            "    target = os.path.join(base, name)\n"
            "    return not (base != os.path.commonprefix([base, target]))\n"
            "return check(item)",
            "os.path.commonprefix",
            5,
            5,
            5,
        ),
    ],
)
def test_directory_prefix_decisions(imports, body, api, line, end, comparison):
    [check] = directory_checks(module(imports, body))
    assert (check.api, check.line, check.end_line, check.comparison_line) == (
        api,
        line,
        end,
        comparison,
    )


@pytest.mark.parametrize(
    "body",
    [
        "return fs.commonpath([fs.abspath(base), item]) == fs.abspath(base)",
        "return Path(item).resolve().is_relative_to(Path(base).resolve())",
        "return fs.commonprefix([base, item]) == base",
        "root = fs.abspath(base)\nreturn fs.commonprefix([root, item]) == other",
        "root = fs.abspath(base)\nprint(fs.commonprefix([root, item]) == root)",
        "root = fs.abspath(base)\nreturn fs.commonprefix([root, item]) is root",
        "root = fs.abspath(base)\n"
        "paths = [root, item]\n"
        "paths.append(other)\n"
        "return fs.commonprefix(paths) == root",
        "path = fs.abspath(item)\n"
        "shared = fs.commonprefix([base, path])\n"
        "base = other\n"
        "return shared == base",
        "root = fs.abspath(base)\n"
        "shared = fs.commonprefix((root, item))\n"
        "shared = other\n"
        "return shared == root",
        "root = other.build(base)\nreturn fs.commonprefix([root, item]) == root",
        "return fs.commonprefix([fs.abspath(other()), item]) == fs.abspath(other())",
        "fs = other\nroot = fs.abspath(base)\nreturn fs.commonprefix([root, item]) == root",
        "root = fs.abspath(base)\ncommonprefix = other\nreturn commonprefix([root, item]) == root",
    ],
)
def test_directory_prefix_controls(body):
    imports = (
        "from os import path as fs\nfrom os.path import commonprefix\nfrom pathlib import Path"
    )
    assert directory_checks(module(imports, body)) == []


def test_directory_prefix_scan_honors_rule_setting_and_reparses_changes(tmp_path):
    path = tmp_path / "paths.py"
    code = module(
        "from os import path as fs",
        "root = fs.abspath(base)\nreturn fs.commonprefix([root, item]) == root",
    )
    path.write_bytes(code)
    engine = ScanEngine()
    for _ in range(2):
        result = engine.scan_files(tmp_path, [path])
        [finding] = [f for f in result.findings if f.rule_id == "AEG-PATH-003"]
        assert (finding.line_start, finding.line_end) == (4, 4)
        assert finding.evidence_state.value == "candidate"
        assert finding.disposition.value == "advisory"
        assert finding.taint_flow is None
    config = AegifyConfig()
    config.rules.disabled_rules = ["AEG-PATH-003"]
    disabled = ScanEngine(config=config).scan_files(tmp_path, [path])
    assert "AEG-PATH-003" not in disabled.evaluated_rules
    assert all(f.rule_id != "AEG-PATH-003" for f in disabled.findings)
    path.write_bytes(code.replace(b"commonprefix", b"commonpath"))
    fixed = engine.scan_files(tmp_path, [path])
    assert "AEG-PATH-003" in fixed.evaluated_rules
    assert all(f.rule_id != "AEG-PATH-003" for f in fixed.findings)
