"""Check literal syntax with CPython and source locations with an installed Aegify CLI."""

from __future__ import annotations

import argparse
import ast
import hashlib
import itertools
import json
import platform
import subprocess
import tempfile
import warnings
from pathlib import Path
from textwrap import indent

GUARD = """text.startswith("'") and text.endswith("'") and "'" not in text[1:-1]"""
HEADER = (
    "import builtins as runtime\n"
    "from builtins import eval as read_expression\n"
    "from flask import request\n"
    "def inspect_input():\n"
    '    text = request.args.get("expression", "")\n'
)
CODE = "AEG-EXEC-001"
PATH = "AEG-PATH-001"
# Each expected rule belongs on the last statement. An empty set expects neither rule.
CASES = {
    "bare": ("return eval(text)", {CODE}),
    "module_alias": ("return runtime.exec(text)", {CODE}),
    "imported_alias": ("return read_expression(text)", {CODE}),
    "assigned_alias": ("interpret = runtime.eval\nreturn interpret(text)", {CODE}),
    "whole_literal": (f"if {GUARD}:\n    return eval(text)", set()),
    "indexed_edges": (
        """if text[0] == '"' and text[-1] == '"' and '"' not in text[1:-1]:\n    exec(text)""",
        set(),
    ),
    "missing_interior_check": (
        """if text.startswith("'") and text.endswith("'"):\n    return eval(text)""",
        {CODE},
    ),
    "different_operand": (
        f"""if {GUARD}:\n    other = request.args.get("other", "")\n    return eval(other)""",
        {CODE},
    ),
    "new_assignment": (
        f"""if {GUARD}:\n    text = request.args.get("other", "")\n    return exec(text)""",
        {CODE},
    ),
    "complete_representation": ("return eval(repr(text))", set()),
    "representation_plus_input": ("return eval(repr(text) + text)", {CODE}),
    "file_after_code_guard": (f"if {GUARD}:\n    return open(text)", {PATH}),
    "data_in_namespace": ('return eval("1 + 2", {}, {"note": text})', set()),
}


def grammar_reference() -> dict:
    alphabet = ("a", "1", "'", '"', "+", " ", "#", "\\", "\n", "雪")
    guarded = literals = invalid = representations = 0
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        for width in range(5):
            for parts in itertools.product(alphabet, repeat=width):
                value = "".join(parts)
                result = ast.parse(repr(value), mode="eval").body
                assert isinstance(result, ast.Constant) and result.value == value
                representations += 1
                for quote in ('"', "'"):
                    source = quote + value + quote
                    if quote in value:
                        continue
                    guarded += 1
                    try:
                        expr = ast.parse(source, mode="eval").body
                    except SyntaxError:
                        try:
                            ast.parse(source, mode="exec")
                        except SyntaxError:
                            invalid += 1
                            continue
                        raise AssertionError("exec accepted a source rejected by eval")
                    (stmt,) = ast.parse(source, mode="exec").body
                    assert isinstance(stmt, ast.Expr) and ast.dump(stmt.value) == ast.dump(expr)
                    assert isinstance(expr, ast.Constant) and type(expr.value) is str
                    literals += 1
    assert isinstance(ast.parse("1 + 2", mode="eval").body, ast.BinOp)
    assert literals + invalid == guarded and min(literals, invalid) > 0
    return dict(
        python=platform.python_version(),
        matching_inputs=guarded,
        single_strings=literals,
        syntax_errors=invalid,
        repr_round_trips=representations,
    )


def check_scanner(cli: Path) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="aegify-code-input-") as temp:
        root = Path(temp)
        sources = root / "inputs"
        sources.mkdir()
        cases = {}
        for name, (body, rules) in CASES.items():
            text = HEADER + indent(body, "    ") + "\n"
            (sources / (name + ".py")).write_text(text, encoding="utf-8")
            cases[name] = {
                "case": name,
                "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "expected": sorted([rule, len(text.splitlines())] for rule in rules),
                "observed": [],
            }
        sarif = root / "scan.sarif"
        process = subprocess.run(
            [str(cli), "scan", str(sources), "--no-llm", "-o", "sarif", "-f", str(sarif)],
            cwd=root,
            capture_output=True,
        )
        if process.returncode not in (0, 1) or not sarif.is_file():
            raise RuntimeError(
                f"Scanner failed with exit {process.returncode}: {process.stderr[-500:]!r}"
            )
        (run,) = json.loads(sarif.read_text())["runs"]
        (invocation,) = run["invocations"]
        coverage = invocation["properties"]
        assert invocation["executionSuccessful"] and coverage["analysisStatus"] == "completed"
        assert coverage["filesScanned"] == len(CASES) and not coverage["analysisGaps"]
        assert coverage["tokenUsage"]["calls_started"] == 0
        for result in run["results"]:
            if result["ruleId"] not in {CODE, PATH}:
                continue
            loc = result["locations"][0]["physicalLocation"]
            name = Path(loc["artifactLocation"]["uri"]).stem
            cases[name]["observed"].append([result["ruleId"], loc["region"]["startLine"]])
        for case in cases.values():
            case["observed"].sort()
            case["agrees"] = case["expected"] == case["observed"]
        return list(cases.values())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", type=Path, help="Path to the installed aegify CLI")
    args = parser.parse_args()
    rows = check_scanner(args.scanner.resolve())
    print(json.dumps({"grammar_reference": grammar_reference(), "cases": rows}, indent=2))
    raise SystemExit(0 if all(row["agrees"] for row in rows) else 1)
