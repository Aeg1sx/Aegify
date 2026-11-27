from textwrap import dedent

import pytest

from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_files import post_read_limits


@pytest.mark.parametrize(
    "source, flagged",
    [
        ("value = path.read_bytes()\nif len(value) > limit: raise ValueError()", True),
        ("value: str = path.read_text()\nif limit <= len(value): return None", True),
        ("value = file.read(limit + 1)\nif len(value) > limit: raise ValueError()", False),
        ("value = path.read_bytes()\nif len(other) > limit: return None", False),
        ("value = path.read_bytes()\nif len(value) < limit: return None", False),
        ("len = measure\nvalue = path.read_bytes()\nif len(value) > limit: return None", False),
        (
            "if allow:\n    value = path.read_bytes()\n"
            "else:\n    if len(value) > limit: return None",
            False,
        ),
        (
            "value = path.read_bytes()\nvalue = replacement\nif len(value) > limit: return None",
            False,
        ),
        ("value = path.read_bytes()\nif len(value) > limit: record_metric()", False),
    ],
)
def test_reader_and_guard_must_act_on_the_same_value_in_order(source, flagged):
    code = "def load(path, limit):\n" + "\n".join("    " + line for line in source.splitlines())
    assert len(post_read_limits(code.encode())) == int(flagged)


def test_resource_advisory_and_bounded_repair_through_engine(tmp_path):
    file = tmp_path / "reader.py"
    original = dedent("""\
        def load(path, limit):
            payload = path.read_bytes()
            if len(payload) > limit:
                raise ValueError("Too large")
            return payload
    """)
    repaired = original.replace(
        "payload = path.read_bytes()",
        'with path.open("rb") as stream:\n        payload = stream.read(limit + 1)',
    )
    engine = ScanEngine()
    for code, expected in [(original, [(2, 400, "advisory")]), (repaired, [])]:
        file.write_text(code)
        result = engine.scan_files(tmp_path, [file])
        assert result.status == "completed" and "AEG-IO-001" in result.evaluated_rules
        assert [
            (f.line_start, f.cwe_id, f.disposition.value)
            for f in result.findings
            if f.rule_id == "AEG-IO-001"
        ] == expected
