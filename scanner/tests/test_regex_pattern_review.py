"""Check pattern provenance through the normal multi-file scanner."""

from pathlib import Path

import pytest

from aegify.config import AegifyConfig
from aegify.models import FileAST
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_regex import regex_operand
from aegify.scanner.python_scope import PythonModules

RULE = "AEG-A03-011"
RULES = Path(__file__).resolve().parents[2] / "rules/a03-injection/injection.yml"


def scan(root: Path, files: dict[str, str]) -> list[tuple[str, int, str]]:
    for filename, source in files.items():
        (root / filename).write_text(source)
    config = AegifyConfig()
    config.llm.enabled = False
    config.rules.custom_rules = str(RULES)
    findings = ScanEngine(config=config).scan(root).findings
    return sorted(
        (Path(f.file_path).name, f.line_start, f.disposition.value)
        for f in findings
        if f.rule_id == RULE
    )


@pytest.mark.parametrize(
    ("expression", "alert"),
    [
        ("rx.search(string='subject', pattern=q)", True),
        ("rx.fullmatch(q, '')", True),
        ("rx.finditer(pattern=q, string='')", True),
        ("rx.subn(pattern=q, repl='', string='')", True),
        ("rx.split(q, '')", True),
        ("rx.compile(f'key{q}')", True),
        ("rx.search('query+', q)", False),
        ("rx.subn(pattern='word', repl=q, string=q)", False),
        ("rx.compile('fixed', flags=q)", False),
        ("rx.compile(pattern=rx.escape(q))", False),
        ("rx.compile(rx.escape(pattern=q))", False),
        ("rx.search('^' + escaped + '$', '')", False),
        ("rx.compile(escaped + q)", True),
        ("rx.compile(q + escaped)", True),
        ("rx.compile(rx.escape(convert(q)))", True),
    ],
)
def test_python_pattern_operand(tmp_path: Path, expression: str, alert: bool):
    source = (
        "import re as rx\nfrom flask import request\n"
        "def view():\n    q = request.args['q']\n    escaped = rx.escape(q)\n"
        f"    return {expression}\n"
    )
    assert scan(tmp_path, {"app.py": source}) == ([("app.py", 6, "blocking")] if alert else [])


def test_keyword_name_cannot_introduce_argument_taint(tmp_path: Path):
    source = (
        "import re\nfrom flask import request\n"
        "def view(configured):\n    pattern = request.args['pattern']\n"
        "    return re.search(string=pattern, pattern=configured)\n"
    )
    assert scan(tmp_path, {"app.py": source}) == []


def test_python_cross_file_regex_binding(tmp_path: Path):
    files = {
        "app.py": (
            "from flask import request\nfrom matcher import find\ndef view():\n"
            "    return find(request.args['q'])\n"
        ),
        "matcher.py": (
            "from re import findall as lookup\ndef find(value):\n"
            "    return lookup(string='text', pattern=value)\n"
        ),
    }
    assert scan(tmp_path, files) == [("matcher.py", 3, "blocking")]
    assert scan(tmp_path, {"re.py": "def findall(pattern, string):\n    return pattern\n"}) == []


@pytest.mark.parametrize("change", ["", "rx.escape = transform", "rx = local_module"])
def test_escape_and_matcher_rebinding(tmp_path: Path, change: str):
    source = (
        "import re as rx\nfrom flask import request\n" + change + "\n"
        "def view():\n    q = request.args.get('q')\n    return rx.compile(rx.escape(q))\n"
    )
    expected = [("app.py", 6, "blocking")] if change == "rx.escape = transform" else []
    assert scan(tmp_path, {"app.py": source}) == expected


def test_custom_request_storage_keeps_pattern_for_review(tmp_path: Path):
    source = (
        "import re\nfrom flask import request\ndef view():\n"
        "    return re.search(re.escape(request.args['q']), '')\n"
    )
    assert scan(
        tmp_path, {"app.py": source, "config.py": "app.request_class = CustomRequest\n"}
    ) == [("app.py", 4, "blocking")]


@pytest.mark.parametrize("suffix", ["js", "ts"])
@pytest.mark.parametrize(
    ("expression", "alert"),
    [
        ("new RegExp(/* pattern */ req.query.q)", True),
        ("RegExp(req.query.q)", True),
        ("new globalThis.RegExp(req.query.q)", True),
        ("RegExp(`tag${req.query.q}`)", True),
        ("new RegExp('req.query.q+', req.query.flags)", False),
        ("RegExp.escape(req.query.q)", False),
        ("new RegExp(RegExp.escape(req.query.q))", False),
        ("new RegExp(RegExp.escape(req.query.q) + req.query.more)", True),
        ("client.RegExp(req.query.q)", False),
    ],
)
def test_javascript_pattern_operand(tmp_path: Path, suffix: str, expression: str, alert: bool):
    file = "app." + suffix
    assert scan(tmp_path, {file: "function view(req) {\n  return " + expression + ";\n}"}) == (
        [(file, 2, "blocking")] if alert else []
    )


def test_js_constructor_shadow_is_local(tmp_path: Path):
    src = (
        "function local(req, RegExp) {\n return new RegExp(req.query.q);\n}\n"
        "function builtin(req) {\n return new RegExp(req.query.q);\n}\n"
    )
    assert scan(tmp_path, {"app.js": src}) == [("app.js", 5, "blocking")]


def test_typescript_annotation_does_not_hide_runtime_constructor(tmp_path: Path):
    src = "function run(req, matcher: RegExp) {\n return new RegExp(req.query.q);\n}\n"
    assert scan(tmp_path, {"app.ts": src}) == [("app.ts", 2, "blocking")]


def test_replaced_global_constructor_is_not_a_native_sink(tmp_path: Path):
    src = (
        "globalThis.RegExp = localFactory;\nfunction run(req) {\n"
        " return new RegExp(req.query.q);\n}\n"
    )
    assert scan(tmp_path, {"app.js": src}) == []


def test_javascript_mutated_escape_remains_visible(tmp_path: Path):
    src = (
        "RegExp.escape = identity;\nfunction matcher(req) {\n"
        " return RegExp(RegExp.escape(req.query.q));\n}\n"
    )
    assert scan(tmp_path, {"app.js": src}) == [("app.js", 3, "blocking")]


def test_go_standard_regexp_excludes_backtracking_finding(tmp_path: Path):
    source = (
        'package api\nimport "regexp"\nimport "net/http"\n'
        'func view(r *http.Request) {\n form := r.FormValue("q")\n regexp.Compile(form)\n}\n'
    )
    assert scan(tmp_path, {"app.go": source}) == []


def test_regex_facts_survive_snapshot_and_preserve_old_positions(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text("import re\nre.search(string=subject, pattern=expression)\n")
    file = ASTParser().parse_file(path, repository_root=tmp_path)
    assert file is not None
    saved = FileAST.model_validate_json(file.model_dump_json())
    assert regex_operand(saved.calls[0], saved, PythonModules([saved])) == ("re.search", 1)
    saved.python_regex_resolved = False
    saved.calls[0].python_regex_pattern = None
    assert regex_operand(saved.calls[0], saved, PythonModules([saved])) == ("re.search", 1)


@pytest.mark.parametrize(
    ("regex", "replacement", "disposition"),
    [
        (r"/[\x00-\x7f]/g", r"'\\$&'", "advisory"),
        (r"/[\x00-\x7f]/g", r"c => '\\' + c", "advisory"),
        (
            r"/[\x00-\x7f]/g",
            r"c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')",
            "advisory",
        ),
        (r"/[\x00-\x7f]/", r"'\\$&'", "blocking"),
        (r"/[\x40-\x7f]/g", r"'\\$&'", "blocking"),
        (r"/[.]/g", r"'\\$&'", "blocking"),
        (r"/[^\x00-\x7f]/g", r"'\\$&'", "blocking"),
        (r"/[\x00-\x7f]/g", r"c => '\\' + req.query.extra", "blocking"),
        (r"/[\x00-\x7f]/g", r"c => '\\x' + c", "blocking"),
        (r"/[\x00-\x7f]/g", r"'$&'", "blocking"),
    ],
)
def test_replacement_requires_global_coverage_and_matched_text(
    tmp_path, regex, replacement, disposition
):
    source = (
        "function transform(value) {\n"
        f"  return value.replace({regex}, {replacement});\n"
        "}\nfunction handler(req) {\n"
        "  return RegExp(transform(req.query.term));\n}\n"
    )
    assert scan(tmp_path, {"api.js": source}) == [("api.js", 5, disposition)]


def test_replacement_review_only_applies_to_the_complete_pattern(tmp_path):
    source = r"""function handler(req) {
  let term = req.query.term.replace(/[\x00-\x7f]/g, '\\$&');
  RegExp(term);
  RegExp(term + req.query.more);
  term = req.query.raw;
  RegExp(term);
}
"""
    assert scan(tmp_path, {"api.js": source}) == [
        ("api.js", 3, "advisory"),
        ("api.js", 4, "blocking"),
        ("api.js", 6, "blocking"),
    ]


def test_following_raw_operand_on_same_line_remains_blocking(tmp_path):
    source = r"""function handler(req) {
  const input = req.query.term;
  RegExp(input.replace(/[\x00-\x7f]/g, '\\$&')); RegExp(input);
}
"""
    assert scan(tmp_path, {"api.js": source}) == [("api.js", 3, "blocking")]
