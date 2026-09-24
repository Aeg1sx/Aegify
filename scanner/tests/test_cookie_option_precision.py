"""Owned syntax fixtures, parsed as data without running application code."""

from pathlib import Path

import networkx as nx
import pytest
import yaml

from aegify.models import EvidenceState, FileAST, FindingDisposition
from aegify.rules.audit import audit_rules
from aegify.rules.call_options import BooleanOptionSpec
from aegify.rules.yaml_rule import PatternSpec, load_yaml_rules
from aegify.scanner.ast_parser import ASTParser

RULE_FILE = Path(__file__).parents[2] / "rules/a05-security-misconfiguration/misconfig.yml"
RULES = {
    rule.definition.id: rule
    for rule in load_yaml_rules(RULE_FILE)
    if rule.definition.id in {"AEG-A05-005", "AEG-A05-006"}
}


def parse(tmp_path, name, source):
    path = tmp_path / name
    path.write_text(source)
    ast = ASTParser().parse_file(path)
    assert ast is not None and ast.parse_error_count == 0
    return ast


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        ("safe.py", 'r.set_cookie("n", "v", secure=True, httponly=True)', set()),
        ("false.py", 'r.set_cookie("n", "v", secure=False, httponly=False)', {5, 6}),
        ("mixed.py", 'r.set_cookie("n", "v", secure=True, httponly=False)', {6}),
        ("missing.py", 'r.set_cookie("n", "v")', {5, 6}),
        ("text.py", 'r.set_cookie("secure=True httponly=True", "v")', {5, 6}),
        ("nested.py", 'r.set_cookie("n", "v", meta={"secure":True,"httponly":True})', {5, 6}),
        ("unpack.py", 'r.set_cookie("n", "v", **{"secure":True,"httponly":True})', set()),
        (
            "unpack_nested.py",
            'r.set_cookie("n", "v", **{**{"secure":False},"secure":True,"httponly":True})',
            set(),
        ),
        (
            "unpack_override.py",
            'r.set_cookie("n", "v", **{"secure":True,**options,"httponly":True})',
            {5},
        ),
        (
            "unpack_before.py",
            'r.set_cookie("n", "v", **{**options,"secure":True,"httponly":True})',
            set(),
        ),
        ("dynamic.py", 'r.set_cookie("n", "v", secure=enabled, httponly=enabled)', {5, 6}),
        ("unknown_unpack.py", 'r.set_cookie("n", "v", **options)', {5, 6}),
        ("constructor.py", 'Cookie(name="n", secure=True, httponly=True)', set()),
        ("callee.py", 'metadata.set_cookie_handler("n", "v")', set()),
        ("safe.js", 'res.cookie("n", "v", {secure:true,httpOnly:true});', set()),
        ("false.js", 'res.cookie("n", "v", {secure:false,httpOnly:false});', {5, 6}),
        ("missing.js", 'res.cookie("n", "v");', {5, 6}),
        ("nested.js", 'res.cookie("n", "v", {auth:{secure:true,httpOnly:true}});', {5, 6}),
        ("text.js", 'res.cookie("secure:true httpOnly:true", "v");', {5, 6}),
        ("other_argument.js", 'res.cookie({secure:true,httpOnly:true}, "v", {});', {5, 6}),
        ("duplicate.js", 'res.cookie("n", "v", {secure:true,secure:false,httpOnly:true});', {5}),
        (
            "duplicate_safe.js",
            'res.cookie("n", "v", {secure:false,secure:true,httpOnly:true});',
            set(),
        ),
        (
            "spread_before.js",
            'res.cookie("n", "v", {...options,secure:true,httpOnly:true});',
            set(),
        ),
        (
            "spread_after.js",
            'res.cookie("n", "v", {secure:true,httpOnly:true,...options});',
            {5, 6},
        ),
        ("spread_literal.js", 'res.cookie("n", "v", {...{secure:true,httpOnly:true}});', set()),
        ("computed.js", 'res.cookie("n", "v", {["secure"]:true,["httpOnly"]:true});', set()),
        (
            "escaped_key.js",
            r'res.cookie("n", "v", {"\u0073ecure":true,"httpOnly":true});',
            set(),
        ),
        (
            "computed_unknown.js",
            'res.cookie("n", "v", {secure:true,httpOnly:true,[name]:false});',
            {5, 6},
        ),
        ("shorthand.js", 'res.cookie("n", "v", {secure,httpOnly});', {5, 6}),
        (
            "comments.js",
            'res.cookie(/* name */ "n", /* value */ "v", '
            "/* options */ {secure:true,httpOnly:true});",
            set(),
        ),
        ("paren.ts", 'res.cookie("n", "v", ({secure:(true),httpOnly:(true)}));', set()),
        ("const.ts", 'res.cookie("n","v",{secure:true as const,httpOnly:true} as const)', set()),
        (
            "satisfies.ts",
            'res.cookie("n","v",({secure:true,httpOnly:true} satisfies Options))',
            set(),
        ),
        ("nonnull.ts", 'res.cookie("n","v",({secure:true,httpOnly:true})!)', set()),
        (
            "safe.tsx",
            'export const view = () => <p/>; res.cookie("n","v",{secure:true,httpOnly:true});',
            set(),
        ),
        ("getter.ts", 'res.cookie("n","v",{get secure(){return true},httpOnly:true});', {5}),
        (
            "variadic.ts",
            'context.setCookie({name:"a",secure:true,httpOnly:true},{name:"b",secure:false,httpOnly:true});',
            {5},
        ),
        (
            "variadic_safe.ts",
            'context.setCookie({name:"a",secure:true,httpOnly:true},{name:"b",secure:true,httpOnly:true});',
            set(),
        ),
        ("spread_args.ts", "res.cookie(...values,{secure:true,httpOnly:true});", {5, 6}),
        (
            "safe.go",
            "package fixture\nfunc f(){http.SetCookie(w,"
            '&http.Cookie{Name:"n",Secure:true,HttpOnly:true})}',
            set(),
        ),
        (
            "false.go",
            "package fixture\nfunc f(){http.SetCookie(w,"
            '&http.Cookie{Name:"n",Secure:false,HttpOnly:true})}',
            {5},
        ),
        (
            "missing.go",
            'package fixture\nfunc f(){http.SetCookie(w,&http.Cookie{Name:"n"})}',
            {5, 6},
        ),
        ("dynamic.go", "package fixture\nfunc f(){http.SetCookie(w,cookie)}", {5, 6}),
        ("review.java", "class CookieFixture{void f(){response.setCookie(cookie);}}", {5, 6}),
        ("servlet.java", "class CookieFixture{void f(){response.addCookie(cookie);}}", {5, 6}),
        ("callee.js", 'res.cookie_handler("n", "v");', set()),
    ],
)
def test_cookie_option_selection_and_close_negatives(tmp_path, name, source, expected):
    ast = parse(tmp_path, name, source)
    # Serialized ASTs must retain the exact option facts used by the evaluator.
    restored = FileAST.model_validate_json(ast.model_dump_json())
    for tree in [ast, restored]:
        found = []
        for rule in RULES.values():
            found.extend(rule.evaluate([tree], nx.DiGraph(), []))
        assert {int(item.rule_id[-3:]) for item in found} == expected
        assert all(
            item.evidence_state == EvidenceState.CANDIDATE
            and item.disposition == FindingDisposition.ADVISORY
            for item in found
        )
        if "dynamic" in name or "unknown" in name or "getter" in name:
            assert all("option state: unknown" in item.message for item in found)


def test_unknown_states_and_bounds_are_not_assumed_false_or_safe(tmp_path):
    samples = [
        ('res.cookie("n","v",{secure:true,...options})', "unknown"),
        ('res.cookie("n","v",{...options,secure:true})', "true"),
        ('res.cookie("n","v",{secure:false,other:{secure:true}})', "false"),
        ('res.cookie("n","v",{other:{secure:true}})', "missing"),
        (
            'res.cookie("n","v",{' + ",".join(f"p{i}:true" for i in range(140)) + ",secure:true})",
            "unknown",
        ),
    ]
    selector = BooleanOptionSpec.parse(
        {"name": "secure", "location": "argument", "argument": 2, "states": ["unknown"]}
    )
    for index, (source, state) in enumerate(samples):
        call = parse(tmp_path, f"case{index}.js", source).calls[0]
        assert selector.state(call) == state
        if call.structured_arguments[2].options is not None:
            assert len(call.structured_arguments[2].options) <= 129
    keyword = BooleanOptionSpec.parse(
        {"name": "secure", "location": "keyword", "states": ["unknown"]}
    )
    duplicate = parse(
        tmp_path, "duplicate.py", 'r.set_cookie("n","v",secure=True,**{"secure":False})'
    )
    assert keyword.state(duplicate.calls[0]) == "unknown"


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {},
        {"name": "secure", "location": "typo", "states": ["false"]},
        {"name": "secure", "location": "argument", "argument": True, "states": ["false"]},
        {"name": "secure", "location": "argument", "argument": 128, "states": ["false"]},
        {"name": "secure", "location": "keyword", "argument": 0, "states": ["false"]},
        {"name": "secure", "location": "keyword", "states": [False]},
        {"name": "secure", "location": "keyword", "states": ["typo"]},
        {"name": "secure", "location": "keyword", "states": ["false"], "ignored": True},
    ],
)
def test_invalid_boolean_option_never_becomes_an_unconstrained_rule(tmp_path, invalid):
    pattern = {"callee": "set_cookie", "boolean_option": invalid}
    with pytest.raises(ValueError):
        PatternSpec(pattern)
    path = tmp_path / "rule.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "TEST-OPTION",
                        "name": "Owned rule",
                        "severity": "medium",
                        "languages": ["python"],
                        "patterns": [pattern],
                    }
                ]
            }
        )
    )
    report = audit_rules(path)
    assert any(issue.code == "invalid-pattern" for issue in report.issues)
    assert not load_yaml_rules(path)


def test_boolean_option_requires_call_mode_and_old_call_models_stay_unknown():
    assert not PatternSpec(
        {
            "pattern_type": "regex",
            "match": "cookie",
            "boolean_option": {"name": "secure", "location": "keyword", "states": ["false"]},
        }
    ).is_executable
    # Legacy/persisted call models lack facts; they must remain unknown.
    from aegify.models import CallSite

    call = CallSite(
        callee="set_cookie", file_path="fixture.py", line=1, column=0, arguments=["secure=True"]
    )
    selector = BooleanOptionSpec.parse(
        {"name": "secure", "location": "keyword", "states": ["unknown"]}
    )
    assert selector.state(call) == "unknown"


def test_boolean_selector_can_report_missing_options_on_zero_argument_call(tmp_path):
    path = tmp_path / "defaults.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "AEG-TEST-DEFAULT",
                        "name": "Explicit default option review",
                        "severity": "low",
                        "languages": ["python"],
                        "patterns": [
                            {
                                "callee": "configure",
                                "callee_match_mode": "full",
                                "boolean_option": {
                                    "name": "enabled",
                                    "location": "keyword",
                                    "states": ["missing"],
                                },
                            }
                        ],
                        "message": "Default option state: {option_state}",
                    }
                ]
            }
        )
    )
    rule = load_yaml_rules(path)[0]
    findings = rule.evaluate([parse(tmp_path, "default.py", "configure()")], nx.DiGraph(), [])
    assert len(findings) == 1
    assert findings[0].message == "Default option state: missing"


def test_argument_extraction_changes_invalidate_cached_asts(tmp_path, monkeypatch):
    from aegify.scanner import ast_parser, call_arguments

    ast_parser.parser_fingerprint.cache_clear()
    original = ast_parser.parser_fingerprint()
    changed = tmp_path / "call_arguments.py"
    changed.write_text("# owned fingerprint fixture, not imported\n")
    with monkeypatch.context() as patch:
        patch.setattr(call_arguments, "__file__", str(changed))
        ast_parser.parser_fingerprint.cache_clear()
        assert ast_parser.parser_fingerprint() != original
    ast_parser.parser_fingerprint.cache_clear()
    assert ast_parser.parser_fingerprint() == original


def test_go_argument_order_and_comments_survive_ast_serialization(tmp_path):
    ast = parse(
        tmp_path,
        "args.go",
        "package fixture\nfunc f(){ review(first, /* ignored */ second, third) }",
    )
    assert ast.calls[0].arguments == ["first", "second", "third"]
    assert len(ast.calls[0].structured_arguments) == 3
    assert (
        FileAST.model_validate_json(ast.model_dump_json()).calls[0].arguments
        == ast.calls[0].arguments
    )
