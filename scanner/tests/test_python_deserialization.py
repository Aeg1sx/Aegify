"""Source-only reader and loader controls. Fixture applications are never executed."""

from textwrap import dedent, indent

import networkx as nx
import pytest

from aegify.config import AegifyConfig
from aegify.models import CallSite, FileAST, FindingDisposition, Language
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.engine import ScanEngine
from aegify.scanner.python_deserialization import decode_calls, reader, sink_operand
from tests.test_python_xml import PACKS
from tests.test_taint_value_identity import _flows


def sample(body):
    return (
        "import pickle as p\nimport yaml as y\nfrom flask import request\n"
        "def review(data, options, other):\n" + indent(dedent(body).strip(), "    ") + "\n"
    )


def facts(body):
    return list(decode_calls(sample(body).encode())[0].values())


@pytest.mark.parametrize(
    ("expression", "api", "mode", "index"),
    [
        ("p.loads(data=request.args.get('entry'))", "pickle.loads", "pickle", 0),
        ("p.load(file=data)", "pickle.load", "pickle", 0),
        ("y.load(Loader=y.Loader, stream=data)", "yaml.load", "object", 1),
        ("y.load(data, y.CSafeLoader)", "yaml.load", "restricted", 0),
        ("y.safe_load(data)", "yaml.safe_load", "restricted", 0),
        ("y.full_load(data)", "yaml.full_load", "full", 0),
        ("y.unsafe_load(data)", "yaml.unsafe_load", "object", 0),
        ("y.load(data)", "yaml.load", "unknown", 0),
        ("y.load(data, Loader=other.SafeLoader)", "yaml.load", "unknown", 0),
        ("y.load(**options)", "yaml.load", "unknown", None),
        ("p.loads(*options)", "pickle.loads", "pickle", None),
        ("y.load(Loader=data, stream='record')", "yaml.load", "unknown", 1),
    ],
)
def test_imported_reader_binds_its_actual_input(expression, api, mode, index):
    (fact,) = facts(expression)
    assert (fact.api, fact.mode, fact.argument_index) == (api, mode, index)


def test_loader_aliases_and_shadowed_reader():
    (fact,) = facts(
        "from yaml.loader import SafeLoader as Safe\nloader = Safe\ny.load(data, loader)"
    )
    assert fact.mode == "restricted"
    assert not facts("p = other\np.loads(data)\nother.yaml.load(data)")


@pytest.mark.parametrize(
    ("body", "passive"),
    [
        (r"return p.loads(b'\x80\x04K\x07.')", True),
        ("return p.loads(b'')", True),
        (r"return p.loads(b'\x80')", False),
        (r"return p.loads(b'N.', encoding=other)", False),
        ("return y.unsafe_load('ledger: ready')", True),
        ("return y.unsafe_load('!record ready')", False),
        ("return y.unsafe_load(data)", False),
        ("from io import BytesIO\nreturn p.load(BytesIO(b'N.'))", True),
        ("from io import BytesIO\ns = BytesIO(b'N.')\ns.write(data)\nreturn p.load(s)", False),
        ("import base64 as b\nreturn p.loads(b.b64decode('Ti4='))", True),
        ("import base64 as b\nreturn p.loads(b.b64decode(data))", False),
        ("v = ['a', data]\nreturn y.unsafe_load(v[0])", True),
        ("v = ['a', data]\nreturn y.unsafe_load(v[1])", False),
        ("v = ''\nif options:\n    v = data\nreturn y.unsafe_load(v)", False),
        ("if options:\n    v = 'yes'\nelse:\n    v = 'no'\nreturn y.unsafe_load(v)", True),
        ("v = ''\nv += 'known'\nreturn y.unsafe_load(v)", True),
        ("v = ''\nv += data\nreturn y.unsafe_load(v)", False),
        ("v = ''\nif options: v = data; return y.unsafe_load(v)", False),
        ("n = 4\nreturn y.unsafe_load('local' if n * 3 > 9 else data)", True),
        ("n = data\nreturn y.unsafe_load('local' if n * 3 > 9 else data)", False),
        (
            "choice = 'a'\nmatch choice:\n    case 'a': v = 'ok'\n"
            "    case _: v = data\nreturn y.unsafe_load(v)",
            True,
        ),
        (
            "choice = data\nmatch choice:\n    case 'a': v = 'ok'\n"
            "    case _: v = data\nreturn y.unsafe_load(v)",
            False,
        ),
    ],
)
def test_only_bounded_fixed_values_are_passive(body, passive):
    (fact,) = facts(body)
    assert fact.passive_input is passive


@pytest.mark.parametrize("prefix", [b"N", b"K\x07", b"J\x02\x00\x00\x00", b"\x80\x04K\x07"])
def test_fixed_width_reader_stops_at_the_disassembled_boundary(prefix):
    import pickletools
    from io import BytesIO

    # Disassembly only. Both EOF and the unrecognized byte occur after these plain data opcodes.
    for suffix in (b"", b"?"):
        stream = BytesIO(prefix + suffix)
        with pytest.raises(ValueError):
            list(pickletools.genops(stream))
        assert stream.tell() == len(prefix + suffix)
        assert facts(f"return p.loads({prefix + suffix!r})")[0].passive_input
    # A buffer request or a truncated variable-length operand remains reviewable.
    for suffix in (b"\x97.", b"\x8c\x05ab"):
        assert not facts(f"return p.loads({prefix + suffix!r})")[0].passive_input


@pytest.mark.parametrize(
    ("expression", "deferred"),
    [
        ("list(y.unsafe_load_all(data))", False),
        ("return y.unsafe_load_all(data)", True),
        ("for entry in y.unsafe_load_all(data):\n    print(entry)", False),
        ("list = other\nlist(y.unsafe_load_all(data))", True),
    ],
)
def test_yaml_iterator_consumption(expression, deferred):
    (fact,) = facts(expression)
    assert fact.deferred is deferred
    assert not facts("y.unsafe_load_all(data)")


@pytest.mark.parametrize(
    ("body", "extension"),
    [
        ("y.SafeLoader.add_constructor('!record', other)", ["SafeLoader"]),
        (
            "from yaml import add_constructor as register\nregister('!x', other, y.SafeLoader)",
            ["SafeLoader"],
        ),
        ("y.add_multi_constructor('!x', other)", ["FullLoader", "Loader", "UnsafeLoader"]),
        ("y.add_constructor('!x', other, **options)", ["*"]),
        ("y.add_implicit_resolver('!x', other, None, y.CSafeLoader)", ["CSafeLoader"]),
        ("y.SafeLoader.yaml_constructors['!record'] = other", ["SafeLoader"]),
        (
            "class Record(y.YAMLObject):\n    yaml_tag = '!record'\n    yaml_loader = y.SafeLoader",
            ["SafeLoader"],
        ),
        ("other.SafeLoader.add_constructor('!record', other)", []),
    ],
)
def test_local_yaml_registration(body, extension):
    assert decode_calls(sample(body).encode())[1] == extension


def test_extended_loader_advisory_is_scoped_to_the_repository(tmp_path):
    registration = tmp_path / "tags.py"
    registration.write_text(sample("y.SafeLoader.add_constructor('!record', other)"))
    consumer = tmp_path / "views.py"
    consumer.write_text(sample("return y.safe_load('sample')"))
    asts = ASTParser().parse_directory(tmp_path)
    (rule,) = (
        r
        for r in load_yaml_rules(PACKS / "a08-data-integrity/data_integrity.yml")
        if r.definition.id == "AEG-A08-004"
    )
    (found,) = rule.evaluate(asts, nx.MultiDiGraph(), [])
    assert found.file_path == str(consumer)
    assert found.disposition == FindingDisposition.ADVISORY
    assert "registered constructors" in found.message
    for file in asts:
        file.repository_id = file.file_path
    assert not rule.evaluate(asts, nx.MultiDiGraph(), [])


def test_normal_engine_tracks_data_into_imported_reader(tmp_path):
    path = tmp_path / "read.py"
    path.write_text(
        sample("""
        from pickle import loads as read
        user_input = request.args.get('entry')
        read(user_input)
        y.load(Loader=y.UnsafeLoader, stream=user_input)
        y.load(Loader=y.SafeLoader, stream=user_input)
        y.load(Loader=user_input, stream='literal')
        y.full_load(user_input)
        y.unsafe_load('record: ok')
        return y.unsafe_load_all(user_input)
    """)
    )
    flows = _flows(tmp_path, "deserialization")
    assert {(f.sink.function, f.sink.argument_index, f.sink.line) for f in flows} == {
        ("pickle.loads", 0, 7),
        ("yaml.load", 1, 8),
    }
    config = AegifyConfig()
    config.llm.enabled = False
    config.storage.backend = "memory"
    result = ScanEngine(config=config).scan(tmp_path)
    assert result.status == "completed"
    findings = [f for f in result.findings if f.cwe_id == 502]
    assert {(f.rule_id, f.line_start) for f in findings if f.taint_flow} >= {
        ("AEG-DESER-006", 8),
        ("AEG-RCE-PY-006", 7),
    }
    assert {f.line_start for f in findings if f.line_start > 8} == {10, 11, 13}
    assert all(f.disposition == FindingDisposition.ADVISORY for f in findings if f.line_start > 8)
    assert all("literal" not in f.message for f in findings)


def test_old_serialized_ast_does_not_invent_loader_or_flow():
    call = CallSite(receiver="pickle", callee="loads", line=1, column=0, file_path="old.py")
    file = FileAST(file_path="old.py", language=Language.PYTHON, calls=[call])
    assert sink_operand(call, file) == ("pickle.loads", 0)
    call.receiver, call.callee = "yaml", "load"
    assert reader(call, file).mode == "unknown"
    assert sink_operand(call, file) is None
    file.python_deserialization_resolved = True
    assert reader(call, file) is None
