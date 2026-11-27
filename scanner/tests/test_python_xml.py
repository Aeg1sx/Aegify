"""Static XML API contracts. Scanned fixtures are never imported or executed."""

from pathlib import Path
from textwrap import dedent, indent

import networkx as nx
import pytest

from aegify.models import EvidenceState, FindingDisposition
from aegify.rules.yaml_rule import load_yaml_rules
from aegify.scanner.ast_parser import ASTParser
from tests.test_taint_value_identity import _flows

PACKS = Path(__file__).resolve().parents[2] / "rules"


def _app(directory, imports, body, args=""):
    path = directory / "app.py"
    path.write_text(
        f"from flask import request\n{imports}\ndef inspect({args}):\n"
        + indent(dedent(body).strip(), "    ")
        + "\n"
    )
    return path


@pytest.mark.parametrize(
    ("imports", "consumer", "index"),
    [
        ("from elementpath import select as choose", "choose(tree, query)", 1),
        ("import elementpath as ep", "ep.select(path=query, root=tree)", 0),
        ("import elementpath as ep", "ep.iter_select(tree, path=query)", 1),
        ("import elementpath as ep", "ep.Selector(query)", 0),
        ("from lxml import etree as xml", "xml.XPath(path=query)", 0),
        ("from lxml import etree as xml", "xml.ETXPath(query)", 0),
        ("from lxml import etree as xml", "xml.fromstring('<r/>').xpath(query)", 0),
        (
            "from lxml import etree as xml",
            "xml.Element('root').getroottree().xpath(_path=query)",
            0,
        ),
    ],
)
def test_only_a_resolved_query_program_is_a_sink(tmp_path, imports, consumer, index):
    path = _app(tmp_path, imports, f"query = request.args.get('path')\nreturn {consumer}", "tree")
    flows = _flows(tmp_path, "xpath_query")
    assert len(flows) == 1
    assert (flows[0].source.line, flows[0].sink.line, flows[0].sink.argument_index) == (4, 5, index)
    parsed = ASTParser().parse_file(path)
    assert parsed is not None
    rules = load_yaml_rules(PACKS / "a03-injection/xpath_injection.yml")
    actual = [
        finding for rule in rules for finding in rule.evaluate([parsed], nx.MultiDiGraph(), flows)
    ]
    assert [f.rule_id for f in actual] == ["AEG-XPATH-001"]
    assert actual[0].evidence_state == EvidenceState.REACHABLE


@pytest.mark.parametrize(
    ("imports", "body", "args"),
    [
        (
            "from lxml import etree",
            "doc = etree.Element('catalog')\nreturn doc.xpath('$name', name=request.args['name'])",
            "",
        ),
        (
            "from lxml import etree",
            "p = etree.XPath('$name')\nreturn p(tree, name=request.args['name'])",
            "tree",
        ),
        (
            "from lxml import etree",
            "doc = etree.Element('catalog')\nreturn doc.xpath('$path', path=request.args['path'])",
            "",
        ),
        (
            "import elementpath",
            "return elementpath.select(request.args.get('root'), '/catalog')",
            "",
        ),
        (
            "import elementpath",
            "return elementpath.select(tree, '$name', variables={'name': request.args['name']})",
            "tree",
        ),
        (
            "import elementpath",
            "return elementpath.select(tree, request.args['name'])",
            "elementpath, tree",
        ),
        (
            "from foreign import etree",
            "doc = etree.Element('catalog')\nreturn doc.xpath(request.args['name'])",
            "",
        ),
        (
            "from lxml import etree",
            "doc = etree.Element('catalog')\ndoc = other\nreturn doc.xpath(request.args['name'])",
            "other",
        ),
        ("from lxml import etree", "return unrelated.xpath(request.args['name'])", "unrelated"),
        ("from lxml import etree", "return etree.XPath(*values)", "values"),
    ],
)
def test_parameterized_or_unresolved_xpath(tmp_path, imports, body, args):
    path = _app(tmp_path, imports, body, args)
    assert _flows(tmp_path, "xpath_query") == []
    parsed = ASTParser().parse_file(path)
    rules = load_yaml_rules(PACKS / "a03-injection/xpath_injection.yml")
    assert not any(rule.evaluate([parsed], nx.MultiDiGraph(), []) for rule in rules)


def _sax(directory, body, args=""):
    return _app(
        directory,
        "from xml import sax\n"
        "from xml.sax.handler import feature_external_ges as external\n"
        "from xml.dom import minidom as dom",
        body,
        args,
    )


def _config_findings(path):
    parsed = ASTParser().parse_file(path)
    rule = next(
        rule
        for rule in load_yaml_rules(PACKS / "a05-security-misconfiguration/misconfig.yml")
        if rule.definition.id == "AEG-A05-004"
    )
    return rule.evaluate([parsed], nx.MultiDiGraph(), [])


@pytest.mark.parametrize(
    "settings, consumer",
    [
        ("parser.setFeature(external, True)", "dom.parseString(request.data, parser)"),
        (
            "alias = parser\nalias.setFeature(external, True)",
            "dom.parseString(parser=parser, string=request.data)",
        ),
        ("parser.setFeature(external, True)", "parser.parse(request.data)"),
    ],
)
def test_external_resolution_bound_to_actual_parser(tmp_path, settings, consumer):
    path = _sax(tmp_path, f"parser = sax.make_parser()\n{settings}\nreturn {consumer}")
    flows = _flows(tmp_path, "xml_external_input")
    assert flows and all(flow.source.source_type == "http_body" for flow in flows)
    (finding,) = _config_findings(path)
    assert finding.line_start == flows[0].sink.line
    assert (
        "were enabled on line" in finding.message
        and finding.disposition == FindingDisposition.ADVISORY
    )


@pytest.mark.parametrize(
    "body",
    [
        "return dom.parseString(request.data)",
        "return dom.parseString(request.data, parser=None)",
        "parser = sax.make_parser()\nreturn dom.parseString(request.data, parser)",
        "parser = sax.make_parser()\n"
        "parser.setFeature(external, True)\n"
        "parser.setFeature(external, False)\n"
        "return dom.parseString(request.data, parser)",
        "a = sax.make_parser()\n"
        "b = sax.make_parser()\n"
        "a.setFeature(external, True)\n"
        "return dom.parseString(request.data, b)",
        "parser = sax.make_parser()\n"
        "parser.setFeature(external, True)\n"
        "return dom.parseString('<catalog/>', parser)",
        "parser = sax.make_parser()\nparser.setFeature(external, True)",
    ],
)
def test_default_separate_and_disabled_parsers(tmp_path, body):
    path = _sax(tmp_path, body)
    assert not _flows(tmp_path, "xml_external_input")
    assert _config_findings(path) == []


@pytest.mark.parametrize(
    "body",
    [
        "return dom.parseString(request.data, custom)",
        "parser = sax.make_parser()\n"
        "if flag:\n"
        "    parser.setFeature(external, True)\n"
        "return dom.parseString(request.data, parser)",
        "parser = sax.make_parser()\n"
        "configure(parser)\n"
        "return dom.parseString(request.data, parser)",
        "parser = sax.make_parser()\n"
        "parser.setFeature(external, flag)\n"
        "return dom.parseString(request.data, parser)",
        "parser = sax.make_parser(custom)\nreturn dom.parseString(request.data, parser)",
    ],
)
def test_unknown_configuration_stays_advisory(tmp_path, body):
    path = _sax(tmp_path, body, "flag, custom, configure")
    assert not _flows(tmp_path, "xml_external_input")
    (finding,) = _config_findings(path)
    assert "could not be resolved" in finding.message
    assert finding.evidence_state == EvidenceState.CANDIDATE


def test_constant_filename_does_not_prove_constant_document(tmp_path):
    path = _sax(
        tmp_path,
        "parser = sax.make_parser()\n"
        "parser.setFeature(external, True)\n"
        "return dom.parse('catalog.xml', parser)",
    )
    assert len(_config_findings(path)) == 1


def test_append_only_buffer_retains_the_write_time_value(tmp_path):
    path = _app(
        tmp_path,
        "from io import StringIO as Text\nfrom lxml.etree import XPath",
        """
        value = request.args.get("query")
        buf = Text()
        buf.write(value)
        value = "fixed"
        buf.write("/name")
        return XPath(buf.getvalue())
        """,
    )
    flows = _flows(tmp_path, "xpath_query")
    assert len(flows) == 1
    assert any(step.propagation_type == "buffer-write" and step.line == 7 for step in flows[0].path)
    assert flows[0].sink.file_path == str(path)


@pytest.mark.parametrize("extra", ["left.seek(0)", "opaque(left)", "alias = left"])
def test_mutable_or_shared_stream_has_no_append_only_summary(tmp_path, extra):
    path = _app(
        tmp_path,
        "import io\nimport elementpath",
        f"left = io.StringIO()\nright = io.StringIO()\nleft.write(request.data)\n{extra}\n"
        "return elementpath.select(tree, right.getvalue())",
        "tree, opaque",
    )
    parsed = ASTParser().parse_file(path)
    assert not any(call.python_buffer_write for call in parsed.calls)
    assert not _flows(tmp_path, "xpath_query")


def test_distinct_append_only_streams_do_not_share_writes(tmp_path):
    _app(
        tmp_path,
        "import io\nfrom lxml.etree import XPath",
        """
        left = io.StringIO()
        right = io.StringIO()
        left.write(request.args["query"])
        right.write("/fixed")
        return XPath(right.getvalue())
        """,
    )
    assert not _flows(tmp_path, "xpath_query")


@pytest.mark.parametrize(
    "setup,field,quoted,bound",
    [
        ("", """name.replace("'", "")""", True, True),
        ("", """name.replace('"', '')""", True, False),
        ("", """name.replace("'", "'", 1)""", True, False),
        ("", """name.replace("'", "")""", False, False),
        ("""if "'" in name:\n    return""", "name", True, True),
        ("""if "'" in other:\n    return""", "name", True, False),
        ("""if "'" in name:\n    remember(name)""", "name", True, False),
        ("""if "'" in name:\n    return\nname = request.args['next']""", "name", True, False),
        ("""if "'" in name:\n    return""", "name!r", True, False),
        ("name = custom", """name.replace("'", "")""", True, False),
    ],
)
def test_quote_constraints_are_bound_to_the_value_and_xpath_literal(
    tmp_path, setup, field, quoted, bound
):
    value = "'{" + field + "}'" if quoted else "{" + field + "}"
    path = _app(
        tmp_path,
        "from lxml import etree",
        "name = request.args['name']\n"
        + setup
        + "\n"
        + 'query = f"/catalog/item[@code='
        + value
        + ']"\nreturn etree.XPath(query)',
        "other, custom, remember",
    )
    calls = ASTParser().parse_file(path).calls
    (consumer,) = (call.xml_invocation for call in calls if call.xml_invocation)
    assert consumer.quoted_value_constrained is bound
    if bound:
        assert not _flows(tmp_path, "xpath_query")


@pytest.mark.parametrize(
    "insert,selected,advisory",
    [
        ("", "NAME", False),
        ("", "untrusted", True),
        ("settings.set('catalog', 'name', '%(untrusted)s')", "name", True),
        ("if flag:\n    settings.set('catalog', 'name', request.data)", "name", True),
        ("settings.set('catalog', option, request.data)", "name", True),
        ("reconfigure(settings)", "name", True),
    ],
)
def test_configparser_requires_a_stable_literal_section_and_option(
    tmp_path, insert, selected, advisory
):
    path = _app(
        tmp_path,
        "from xml import sax\nfrom xml.dom import minidom\nimport configparser",
        "settings = configparser.ConfigParser()\nsettings.add_section('catalog')\n"
        "settings.set('catalog', 'name', '<catalog/>')\n"
        "settings.set('catalog', 'untrusted', request.data)\n"
        + insert
        + "\n"
        + f"doc = settings.get('catalog', '{selected}')\n"
        "parser = sax.make_parser()\nparser.setFeature(sax.handler.feature_external_ges, True)\n"
        "return minidom.parseString(doc, parser)",
        "flag, option, reconfigure",
    )
    assert bool(_config_findings(path)) is advisory


def test_literal_mapping_input_is_selected_by_its_unchanged_key(tmp_path):
    path = _sax(
        tmp_path,
        """
        docs = {}
        docs['public'] = '<catalog/>'
        docs['submitted'] = request.data
        parser = sax.make_parser()
        parser.setFeature(external, True)
        return dom.parseString(docs['public'], parser)
        """,
    )
    assert not _config_findings(path)


@pytest.mark.parametrize(
    ("setup", "call", "advisory"),
    [
        ("docs = [request.data, b'<r/>']\ndoc = docs[1]", "dom.parseString(doc, parser)", False),
        ("doc = '<r>' + '</r>' if flag else '<q/>'", "dom.parseString(doc, parser)", False),
        ("doc = '<r/>' if flag else request.data", "dom.parseString(doc, parser)", True),
        ("doc = '<r>' + '&amp;</r>'", "dom.parseString(doc, parser)", True),
        ("doc = '<?xml version=\"1.0\"?><r/>'", "dom.parseString(doc, parser)", True),
        ("docs = ['<r/>']\nchange(docs)", "dom.parseString(docs[0], parser)", True),
        ("doc = 'one.xml' if flag else 'two.xml'", "dom.parse(doc, parser)", True),
        (
            "import configparser\ns = configparser.ConfigParser()\ns.add_section('documents')\n"
            "ref = '%(submitted)s'\ns.set('documents', 'current', ref)\n"
            "s.set('documents', 'submitted', request.data)\ndoc = s.get('documents', 'current')",
            "dom.parseString(doc, parser)",
            True,
        ),
    ],
)
def test_entity_enabled_reader_checks_every_possible_document(tmp_path, setup, call, advisory):
    path = _sax(
        tmp_path,
        "parser = sax.make_parser()\nparser.setFeature(external, True)\n"
        + setup
        + "\nreturn "
        + call,
        "flag, change",
    )
    assert bool(_config_findings(path)) is advisory


@pytest.mark.parametrize("backend", ["mapping", "config"])
@pytest.mark.parametrize("selected,expected", [("chosen", 1), ("other", 0)])
def test_lookup_restores_the_value_at_write_time(tmp_path, backend, selected, expected):
    setup = (
        "store = {}\nstore['chosen'] = value\nstore['other'] = 'constant'\n"
        if backend == "mapping"
        else "store = configparser.ConfigParser()\nstore.add_section('catalog')\n"
        "store.set('catalog', 'chosen', value)\nstore.set('catalog', 'other', 'constant')\n"
    )
    lookup = (
        f"store['{selected}']" if backend == "mapping" else f"store.get('catalog', '{selected}')"
    )
    _app(
        tmp_path,
        "import configparser\nfrom lxml.etree import XPath",
        "value = request.args['query']\n"
        + setup
        + "value = 'overwritten'\n"
        + f"query = {lookup}\nreturn XPath(query)",
    )
    flows = _flows(tmp_path, "xpath_query")
    assert len(flows) == expected
    if flows:
        assert any(step.propagation_type == "keyed-store" for step in flows[0].path)


@pytest.mark.parametrize(
    "before,after,expected",
    [
        ("settings.read('catalog.ini')", "", True),
        ("other.read('catalog.ini')", "", False),
        ("", "settings.read('catalog.ini')", False),
    ],
)
def test_config_source_requires_a_prior_file_read_on_the_same_instance(
    tmp_path, before, after, expected
):
    _app(
        tmp_path,
        "import configparser\nfrom lxml.etree import XPath",
        "settings = configparser.ConfigParser()\nother = configparser.ConfigParser()\n"
        + before
        + "\nquery = settings.get('file', 'selection')\n"
        + after
        + "\nreturn XPath(query)",
    )
    assert (
        bool([f for f in _flows(tmp_path, "xpath_query") if f.source.source_type == "config_value"])
        is expected
    )
