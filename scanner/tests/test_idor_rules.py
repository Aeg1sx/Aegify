"""Tests for IDOR and authorization rules."""

import networkx as nx
import pytest

from aegify.models import (
    CallSite,
    FileAST,
    FunctionDef,
    Language,
    TaintFlow,
    TaintSink,
    TaintSource,
)
from aegify.rules.idor import (
    IDORRule,
    InsecureDirectReferenceRule,
    MassAssignmentRule,
)


class TestIDORRule:
    @pytest.fixture
    def rule(self):
        return IDORRule()

    @pytest.fixture
    def empty_graph(self):
        return nx.DiGraph()

    def test_detects_idor_in_route_handler(self, rule, empty_graph):
        ast = FileAST(
            file_path="views.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="get_user",
                    qualified_name="views.get_user",
                    file_path="views.py",
                    line_start=1,
                    line_end=10,
                    decorators=["@app.route('/users/<id>')"],
                    parameters=["id"],
                ),
            ],
            calls=[
                CallSite(
                    callee="get",
                    receiver="User.objects",
                    file_path="views.py",
                    line=5,
                    column=0,
                    arguments=["id"],
                    in_function="get_user",
                ),
            ],
        )

        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) >= 1
        assert any("IDOR" in f.message or "ownership" in f.message for f in findings)

    def test_no_idor_with_ownership_check(self, rule, empty_graph):
        ast = FileAST(
            file_path="views.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="get_user",
                    qualified_name="views.get_user",
                    file_path="views.py",
                    line_start=1,
                    line_end=10,
                    decorators=["@app.route('/users/<id>')"],
                    parameters=["id"],
                ),
            ],
            calls=[
                CallSite(
                    callee="get",
                    receiver="User.objects",
                    file_path="views.py",
                    line=5,
                    column=0,
                    arguments=["id", "current_user.id"],
                    in_function="get_user",
                ),
            ],
        )

        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) == 0

    def test_no_detection_in_non_endpoint(self, rule, empty_graph):
        ast = FileAST(
            file_path="utils.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="helper",
                    qualified_name="utils.helper",
                    file_path="utils.py",
                    line_start=1,
                    line_end=10,
                    decorators=[],
                    parameters=["id"],
                ),
            ],
            calls=[
                CallSite(
                    callee="get",
                    receiver="User.objects",
                    file_path="utils.py",
                    line=5,
                    column=0,
                    arguments=["id"],
                    in_function="helper",
                ),
            ],
        )

        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) == 0

    def test_skips_unsupported_language(self, rule, empty_graph):
        ast = FileAST(
            file_path="app.rs",
            language=Language.RUST,
            functions=[],
            calls=[],
        )
        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) == 0


class TestMassAssignmentRule:
    @pytest.fixture
    def rule(self):
        return MassAssignmentRule()

    @pytest.fixture
    def empty_graph(self):
        return nx.DiGraph()

    def test_detects_mass_assignment(self, rule, empty_graph):
        ast = FileAST(
            file_path="views.py",
            language=Language.PYTHON,
            functions=[],
            calls=[
                CallSite(
                    callee="create",
                    receiver="User.objects",
                    file_path="views.py",
                    line=10,
                    column=0,
                    arguments=["**request.json"],
                    in_function="create_user",
                ),
            ],
        )

        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) >= 1
        assert any("mass assignment" in f.message.lower() for f in findings)

    def test_safe_with_schema(self, rule, empty_graph):
        ast = FileAST(
            file_path="views.py",
            language=Language.PYTHON,
            functions=[],
            calls=[
                CallSite(
                    callee="create",
                    receiver="User.objects",
                    file_path="views.py",
                    line=10,
                    column=0,
                    arguments=["serializer.validated_data"],
                    in_function="create_user",
                ),
            ],
        )

        findings = rule.evaluate([ast], empty_graph, [])
        assert len(findings) == 0


class TestInsecureDirectReferenceRule:
    @pytest.fixture
    def rule(self):
        return InsecureDirectReferenceRule()

    @pytest.fixture
    def empty_graph(self):
        return nx.DiGraph()

    def test_detects_file_access_without_validation(self, rule, empty_graph):
        flow = TaintFlow(
            source=TaintSource(
                variable="request.args",
                file_path="app.py",
                line=1,
                source_type="http_param",
                in_function="download",
            ),
            sink=TaintSink(
                function="open",
                file_path="app.py",
                line=5,
                sink_type="file_access",
                in_function="download",
            ),
            sanitized=False,
        )

        findings = rule.evaluate([], empty_graph, [flow])
        assert len(findings) >= 1

    def test_no_finding_when_sanitized(self, rule, empty_graph):
        flow = TaintFlow(
            source=TaintSource(
                variable="request.args",
                file_path="app.py",
                line=1,
                source_type="http_param",
            ),
            sink=TaintSink(
                function="open",
                file_path="app.py",
                line=5,
                sink_type="file_access",
            ),
            sanitized=True,
            sanitizer="os.path.realpath",
        )

        findings = rule.evaluate([], empty_graph, [flow])
        assert len(findings) == 0

    def test_no_finding_for_non_file_sink(self, rule, empty_graph):
        flow = TaintFlow(
            source=TaintSource(
                variable="request.args",
                file_path="app.py",
                line=1,
                source_type="http_param",
            ),
            sink=TaintSink(
                function="cursor.execute",
                file_path="app.py",
                line=5,
                sink_type="sql_query",
            ),
            sanitized=False,
        )

        findings = rule.evaluate([], empty_graph, [flow])
        assert len(findings) == 0
