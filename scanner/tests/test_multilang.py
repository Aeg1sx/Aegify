"""Multi-language parser and scan tests."""

from pathlib import Path

import pytest

from codeguard.config import CodeGuardConfig
from codeguard.models import Language
from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.call_graph import CallGraphBuilder
from codeguard.scanner.engine import ScanEngine

FIXTURES = Path(__file__).parent / "fixtures"


class TestJavaScriptParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "vulnerable_app.js")

    def test_parses_successfully(self, ast):
        assert ast is not None
        assert ast.language == Language.JAVASCRIPT

    def test_extracts_functions(self, ast):
        names = [f.name for f in ast.functions]
        assert "validateInput" in names
        assert "queryUser" in names

    def test_extracts_calls(self, ast):
        assert len(ast.calls) > 0
        callees = [c.callee for c in ast.calls]
        assert "query" in callees  # db.query

    def test_call_graph_edges(self, ast):
        builder = CallGraphBuilder()
        graph = builder.build([ast])
        assert graph.number_of_nodes() > 0


class TestJavaParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "VulnerableApp.java")

    def test_parses_successfully(self, ast):
        assert ast is not None
        assert ast.language == Language.JAVA

    def test_extracts_methods(self, ast):
        names = [f.qualified_name for f in ast.functions]
        assert "VulnerableApp.getUser" in names
        assert "VulnerableApp.ping" in names
        assert "VulnerableApp.validateInput" in names
        assert "VulnerableApp.queryDatabase" in names

    def test_extracts_imports(self, ast):
        assert len(ast.imports) > 0

    def test_extracts_calls(self, ast):
        callees = [c.callee for c in ast.calls]
        assert "executeQuery" in callees
        assert "getParameter" in callees

    def test_call_graph_has_edges(self, ast):
        """getUser2 -> validateInput, queryDatabase"""
        builder = CallGraphBuilder()
        graph = builder.build([ast])
        edges = list(graph.edges())
        assert len(edges) > 0

        callees = builder.get_callees("VulnerableApp.getUser2")
        assert "VulnerableApp.validateInput" in callees or "VulnerableApp.queryDatabase" in callees


class TestGoParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "vulnerable_app.go")

    def test_parses_successfully(self, ast):
        assert ast is not None
        assert ast.language == Language.GO

    def test_extracts_functions(self, ast):
        names = [f.name for f in ast.functions]
        assert "getUser" in names
        assert "ping" in names
        assert "greet" in names
        assert "validateInput" in names
        assert "queryDatabase" in names
        assert "main" in names

    def test_extracts_imports(self, ast):
        modules = [i.module for i in ast.imports]
        assert "database/sql" in modules
        assert "net/http" in modules

    def test_extracts_calls(self, ast):
        assert len(ast.calls) > 0
        callees = [c.callee for c in ast.calls]
        assert "Query" in callees  # db.Query
        assert "Command" in callees or "Fprintf" in callees

    def test_call_graph_has_edges(self, ast):
        """getUser2 -> validateInput, queryDatabase"""
        builder = CallGraphBuilder()
        builder.build([ast])
        callees = builder.get_callees("getUser2")
        assert "validateInput" in callees or "queryDatabase" in callees


class TestMultiLangScan:
    @pytest.fixture
    def engine(self):
        config = CodeGuardConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        return ScanEngine(config=config)

    def test_scan_js(self, engine):
        result = engine.scan(FIXTURES / "vulnerable_app.js")
        assert result.files_scanned == 1
        assert len(result.findings) > 0
        rule_ids = [f.rule_id for f in result.findings]
        # Should detect at least SQL injection or command injection
        has_detection = any(r.startswith(("CG-SQL", "CG-CMD", "CG-XSS")) for r in rule_ids)
        assert has_detection, f"Expected detections in JS, got: {rule_ids}"

    def test_scan_java(self, engine):
        result = engine.scan(FIXTURES / "VulnerableApp.java")
        assert result.files_scanned == 1
        assert len(result.findings) > 0

    def test_scan_go(self, engine):
        result = engine.scan(FIXTURES / "vulnerable_app.go")
        assert result.files_scanned == 1
        assert len(result.findings) > 0

    def test_scan_all_fixtures(self, engine):
        result = engine.scan(FIXTURES)
        assert result.files_scanned >= 5  # py x3 + js + java + go
        assert len(result.findings) > 0
