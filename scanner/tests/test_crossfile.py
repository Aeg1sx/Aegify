"""Tests for cross-file call graph resolution."""

from pathlib import Path

import pytest

from codeguard.config import CodeGuardConfig
from codeguard.scanner.ast_parser import ASTParser
from codeguard.scanner.call_graph import CallGraphBuilder
from codeguard.scanner.engine import ScanEngine

CROSSFILE = Path(__file__).parent / "fixtures" / "crossfile"


class TestCrossFileCallGraph:
    @pytest.fixture
    def asts(self):
        parser = ASTParser()
        return parser.parse_directory(CROSSFILE)

    @pytest.fixture
    def builder_with_graph(self, asts):
        builder = CallGraphBuilder()
        builder.build(asts)
        return builder

    def test_parses_all_files(self, asts):
        assert len(asts) == 3  # routes.py, db.py, utils.py
        filenames = sorted(a.file_path.split("/")[-1] for a in asts)
        assert filenames == ["db.py", "routes.py", "utils.py"]

    def test_import_map_built(self, builder_with_graph):
        """routes.py imports from db and utils, so import map should resolve them."""
        imap = builder_with_graph._import_map
        assert len(imap) > 0

        # Check that routes.py's imported names are mapped
        routes_file = str(CROSSFILE / "routes.py")
        mapped_names = {k[1] for k, v in imap.items() if k[0] == routes_file}
        assert "query_user" in mapped_names
        assert "query_products" in mapped_names
        assert "validate_input" in mapped_names

    def test_cross_file_edges(self, builder_with_graph):
        """get_user in routes.py should connect to validate_input and query_user."""
        graph = builder_with_graph.graph
        assert graph.number_of_edges() > 0

        callees = builder_with_graph.get_callees("get_user")
        assert "validate_input" in callees, f"Expected validate_input in callees, got: {callees}"
        assert "query_user" in callees, f"Expected query_user in callees, got: {callees}"

    def test_search_cross_file_edges(self, builder_with_graph):
        """search in routes.py should connect to query_products."""
        callees = builder_with_graph.get_callees("search")
        assert "query_products" in callees, f"Expected query_products in callees, got: {callees}"

    def test_full_path_entry_to_sink(self, builder_with_graph):
        """Should be able to trace from get_user -> query_user -> get_connection."""
        chain = builder_with_graph.get_call_chain("get_user", "get_connection")
        assert chain is not None, "Expected path from get_user to get_connection"
        assert "get_user" in chain
        assert "query_user" in chain
        assert "get_connection" in chain

    def test_cross_file_scan_detects_vulnerability(self):
        """Full scan of crossfile should find SQL injection in query_user via routes.py."""
        config = CodeGuardConfig()
        config.llm.enabled = False
        config.rules.severity_threshold = "low"
        engine = ScanEngine(config=config)
        result = engine.scan(CROSSFILE)

        assert result.files_scanned == 3
        assert len(result.findings) > 0

        # Should find SQL injection in db.py
        sql_findings = [f for f in result.findings if f.rule_id.startswith("CG-SQL")]
        assert len(sql_findings) > 0

        # query_products uses parameterized query, should have lower confidence or be filtered
        # query_user uses string concat, should be detected
        db_file = str(CROSSFILE / "db.py")
        db_sql = [f for f in sql_findings if f.file_path == db_file]
        assert len(db_sql) > 0
