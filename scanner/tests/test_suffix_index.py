"""Tests for suffix index and reachability cache in CallGraphBuilder."""

import pytest

from aegify.models import (
    CallSite,
    FileAST,
    FunctionDef,
    Language,
)
from aegify.scanner.call_graph import CallGraphBuilder


class TestSuffixIndex:
    @pytest.fixture
    def builder(self):
        return CallGraphBuilder()

    def test_suffix_index_built(self, builder):
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="handler",
                    qualified_name="app.views.handler",
                    file_path="app.py",
                    line_start=1,
                    line_end=10,
                ),
            ],
            calls=[],
        )

        builder.build([ast])

        # Suffix index should have entries for all suffixes
        assert "handler" in builder._suffix_index
        assert "views.handler" in builder._suffix_index
        assert "app.views.handler" in builder._suffix_index
        assert "app.views.handler" in builder._suffix_index["handler"]

    def test_suffix_index_resolves_callee(self, builder):
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="handler",
                    qualified_name="app.views.handler",
                    file_path="app.py",
                    line_start=1,
                    line_end=10,
                ),
                FunctionDef(
                    name="caller",
                    qualified_name="app.routes.caller",
                    file_path="app.py",
                    line_start=15,
                    line_end=20,
                ),
            ],
            calls=[
                CallSite(
                    callee="handler",
                    file_path="app.py",
                    line=17,
                    column=0,
                    in_function="caller",
                ),
            ],
        )

        graph = builder.build([ast])
        # The call should be resolved via suffix index
        assert graph.number_of_edges() >= 1

    def test_multiple_functions_same_suffix(self, builder):
        """When multiple functions share a name, suffix index stores all."""
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="process",
                    qualified_name="module_a.process",
                    file_path="app.py",
                    line_start=1,
                    line_end=5,
                ),
                FunctionDef(
                    name="process",
                    qualified_name="module_b.process",
                    file_path="app.py",
                    line_start=10,
                    line_end=15,
                ),
            ],
            calls=[],
        )

        builder.build([ast])

        assert "process" in builder._suffix_index
        assert len(builder._suffix_index["process"]) == 2


class TestReachabilityCache:
    @pytest.fixture
    def builder(self):
        return CallGraphBuilder()

    def test_reachability_cache_built_for_entry_points(self, builder):
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="handler",
                    qualified_name="app.handler",
                    file_path="app.py",
                    line_start=1,
                    line_end=10,
                    decorators=["@app.route('/')"],
                ),
                FunctionDef(
                    name="helper",
                    qualified_name="app.helper",
                    file_path="app.py",
                    line_start=15,
                    line_end=20,
                ),
            ],
            calls=[
                CallSite(
                    callee="helper",
                    file_path="app.py",
                    line=5,
                    column=0,
                    in_function="handler",
                ),
            ],
        )

        builder.build([ast])

        # Entry point should have reachability cache
        assert "app.handler" in builder._reachability
        assert "app.helper" in builder._reachability["app.handler"]

    def test_can_reach_uses_cache(self, builder):
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="handler",
                    qualified_name="app.handler",
                    file_path="app.py",
                    line_start=1,
                    line_end=10,
                    decorators=["@app.route('/')"],
                ),
                FunctionDef(
                    name="db_query",
                    qualified_name="app.db_query",
                    file_path="app.py",
                    line_start=15,
                    line_end=20,
                ),
            ],
            calls=[
                CallSite(
                    callee="db_query",
                    file_path="app.py",
                    line=5,
                    column=0,
                    in_function="handler",
                ),
            ],
        )

        builder.build([ast])
        assert builder.can_reach("app.handler", "app.db_query") is True
        assert builder.can_reach("app.db_query", "app.handler") is False

    def test_can_reach_fallback(self, builder):
        """Non-cached nodes use fallback nx.has_path."""
        ast = FileAST(
            file_path="app.py",
            language=Language.PYTHON,
            functions=[
                FunctionDef(
                    name="a",
                    qualified_name="a",
                    file_path="app.py",
                    line_start=1,
                    line_end=5,
                ),
                FunctionDef(
                    name="b",
                    qualified_name="b",
                    file_path="app.py",
                    line_start=10,
                    line_end=15,
                ),
            ],
            calls=[
                CallSite(
                    callee="b",
                    file_path="app.py",
                    line=3,
                    column=0,
                    in_function="a",
                ),
            ],
        )

        builder.build([ast])
        # "a" is not an entry point, so not cached, but fallback should work
        assert builder.can_reach("a", "b") is True
        assert builder.can_reach("nonexistent", "b") is False
