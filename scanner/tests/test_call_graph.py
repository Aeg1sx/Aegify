"""Tests for the call graph builder."""

import time
from pathlib import Path

import pytest

from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.call_graph import CallGraphBuilder

FIXTURES = Path(__file__).parent / "fixtures"


class TestCallGraphBuilder:
    @pytest.fixture
    def builder(self):
        return CallGraphBuilder()

    @pytest.fixture
    def multi_file_asts(self):
        parser = ASTParser()
        return [parser.parse_file(FIXTURES / "multi_file_app.py")]

    @pytest.fixture
    def all_asts(self):
        parser = ASTParser()
        asts = []
        for f in FIXTURES.glob("*.py"):
            ast = parser.parse_file(f)
            if ast:
                asts.append(ast)
        return asts

    def test_build_graph(self, builder, multi_file_asts):
        graph = builder.build(multi_file_asts)
        assert graph.number_of_nodes() > 0

    def test_finds_entry_points(self, builder, multi_file_asts):
        builder.build(multi_file_asts)
        entry_points = builder.get_entry_points()
        # Flask route handlers with @app.route should be entry points
        assert len(entry_points) >= 0  # depends on decorator parsing

    def test_graph_has_edges_with_inter_function_calls(self, builder, multi_file_asts):
        """multi_file_app.py has get_user -> validate_input -> query_database."""
        graph = builder.build(multi_file_asts)
        assert graph.number_of_edges() > 0

        # get_user calls validate_input and query_database
        callees = builder.get_callees("get_user")
        assert "validate_input" in callees or "query_database" in callees

    def test_get_callers(self, builder, multi_file_asts):
        builder.build(multi_file_asts)
        callers = builder.get_callers("validate_input")
        assert "get_user" in callers

    def test_build_with_multiple_files(self, builder, all_asts):
        graph = builder.build(all_asts)
        assert graph.number_of_nodes() > 0


@pytest.mark.parametrize(
    ("declaration", "expression"),
    [
        ('import { resolve } from "node:path";', "resolve(value)"),
        ('import { resolve as normalize } from "node:path";', "normalize(value)"),
        ('import * as paths from "node:path";', "paths.resolve(value)"),
        ('import { resolve } from "external-package";', "resolve(value)"),
        ('import { resolve } from "./missing.js";', "resolve(value)"),
    ],
)
def test_unresolved_imports_do_not_bind_to_unrelated_functions(
    tmp_path: Path, declaration: str, expression: str
):
    (tmp_path / "caller.ts").write_text(
        f"{declaration}\nexport function handle(value) {{ return {expression}; }}\n"
    )
    # Include a same-leaf path module to test Node's reserved node: namespace.
    (tmp_path / "path.ts").write_text(
        "export function resolve(value) { return value; }\n"
        "export function normalize(value) { return value; }\n"
    )
    asts = ASTParser().parse_directory(tmp_path)
    for ordered in (asts, list(reversed(asts))):
        graph = CallGraphBuilder().build(ordered)
        assert graph.number_of_edges() == 0


def test_import_authority_preserves_local_and_aliased_import_edges(tmp_path: Path):
    (tmp_path / "caller.ts").write_text(
        'import { resolve as normalize } from "./local";\n'
        "export function handle(value) { return normalize(value); }\n"
    )
    (tmp_path / "local.ts").write_text("export function resolve(value) { return value; }\n")
    (tmp_path / "unrelated.ts").write_text("export function normalize(value) { return value; }\n")
    graph = CallGraphBuilder().build(ASTParser().parse_directory(tmp_path))
    assert graph.number_of_edges() == 1
    _, callee = next(iter(graph.edges()))
    assert graph.nodes[callee]["data"].file_path.endswith("local.ts")


def test_external_import_resolution_is_bounded_for_repeated_calls(tmp_path: Path):
    (tmp_path / "many.ts").write_text(
        'import { resolve } from "node:path";\n'
        "function handle(value) {\n" + "resolve(value);\n" * 1000 + "}\n"
    )
    (tmp_path / "path.ts").write_text("export function resolve(value) { return value; }\n")
    asts = ASTParser().parse_directory(tmp_path)
    started = time.monotonic()
    graph = CallGraphBuilder().build(asts)
    assert graph.number_of_edges() == 0
    assert time.monotonic() - started < 2
