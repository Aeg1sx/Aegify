"""Tests for Rust, Swift, and Kotlin language support."""

from pathlib import Path

import pytest

from codeguard.models import Language
from codeguard.scanner.ast_parser import ASTParser, detect_language
from codeguard.scanner.call_graph import CallGraphBuilder

FIXTURES = Path(__file__).parent / "fixtures"


# --- Language Detection ---


class TestLanguageDetection:
    def test_detect_rust(self):
        assert detect_language(Path("test.rs")) == Language.RUST

    def test_detect_swift(self):
        assert detect_language(Path("test.swift")) == Language.SWIFT

    def test_detect_kotlin(self):
        assert detect_language(Path("test.kt")) == Language.KOTLIN

    def test_detect_kotlin_script(self):
        assert detect_language(Path("test.kts")) == Language.KOTLIN


# --- Rust ---


class TestRustParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "vulnerable_app.rs")

    def test_parses_rust_file(self, ast):
        assert ast is not None
        assert ast.language == Language.RUST

    def test_extracts_functions(self, ast):
        func_names = [f.name for f in ast.functions]
        assert "handle_request" in func_names
        assert "run_command" in func_names
        assert "get_env_data" in func_names

    def test_extracts_impl_methods(self, ast):
        method_names = [f.name for f in ast.functions if f.is_method]
        assert "query_user" in method_names
        assert "execute" in method_names
        assert "new" in method_names

    def test_qualified_names(self, ast):
        qnames = {f.name: f.qualified_name for f in ast.functions}
        assert qnames["query_user"] == "Database.query_user"
        assert qnames["execute"] == "Database.execute"

    def test_extracts_imports(self, ast):
        modules = [i.module for i in ast.imports]
        assert "std::process::Command" in modules
        assert "std::env" in modules

    def test_extracts_calls(self, ast):
        callees = [c.callee for c in ast.calls]
        assert "new" in callees  # Command::new
        assert "arg" in callees
        assert "format!" in callees or "query_user" in callees

    def test_call_graph(self, ast):
        builder = CallGraphBuilder()
        builder.build([ast])
        assert builder.graph.number_of_nodes() > 0

    def test_classes_from_impl(self, ast):
        class_names = [c.name for c in ast.classes]
        assert "Database" in class_names


# --- Swift ---


class TestSwiftParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "vulnerable_app.swift")

    def test_parses_swift_file(self, ast):
        assert ast is not None
        assert ast.language == Language.SWIFT

    def test_extracts_functions(self, ast):
        func_names = [f.name for f in ast.functions]
        assert "handleUserInput" in func_names
        assert "executeShell" in func_names

    def test_extracts_class_methods(self, ast):
        method_names = [f.name for f in ast.functions if f.is_method]
        assert "getUser" in method_names
        assert "executeQuery" in method_names
        assert "runCommand" in method_names

    def test_qualified_names(self, ast):
        qnames = {f.name: f.qualified_name for f in ast.functions}
        assert qnames["getUser"] == "DatabaseService.getUser"
        assert qnames["runCommand"] == "CommandRunner.runCommand"

    def test_extracts_classes(self, ast):
        class_names = [c.name for c in ast.classes]
        assert "DatabaseService" in class_names
        assert "CommandRunner" in class_names

    def test_extracts_imports(self, ast):
        modules = [i.module for i in ast.imports]
        assert "Foundation" in modules

    def test_extracts_calls(self, ast):
        callees = [c.callee for c in ast.calls]
        assert len(callees) > 0

    def test_call_graph(self, ast):
        builder = CallGraphBuilder()
        builder.build([ast])
        assert builder.graph.number_of_nodes() > 0


# --- Kotlin ---


class TestKotlinParser:
    @pytest.fixture
    def ast(self):
        parser = ASTParser()
        return parser.parse_file(FIXTURES / "VulnerableApp.kt")

    def test_parses_kotlin_file(self, ast):
        assert ast is not None
        assert ast.language == Language.KOTLIN

    def test_extracts_functions(self, ast):
        func_names = [f.name for f in ast.functions]
        assert "handleRequest" in func_names
        assert "executeCommand" in func_names

    def test_extracts_class_methods(self, ast):
        method_names = [f.name for f in ast.functions if f.is_method]
        assert "getUser" in method_names
        assert "deleteUser" in method_names
        assert "runCommand" in method_names

    def test_qualified_names(self, ast):
        qnames = {f.name: f.qualified_name for f in ast.functions}
        assert qnames["getUser"] == "UserController.getUser"
        assert qnames["runCommand"] == "UserController.runCommand"

    def test_extracts_classes(self, ast):
        class_names = [c.name for c in ast.classes]
        assert "UserController" in class_names

    def test_extracts_imports(self, ast):
        modules = [i.module for i in ast.imports]
        assert any("DriverManager" in m for m in modules)

    def test_extracts_calls(self, ast):
        callees = [c.callee for c in ast.calls]
        assert "executeQuery" in callees or "getConnection" in callees

    def test_call_graph(self, ast):
        builder = CallGraphBuilder()
        builder.build([ast])
        assert builder.graph.number_of_nodes() > 0

    def test_kotlin_call_graph_edges(self, ast):
        builder = CallGraphBuilder()
        builder.build([ast])
        # handleRequest calls getUser
        callees = builder.get_callees("handleRequest")
        assert "UserController.getUser" in callees or "getUser" in callees
