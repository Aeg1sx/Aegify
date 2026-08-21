"""Tests for the AST parser module."""

from pathlib import Path

import pytest

from aegify.models import Language
from aegify.scanner.ast_parser import ASTParser, detect_language

FIXTURES = Path(__file__).parent / "fixtures"


class TestDetectLanguage:
    def test_python(self):
        assert detect_language(Path("app.py")) == Language.PYTHON

    def test_javascript(self):
        assert detect_language(Path("app.js")) == Language.JAVASCRIPT
        assert detect_language(Path("app.jsx")) == Language.JAVASCRIPT

    def test_typescript(self):
        assert detect_language(Path("app.ts")) == Language.TYPESCRIPT
        assert detect_language(Path("app.tsx")) == Language.TYPESCRIPT

    def test_java(self):
        assert detect_language(Path("App.java")) == Language.JAVA

    def test_go(self):
        assert detect_language(Path("main.go")) == Language.GO

    def test_unsupported(self):
        assert detect_language(Path("style.css")) is None
        assert detect_language(Path("README.md")) is None


class TestASTParser:
    @pytest.fixture
    def parser(self):
        return ASTParser()

    def test_parse_vulnerable_python(self, parser):
        result = parser.parse_file(FIXTURES / "vulnerable_app.py")
        assert result is not None
        assert result.language == Language.PYTHON
        assert len(result.functions) > 0

        # Check that route handlers are found
        func_names = [f.name for f in result.functions]
        assert "get_user" in func_names
        assert "search" in func_names
        assert "ping" in func_names
        assert "render" in func_names

    def test_parse_safe_python(self, parser):
        result = parser.parse_file(FIXTURES / "safe_app.py")
        assert result is not None

        # Check that functions have decorators
        get_user = next(f for f in result.functions if f.name == "get_user")
        decorator_texts = " ".join(get_user.decorators)
        assert "auth_required" in decorator_texts or "route" in decorator_texts

    def test_parse_extracts_calls(self, parser):
        result = parser.parse_file(FIXTURES / "vulnerable_app.py")
        assert result is not None
        assert len(result.calls) > 0

        # Check that cursor.execute calls are found
        execute_calls = [c for c in result.calls if c.callee == "execute"]
        assert len(execute_calls) > 0

    def test_parse_extracts_imports(self, parser):
        result = parser.parse_file(FIXTURES / "vulnerable_app.py")
        assert result is not None
        assert len(result.imports) > 0

    def test_parse_nonexistent_file(self, parser):
        result = parser.parse_file(Path("/nonexistent/file.py"))
        assert result is None

    def test_parse_unsupported_file(self, parser):
        result = parser.parse_file(Path("style.css"))
        assert result is None

    def test_collect_files_excludes_nested_dependency_environments(self, parser, tmp_path):
        source = tmp_path / "src" / "app.py"
        vendored = tmp_path / "service" / ".venv" / "lib" / "dependency.py"
        node_dependency = tmp_path / "web" / "node_modules" / "package" / "index.js"
        source.parent.mkdir(parents=True)
        vendored.parent.mkdir(parents=True)
        node_dependency.parent.mkdir(parents=True)
        source.write_text("print('app')\n")
        vendored.write_text("print('dependency')\n")
        node_dependency.write_text("export const dependency = true;\n")

        files = parser._collect_files(
            tmp_path,
            {"**/.venv/**", "**/node_modules/**"},
        )

        assert files == [source]
