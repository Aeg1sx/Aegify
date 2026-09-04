"""AST parsing using tree-sitter for multi-language support."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import tree_sitter_go as tsgo
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjs
import tree_sitter_kotlin as tskotlin
import tree_sitter_python as tspython
import tree_sitter_rust as tsrust
import tree_sitter_swift as tsswift
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from aegify.models import (
    CallSite,
    ClassDef,
    FileAST,
    FunctionDef,
    ImportInfo,
)
from aegify.models import (
    Language as Lang,
)

logger = logging.getLogger(__name__)

# Language registry
_LANGUAGES: dict[Lang, Language] = {}
_PARSERS: dict[Lang, Parser] = {}


def _get_language(lang: Lang) -> Language:
    """Get or create a tree-sitter Language instance."""
    if lang not in _LANGUAGES:
        match lang:
            case Lang.PYTHON:
                _LANGUAGES[lang] = Language(tspython.language())
            case Lang.JAVASCRIPT:
                _LANGUAGES[lang] = Language(tsjs.language())
            case Lang.TYPESCRIPT:
                _LANGUAGES[lang] = Language(tsts.language_typescript())
            case Lang.JAVA:
                _LANGUAGES[lang] = Language(tsjava.language())
            case Lang.GO:
                _LANGUAGES[lang] = Language(tsgo.language())
            case Lang.RUST:
                _LANGUAGES[lang] = Language(tsrust.language())
            case Lang.SWIFT:
                _LANGUAGES[lang] = Language(tsswift.language())
            case Lang.KOTLIN:
                _LANGUAGES[lang] = Language(tskotlin.language())
    return _LANGUAGES[lang]


def _get_parser(lang: Lang) -> Parser:
    """Get or create a parser for the given language."""
    if lang not in _PARSERS:
        parser = Parser(_get_language(lang))
        _PARSERS[lang] = parser
    return _PARSERS[lang]


def detect_language(file_path: Path) -> Lang | None:
    """Detect programming language from file extension."""
    ext_map: dict[str, Lang] = {
        ".py": Lang.PYTHON,
        ".js": Lang.JAVASCRIPT,
        ".jsx": Lang.JAVASCRIPT,
        ".ts": Lang.TYPESCRIPT,
        ".tsx": Lang.TYPESCRIPT,
        ".java": Lang.JAVA,
        ".go": Lang.GO,
        ".rs": Lang.RUST,
        ".swift": Lang.SWIFT,
        ".kt": Lang.KOTLIN,
        ".kts": Lang.KOTLIN,
    }
    return ext_map.get(file_path.suffix.lower())


class ASTParser:
    """Multi-language AST parser using tree-sitter."""

    def parse_file(
        self,
        file_path: Path,
        *,
        repository_id: str = "",
        repository_root: Path | None = None,
    ) -> FileAST | None:
        """Parse a single file and extract structural information."""
        lang = detect_language(file_path)
        if lang is None:
            return None

        try:
            source = file_path.read_bytes()
        except OSError as e:
            logger.warning("Failed to read %s: %s", file_path, e)
            return None

        parser = _get_parser(lang)
        tree = parser.parse(source)

        extractor = _get_extractor(lang)
        ast = extractor.extract(tree.root_node, source, str(file_path), lang)
        self._apply_callable_identities(ast)
        if repository_id or repository_root is not None:
            self.apply_repository_context(
                ast,
                repository_id=repository_id,
                repository_root=repository_root or file_path.parent,
            )
        return ast

    @staticmethod
    def _apply_callable_identities(ast: FileAST) -> None:
        """Assign descriptor-safe identities even for a single-repository scan."""

        seen: set[int] = set()
        functions = list(ast.functions)
        for cls in ast.classes:
            functions.extend(cls.methods)
        for function in functions:
            if id(function) in seen:
                continue
            seen.add(id(function))
            function.language = ast.language
            function.symbol_id = function.callable_name
        ASTParser._bind_callers(ast, functions)

    @staticmethod
    def _bind_callers(ast: FileAST, functions: list[FunctionDef]) -> None:
        for call in ast.calls:
            candidates = [
                function
                for function in functions
                if function.line_start <= call.line <= function.line_end
            ]
            if candidates:
                caller = min(
                    candidates,
                    key=lambda item: (
                        item.line_end - item.line_start,
                        item.line_start,
                    ),
                )
                call.caller_symbol_id = caller.symbol_id

    @staticmethod
    def apply_repository_context(
        ast: FileAST,
        *,
        repository_id: str,
        repository_root: Path,
    ) -> None:
        """Attach stable module- and optionally repository-qualified identities.

        Display names intentionally remain language-native (for example,
        ``UserController.getUser``). ``symbol_id`` is the collision-resistant
        graph identity used by directory and workspace scans.
        """
        file_path = Path(ast.file_path).resolve()
        root = repository_root.resolve()
        try:
            module_path = file_path.relative_to(root).as_posix()
        except ValueError:
            module_path = file_path.as_posix()
        ast.repository_id = repository_id
        ast.module_path = module_path

        seen: set[int] = set()
        functions = list(ast.functions)
        for cls in ast.classes:
            functions.extend(cls.methods)
        for func in functions:
            if id(func) in seen:
                continue
            seen.add(id(func))
            func.repository_id = repository_id
            func.module_path = module_path
            func.symbol_id = (
                f"repo:{repository_id}:{module_path}::{func.callable_name}"
                if repository_id
                else f"file:{module_path}::{func.callable_name}"
            )
        ASTParser._bind_callers(ast, functions)
        for call in ast.calls:
            call.repository_id = repository_id

    def parse_directory(
        self, directory: Path, exclude_patterns: list[str] | None = None
    ) -> list[FileAST]:
        """Parse all supported files in a directory."""
        results: list[FileAST] = []
        exclude = set(exclude_patterns or [])

        for file_path in self._collect_files(directory, exclude):
            ast = self.parse_file(file_path, repository_root=directory)
            if ast is not None:
                results.append(ast)

        logger.info("Parsed %d files from %s", len(results), directory)
        return results

    def _collect_files(self, directory: Path, exclude: set[str]) -> list[Path]:
        """Collect all parseable files, respecting exclusions."""
        files: list[Path] = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if detect_language(path) is None:
                continue
            rel = str(path.relative_to(directory))
            if any(self._matches_pattern(rel, pat) for pat in exclude):
                continue
            files.append(path)
        return sorted(files)

    @staticmethod
    def _matches_pattern(path: str, pattern: str) -> bool:
        """Simple glob-like pattern matching."""
        from fnmatch import fnmatch

        return fnmatch(path, pattern)


# --- Language-specific extractors ---


class _BaseExtractor:
    """Base class for language-specific AST extraction."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        raise NotImplementedError

    def _node_text(self, node: Node, source: bytes) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def _find_nodes(self, node: Node, type_name: str) -> list[Node]:
        """Recursively find all nodes of a given type."""
        results: list[Node] = []
        if node.type == type_name:
            results.append(node)
        for child in node.children:
            results.extend(self._find_nodes(child, type_name))
        return results

    def _find_enclosing_function(
        self, node: Node, source: bytes, func_types: tuple[str, ...]
    ) -> str | None:
        """Find the enclosing function name for a given node."""
        current = node.parent
        while current is not None:
            if current.type in func_types:
                name_node = current.child_by_field_name("name")
                if name_node:
                    return self._node_text(name_node, source)
            current = current.parent
        return None

    def _find_enclosing_node(
        self,
        node: Node,
        func_types: tuple[str, ...],
    ) -> Node | None:
        current = node.parent
        while current is not None:
            if current.type in func_types:
                return current
            current = current.parent
        return None

    @staticmethod
    def _infer_expression_type(
        expression: str,
        scope_types: dict[str, str],
        *,
        kotlin: bool,
    ) -> str:
        value = expression.strip()
        if kotlin and "=" in value:
            possible_name, _, assigned = value.partition("=")
            if re.fullmatch(r"[A-Za-z_$][\w$]*\s*", possible_name):
                value = assigned.strip()
        if value in scope_types:
            return scope_types[value]
        if re.fullmatch(r'"(?:\\.|[^"\\])*"', value, re.DOTALL):
            return "String"
        if re.fullmatch(r"'(?:\\.|[^'\\])'", value, re.DOTALL):
            return "Char" if kotlin else "char"
        if value in {"true", "false"}:
            return "Boolean" if kotlin else "boolean"
        if value == "null":
            return "Nothing?" if kotlin else "null"
        if re.fullmatch(r"[-+]?\d+[lL]", value):
            return "Long" if kotlin else "long"
        if re.fullmatch(r"[-+]?\d+", value):
            return "Int" if kotlin else "int"
        if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)[fF]", value):
            return "Float" if kotlin else "float"
        if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)(?:[dD])?", value):
            return "Double" if kotlin else "double"
        allocation = re.match(r"(?:new\s+)?([A-Z][\w.$<>?]*)\s*\(", value)
        if allocation:
            return allocation.group(1)
        cast = re.match(r"\(\s*([A-Za-z_$][\w.$<>?\[\]]*)\s*\)", value)
        if cast:
            return cast.group(1)
        return ""


class _PythonExtractor(_BaseExtractor):
    """Extract Python-specific AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        self._extract_imports(root, source, imports)
        self._extract_functions(root, source, file_path, functions)
        self._extract_classes(root, source, file_path, classes, functions)
        self._extract_calls(root, source, file_path, calls)

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _extract_imports(self, root: Node, source: bytes, imports: list[ImportInfo]) -> None:
        for node in self._find_nodes(root, "import_statement"):
            for child in node.named_children:
                if child.type == "dotted_name":
                    imports.append(
                        ImportInfo(
                            module=self._node_text(child, source),
                            line=node.start_point[0] + 1,
                        )
                    )
                elif child.type == "aliased_import":
                    name_node = child.child_by_field_name("name")
                    alias_node = child.child_by_field_name("alias")
                    if name_node:
                        imports.append(
                            ImportInfo(
                                module=self._node_text(name_node, source),
                                alias=(self._node_text(alias_node, source) if alias_node else None),
                                line=node.start_point[0] + 1,
                            )
                        )

        for node in self._find_nodes(root, "import_from_statement"):
            module_node = node.child_by_field_name("module_name")
            module = self._node_text(module_node, source) if module_node else ""
            names: list[str] = []
            bindings: dict[str, str] = {}
            for child in node.children:
                if child.type == "dotted_name" and child != module_node:
                    names.append(self._node_text(child, source))
                elif child.type == "aliased_import":
                    name_node = child.child_by_field_name("name")
                    alias_node = child.child_by_field_name("alias")
                    if name_node:
                        imported = self._node_text(name_node, source)
                        names.append(imported)
                        if alias_node:
                            bindings[self._node_text(alias_node, source)] = imported
            imports.append(
                ImportInfo(
                    module=module,
                    names=names,
                    bindings=bindings,
                    line=node.start_point[0] + 1,
                )
            )

    def _extract_functions(
        self,
        root: Node,
        source: bytes,
        file_path: str,
        functions: list[FunctionDef],
    ) -> None:
        for node in self._find_nodes(root, "function_definition"):
            # Skip methods (they'll be captured via class extraction)
            if node.parent and node.parent.type == "block":
                grandparent = node.parent.parent
                if grandparent and grandparent.type == "class_definition":
                    continue

            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = self._node_text(name_node, source)

            params = self._extract_params(node, source)
            decorators = self._extract_decorators(node, source)

            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    parameters=params,
                    decorators=decorators,
                )
            )

    def _extract_classes(
        self,
        root: Node,
        source: bytes,
        file_path: str,
        classes: list[ClassDef],
        all_functions: list[FunctionDef],
    ) -> None:
        for node in self._find_nodes(root, "class_definition"):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            class_name = self._node_text(name_node, source)

            bases: list[str] = []
            args_node = node.child_by_field_name("superclasses")
            if args_node:
                for child in args_node.children:
                    if child.type in ("identifier", "attribute"):
                        bases.append(self._node_text(child, source))

            decorators = self._extract_decorators(node, source)

            methods: list[FunctionDef] = []
            for method_node in self._find_nodes(node, "function_definition"):
                mn = method_node.child_by_field_name("name")
                if not mn:
                    continue
                method_name = self._node_text(mn, source)
                params = self._extract_params(method_node, source)
                method_decorators = self._extract_decorators(method_node, source)

                method = FunctionDef(
                    name=method_name,
                    qualified_name=f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_node.start_point[0] + 1,
                    line_end=method_node.end_point[0] + 1,
                    parameters=params,
                    decorators=method_decorators,
                    is_method=True,
                    class_name=class_name,
                )
                methods.append(method)
                all_functions.append(method)

            classes.append(
                ClassDef(
                    name=class_name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    base_classes=bases,
                    methods=methods,
                    decorators=decorators,
                )
            )

    def _extract_calls(
        self, root: Node, source: bytes, file_path: str, calls: list[CallSite]
    ) -> None:
        for node in self._find_nodes(root, "call"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue

            callee = self._node_text(func_node, source)
            receiver: str | None = None

            if func_node.type == "attribute":
                obj_node = func_node.child_by_field_name("object")
                attr_node = func_node.child_by_field_name("attribute")
                if obj_node and attr_node:
                    receiver = self._node_text(obj_node, source)
                    callee = self._node_text(attr_node, source)

            args: list[str] = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._node_text(child, source))

            enclosing = self._find_enclosing_function(node, source, ("function_definition",))

            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    receiver=receiver,
                    in_function=enclosing,
                )
            )

    def _extract_params(self, func_node: Node, source: bytes) -> list[str]:
        params: list[str] = []
        params_node = func_node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    params.append(self._node_text(child, source))
                elif child.type in (
                    "default_parameter",
                    "typed_parameter",
                    "typed_default_parameter",
                ):
                    name_node = child.child_by_field_name("name")
                    if name_node:
                        params.append(self._node_text(name_node, source))
        return params

    def _extract_decorators(self, node: Node, source: bytes) -> list[str]:
        decorators: list[str] = []
        # In tree-sitter Python, decorators are children of function_definition
        for child in node.children:
            if child.type == "decorator":
                text = self._node_text(child, source).strip()
                decorators.append(text)
        # Also check parent decorated_definition node
        if not decorators and node.parent and node.parent.type == "decorated_definition":
            for child in node.parent.children:
                if child.type == "decorator":
                    text = self._node_text(child, source).strip()
                    decorators.append(text)
        return decorators


class _JavaScriptExtractor(_BaseExtractor):
    """Extract JavaScript/TypeScript AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        self._extract_imports(root, source, imports)
        self._extract_functions(root, source, file_path, functions)
        self._extract_classes(root, source, file_path, classes, functions)
        self._extract_calls(root, source, file_path, calls)

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _extract_imports(self, root: Node, source: bytes, imports: list[ImportInfo]) -> None:
        for node in self._find_nodes(root, "import_statement"):
            source_node = node.child_by_field_name("source")
            module = ""
            if source_node:
                module = self._node_text(source_node, source).strip("'\"")
            names: list[str] = []
            bindings: dict[str, str] = {}
            for child in self._find_nodes(node, "import_specifier"):
                name_node = child.child_by_field_name("name")
                if name_node:
                    imported = self._node_text(name_node, source)
                    names.append(imported)
                    alias_node = child.child_by_field_name("alias")
                    if alias_node:
                        bindings[self._node_text(alias_node, source)] = imported
            statement = self._node_text(node, source)
            namespace = re.search(r"\*\s+as\s+([A-Za-z_$][\w$]*)", statement)
            default = re.match(r"\s*import\s+([A-Za-z_$][\w$]*)", statement)
            alias = namespace.group(1) if namespace else (default.group(1) if default else None)
            imports.append(
                ImportInfo(
                    module=module,
                    names=names,
                    alias=alias,
                    bindings=bindings,
                    line=node.start_point[0] + 1,
                )
            )

    def _extract_functions(
        self, root: Node, source: bytes, file_path: str, functions: list[FunctionDef]
    ) -> None:
        for type_name in ("function_declaration", "arrow_function", "function"):
            for node in self._find_nodes(root, type_name):
                name_node = node.child_by_field_name("name")
                name = self._node_text(name_node, source) if name_node else "<anonymous>"

                # For variable-assigned arrow functions
                if not name_node and node.parent:
                    if node.parent.type == "variable_declarator":
                        vn = node.parent.child_by_field_name("name")
                        if vn:
                            name = self._node_text(vn, source)

                params = self._extract_params(node, source)

                functions.append(
                    FunctionDef(
                        name=name,
                        qualified_name=name,
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                        parameters=params,
                    )
                )

    def _extract_classes(
        self,
        root: Node,
        source: bytes,
        file_path: str,
        classes: list[ClassDef],
        all_functions: list[FunctionDef],
    ) -> None:
        for node in self._find_nodes(root, "class_declaration"):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            class_name = self._node_text(name_node, source)

            bases: list[str] = []
            heritage = node.child_by_field_name("heritage")
            if heritage:
                for child in heritage.children:
                    if child.type == "identifier":
                        bases.append(self._node_text(child, source))

            methods: list[FunctionDef] = []
            for method_node in self._find_nodes(node, "method_definition"):
                mn = method_node.child_by_field_name("name")
                if not mn:
                    continue
                method_name = self._node_text(mn, source)
                params = self._extract_params(method_node, source)
                method = FunctionDef(
                    name=method_name,
                    qualified_name=f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_node.start_point[0] + 1,
                    line_end=method_node.end_point[0] + 1,
                    parameters=params,
                    is_method=True,
                    class_name=class_name,
                )
                methods.append(method)
                all_functions.append(method)

            classes.append(
                ClassDef(
                    name=class_name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    base_classes=bases,
                    methods=methods,
                )
            )

    def _extract_calls(
        self, root: Node, source: bytes, file_path: str, calls: list[CallSite]
    ) -> None:
        for node in self._find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue

            callee = self._node_text(func_node, source)
            receiver: str | None = None

            if func_node.type == "member_expression":
                obj_node = func_node.child_by_field_name("object")
                prop_node = func_node.child_by_field_name("property")
                if obj_node and prop_node:
                    receiver = self._node_text(obj_node, source)
                    callee = self._node_text(prop_node, source)

            args: list[str] = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.children:
                    if child.type not in ("(", ")", ","):
                        args.append(self._node_text(child, source))

            enclosing = self._find_enclosing_function(
                node, source, ("function_declaration", "arrow_function", "method_definition")
            )

            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    receiver=receiver,
                    in_function=enclosing,
                )
            )

    def _extract_params(self, node: Node, source: bytes) -> list[str]:
        params: list[str] = []
        params_node = node.child_by_field_name("parameters")
        if not params_node:
            params_node = node.child_by_field_name("formal_parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    params.append(self._node_text(child, source))
                elif child.type in ("required_parameter", "optional_parameter"):
                    pn = child.child_by_field_name("pattern") or child.child_by_field_name("name")
                    if pn:
                        params.append(self._node_text(pn, source))
        return params


class _JavaExtractor(_BaseExtractor):
    """Extract Java AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        # Imports
        for node in self._find_nodes(root, "import_declaration"):
            text = self._node_text(node, source).replace("import ", "").rstrip(";").strip()
            imports.append(ImportInfo(module=text, line=node.start_point[0] + 1))

        # Classes, interfaces, and methods. Interfaces are types in the JVM
        # dispatch graph and cannot be discarded if CHA/RTA is expected to
        # resolve calls through an interface-typed receiver.
        type_nodes = self._find_nodes(root, "class_declaration")
        type_nodes.extend(self._find_nodes(root, "interface_declaration"))
        for node in type_nodes:
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            class_name = self._node_text(name_node, source)

            class_annotations = self._extract_java_annotations(node, source)

            methods: list[FunctionDef] = []
            for method_node in self._find_nodes(node, "method_declaration"):
                mn = method_node.child_by_field_name("name")
                if not mn:
                    continue
                method_name = self._node_text(mn, source)
                params, parameter_types, defaults, variadic = self._extract_java_param_details(
                    method_node, source
                )
                method_annotations = self._extract_java_annotations(method_node, source)
                return_node = method_node.child_by_field_name("type")
                method = FunctionDef(
                    name=method_name,
                    qualified_name=f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_node.start_point[0] + 1,
                    line_end=method_node.end_point[0] + 1,
                    parameters=params,
                    parameter_types=parameter_types,
                    parameter_defaults=defaults,
                    variadic=variadic,
                    return_type=(self._node_text(return_node, source) if return_node else ""),
                    decorators=method_annotations,
                    is_method=True,
                    class_name=class_name,
                )
                methods.append(method)
                functions.append(method)

            bases: list[str] = []
            superclass = node.child_by_field_name("superclass")
            if superclass:
                for child in self._find_nodes(superclass, "type_identifier"):
                    bases.append(self._node_text(child, source))
            interfaces = node.child_by_field_name("interfaces")
            if interfaces:
                for child in self._find_nodes(interfaces, "type_identifier"):
                    bases.append(self._node_text(child, source))
            # tree-sitter-java does not expose the interface-declaration
            # `extends_interfaces` node as a named field.
            for child in node.children:
                if child.type == "extends_interfaces":
                    for base in self._find_nodes(child, "type_identifier"):
                        bases.append(self._node_text(base, source))

            classes.append(
                ClassDef(
                    name=class_name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    base_classes=bases,
                    methods=methods,
                    decorators=class_annotations,
                )
            )

        # Calls
        for node in self._find_nodes(root, "method_invocation"):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            callee = self._node_text(name_node, source)
            obj_node = node.child_by_field_name("object")
            receiver = self._node_text(obj_node, source) if obj_node else None

            args: list[str] = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for child in args_node.named_children:
                    args.append(self._node_text(child, source))

            enclosing_node = self._find_enclosing_node(node, ("method_declaration",))
            enclosing = self._find_enclosing_function(node, source, ("method_declaration",))
            scope_types = self._java_scope_types(enclosing_node, node, source)
            receiver_type = scope_types.get(receiver or "", "")
            argument_types = [
                self._infer_expression_type(argument, scope_types, kotlin=False)
                for argument in args
            ]
            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    argument_types=argument_types,
                    receiver=receiver,
                    receiver_type=receiver_type,
                    in_function=enclosing,
                )
            )

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _extract_java_param_details(
        self,
        node: Node,
        source: bytes,
    ) -> tuple[list[str], list[str], list[bool], bool]:
        params: list[str] = []
        types: list[str] = []
        defaults: list[bool] = []
        variadic = False
        params_node = node.child_by_field_name("parameters")
        if params_node:
            parameter_nodes = self._find_nodes(params_node, "formal_parameter")
            parameter_nodes.extend(self._find_nodes(params_node, "spread_parameter"))
            parameter_nodes.sort(key=lambda item: item.start_byte)
            for child in parameter_nodes:
                name_node = child.child_by_field_name("name")
                if name_node:
                    params.append(self._node_text(name_node, source))
                    type_node = child.child_by_field_name("type")
                    types.append(self._node_text(type_node, source) if type_node else "?")
                    defaults.append(False)
                    variadic = variadic or child.type == "spread_parameter"
        return params, types, defaults, variadic

    def _java_scope_types(
        self,
        method: Node | None,
        call: Node,
        source: bytes,
    ) -> dict[str, str]:
        if method is None:
            return {}
        names, types, _, _ = self._extract_java_param_details(method, source)
        scope = dict(zip(names, types, strict=True))
        for declaration in self._find_nodes(method, "local_variable_declaration"):
            if declaration.start_byte > call.start_byte:
                continue
            type_node = declaration.child_by_field_name("type")
            declared_type = self._node_text(type_node, source) if type_node else ""
            for variable in self._find_nodes(declaration, "variable_declarator"):
                name_node = variable.child_by_field_name("name")
                if name_node and declared_type:
                    scope[self._node_text(name_node, source)] = declared_type
        current = method.parent
        while current is not None and current.type not in {
            "class_declaration",
            "interface_declaration",
        }:
            current = current.parent
        if current is not None:
            for declaration in self._find_nodes(current, "field_declaration"):
                type_node = declaration.child_by_field_name("type")
                declared_type = self._node_text(type_node, source) if type_node else ""
                for variable in self._find_nodes(declaration, "variable_declarator"):
                    name_node = variable.child_by_field_name("name")
                    if name_node and declared_type:
                        scope.setdefault(self._node_text(name_node, source), declared_type)
        return scope

    def _extract_java_annotations(self, node: Node, source: bytes) -> list[str]:
        """Extract Java annotations (e.g., @GetMapping, @PreAuthorize)."""
        annotations: list[str] = []
        for child in node.children:
            if child.type in ("marker_annotation", "annotation"):
                text = self._node_text(child, source).strip()
                annotations.append(text)
            elif child.type == "modifiers":
                for mod in child.children:
                    if mod.type in ("marker_annotation", "annotation"):
                        text = self._node_text(mod, source).strip()
                        annotations.append(text)
        return annotations


class _GoExtractor(_BaseExtractor):
    """Extract Go AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        # Imports
        for node in self._find_nodes(root, "import_spec"):
            path_node = node.child_by_field_name("path")
            if path_node:
                module = self._node_text(path_node, source).strip('"')
                imports.append(ImportInfo(module=module, line=node.start_point[0] + 1))

        # Functions
        for node in self._find_nodes(root, "function_declaration"):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = self._node_text(name_node, source)
            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                )
            )

        # Method declarations
        for node in self._find_nodes(root, "method_declaration"):
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = self._node_text(name_node, source)
            receiver_node = node.child_by_field_name("receiver")
            class_name = ""
            if receiver_node:
                for child in receiver_node.children:
                    if child.type == "type_identifier":
                        class_name = self._node_text(child, source)
                    elif child.type == "pointer_type":
                        class_name = self._node_text(child, source).lstrip("*")

            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=f"{class_name}.{name}" if class_name else name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    is_method=bool(class_name),
                    class_name=class_name or None,
                )
            )

        # Calls
        for node in self._find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                continue
            callee = self._node_text(func_node, source)
            receiver: str | None = None

            if func_node.type == "selector_expression":
                operand = func_node.child_by_field_name("operand")
                field = func_node.child_by_field_name("field")
                if operand and field:
                    receiver = self._node_text(operand, source)
                    callee = self._node_text(field, source)

            enclosing = self._find_enclosing_function(
                node, source, ("function_declaration", "method_declaration")
            )
            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    receiver=receiver,
                    in_function=enclosing,
                )
            )

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            imports=imports,
            calls=calls,
        )


class _RustExtractor(_BaseExtractor):
    """Extract Rust AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        # Imports (use declarations)
        for node in self._find_nodes(root, "use_declaration"):
            text = self._node_text(node, source).removeprefix("use ").rstrip(";").strip()
            imports.append(ImportInfo(module=text, line=node.start_point[0] + 1))

        # Top-level functions
        for node in self._find_nodes(root, "function_item"):
            # Skip methods inside impl blocks (handled separately)
            if node.parent and node.parent.type == "declaration_list":
                continue
            name_node = node.child_by_field_name("name")
            if not name_node:
                continue
            name = self._node_text(name_node, source)
            params = self._extract_rust_params(node, source)
            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    parameters=params,
                )
            )

        # Impl blocks (struct methods)
        for impl_node in self._find_nodes(root, "impl_item"):
            # Get the struct/type name
            type_node = None
            for child in impl_node.children:
                if child.type == "type_identifier":
                    type_node = child
                    break
            struct_name = self._node_text(type_node, source) if type_node else ""

            methods: list[FunctionDef] = []
            decl_list = None
            for child in impl_node.children:
                if child.type == "declaration_list":
                    decl_list = child
                    break
            if decl_list:
                for method_node in self._find_nodes(decl_list, "function_item"):
                    mn = method_node.child_by_field_name("name")
                    if not mn:
                        continue
                    method_name = self._node_text(mn, source)
                    params = self._extract_rust_params(method_node, source)
                    method = FunctionDef(
                        name=method_name,
                        qualified_name=(
                            f"{struct_name}.{method_name}" if struct_name else method_name
                        ),
                        file_path=file_path,
                        line_start=method_node.start_point[0] + 1,
                        line_end=method_node.end_point[0] + 1,
                        parameters=params,
                        is_method=bool(struct_name),
                        class_name=struct_name or None,
                    )
                    methods.append(method)
                    functions.append(method)

            if struct_name:
                classes.append(
                    ClassDef(
                        name=struct_name,
                        file_path=file_path,
                        line_start=impl_node.start_point[0] + 1,
                        line_end=impl_node.end_point[0] + 1,
                        methods=methods,
                    )
                )

        # Call expressions
        for node in self._find_nodes(root, "call_expression"):
            func_node = node.child_by_field_name("function")
            if not func_node:
                # tree-sitter-rust: first child is the function expression
                if node.child_count > 0:
                    func_node = node.children[0]
                else:
                    continue

            callee = self._node_text(func_node, source)
            receiver: str | None = None

            # field_expression: obj.method(...)
            if func_node.type == "field_expression":
                value_node = func_node.child_by_field_name("value")
                field_node = func_node.child_by_field_name("field")
                if value_node and field_node:
                    receiver = self._node_text(value_node, source)
                    callee = self._node_text(field_node, source)
            # scoped_identifier: Type::method(...)
            elif func_node.type == "scoped_identifier":
                parts = callee.split("::")
                if len(parts) >= 2:
                    receiver = "::".join(parts[:-1])
                    callee = parts[-1]

            args: list[str] = []
            for child in node.children:
                if child.type == "arguments":
                    for arg_child in child.children:
                        if arg_child.type not in ("(", ")", ","):
                            args.append(self._node_text(arg_child, source))

            enclosing = self._find_enclosing_function(node, source, ("function_item",))
            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    receiver=receiver,
                    in_function=enclosing,
                )
            )

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _extract_rust_params(self, node: Node, source: bytes) -> list[str]:
        params: list[str] = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "parameter":
                    pattern = child.child_by_field_name("pattern")
                    if pattern:
                        params.append(self._node_text(pattern, source))
                elif child.type == "self_parameter":
                    params.append("self")
        return params


class _SwiftExtractor(_BaseExtractor):
    """Extract Swift AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        # Imports
        for node in self._find_nodes(root, "import_declaration"):
            text = self._node_text(node, source).removeprefix("import ").strip()
            imports.append(ImportInfo(module=text, line=node.start_point[0] + 1))

        # Top-level functions (not inside class)
        for node in self._find_nodes(root, "function_declaration"):
            if self._is_inside_class(node):
                continue
            name = self._swift_func_name(node, source)
            if not name:
                continue
            params = self._extract_swift_params(node, source)
            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    parameters=params,
                )
            )

        # Classes
        for node in self._find_nodes(root, "class_declaration"):
            class_name = ""
            for child in node.children:
                if child.type == "type_identifier":
                    class_name = self._node_text(child, source)
                    break

            if not class_name:
                continue

            methods: list[FunctionDef] = []
            for method_node in self._find_nodes(node, "function_declaration"):
                method_name = self._swift_func_name(method_node, source)
                if not method_name:
                    continue
                params = self._extract_swift_params(method_node, source)
                method = FunctionDef(
                    name=method_name,
                    qualified_name=f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_node.start_point[0] + 1,
                    line_end=method_node.end_point[0] + 1,
                    parameters=params,
                    is_method=True,
                    class_name=class_name,
                )
                methods.append(method)
                functions.append(method)

            bases: list[str] = []
            for child in node.children:
                if child.type == "inheritance_specifier":
                    for inherit_child in child.children:
                        if inherit_child.type in ("type_identifier", "user_type"):
                            bases.append(self._node_text(inherit_child, source))

            classes.append(
                ClassDef(
                    name=class_name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    base_classes=bases,
                    methods=methods,
                )
            )

        # Call expressions
        for node in self._find_nodes(root, "call_expression"):
            callee = ""
            receiver: str | None = None

            for child in node.children:
                if child.type == "navigation_expression":
                    # e.g., process.run or URLSession.shared.dataTask
                    text = self._node_text(child, source)
                    parts = text.rsplit(".", 1)
                    if len(parts) == 2:
                        receiver = parts[0]
                        callee = parts[1]
                    else:
                        callee = text
                    break
                elif child.type == "simple_identifier":
                    callee = self._node_text(child, source)
                    break

            if not callee:
                continue

            args: list[str] = []
            for child in node.children:
                if child.type == "call_suffix":
                    for arg_child in child.children:
                        if arg_child.type == "value_argument":
                            args.append(self._node_text(arg_child, source))
                        elif arg_child.type not in ("(", ")", ","):
                            text = self._node_text(arg_child, source).strip("()")
                            if text:
                                args.append(text)

            enclosing = self._find_enclosing_function(node, source, ("function_declaration",))
            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    receiver=receiver,
                    in_function=enclosing,
                )
            )

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _swift_func_name(self, node: Node, source: bytes) -> str | None:
        for child in node.children:
            if child.type == "simple_identifier":
                return self._node_text(child, source)
        return None

    def _is_inside_class(self, node: Node) -> bool:
        current = node.parent
        while current:
            if current.type in ("class_body", "class_declaration"):
                return True
            current = current.parent
        return False

    def _extract_swift_params(self, node: Node, source: bytes) -> list[str]:
        params: list[str] = []
        for child in node.children:
            if child.type == "parameter":
                for param_child in child.children:
                    if param_child.type == "simple_identifier":
                        params.append(self._node_text(param_child, source))
                        break
        return params


class _KotlinExtractor(_BaseExtractor):
    """Extract Kotlin AST information."""

    def extract(self, root: Node, source: bytes, file_path: str, lang: Lang) -> FileAST:
        functions: list[FunctionDef] = []
        classes: list[ClassDef] = []
        imports: list[ImportInfo] = []
        calls: list[CallSite] = []

        # Imports
        for node in self._find_nodes(root, "import"):
            for child in node.children:
                if child.type == "qualified_identifier":
                    module = self._node_text(child, source)
                    imports.append(ImportInfo(module=module, line=node.start_point[0] + 1))
                    break

        # Top-level functions
        for node in self._find_nodes(root, "function_declaration"):
            if self._is_inside_class(node):
                continue
            name_node = self._kotlin_func_name_node(node, source)
            if not name_node:
                continue
            name = self._node_text(name_node, source)
            params, parameter_types, defaults, variadic = self._extract_kotlin_param_details(
                node, source
            )
            decorators = self._extract_kotlin_annotations(node, source)
            functions.append(
                FunctionDef(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    parameters=params,
                    parameter_types=parameter_types,
                    parameter_defaults=defaults,
                    variadic=variadic,
                    decorators=decorators,
                )
            )

        # Classes
        for node in self._find_nodes(root, "class_declaration"):
            class_name = ""
            for child in node.children:
                if child.type == "identifier":
                    class_name = self._node_text(child, source)
                    break

            if not class_name:
                continue

            class_decorators = self._extract_kotlin_annotations(node, source)

            methods: list[FunctionDef] = []
            for method_node in self._find_nodes(node, "function_declaration"):
                mn = self._kotlin_func_name_node(method_node, source)
                if not mn:
                    continue
                method_name = self._node_text(mn, source)
                params, parameter_types, defaults, variadic = self._extract_kotlin_param_details(
                    method_node, source
                )
                method_decorators = self._extract_kotlin_annotations(method_node, source)
                method = FunctionDef(
                    name=method_name,
                    qualified_name=f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_node.start_point[0] + 1,
                    line_end=method_node.end_point[0] + 1,
                    parameters=params,
                    parameter_types=parameter_types,
                    parameter_defaults=defaults,
                    variadic=variadic,
                    decorators=method_decorators,
                    is_method=True,
                    class_name=class_name,
                )
                methods.append(method)
                functions.append(method)

            bases: list[str] = []
            for child in node.children:
                if child.type == "delegation_specifiers":
                    for spec in child.children:
                        if spec.type in ("user_type", "delegation_specifier"):
                            bases.append(self._node_text(spec, source))

            classes.append(
                ClassDef(
                    name=class_name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    base_classes=bases,
                    methods=methods,
                    decorators=class_decorators,
                )
            )

        # Call expressions
        for node in self._find_nodes(root, "call_expression"):
            callee = ""
            receiver: str | None = None

            for child in node.children:
                if child.type == "navigation_expression":
                    text = self._node_text(child, source)
                    parts = text.rsplit(".", 1)
                    if len(parts) == 2:
                        receiver = parts[0]
                        callee = parts[1]
                    else:
                        callee = text
                    break
                elif child.type == "identifier" or child.type == "simple_identifier":
                    callee = self._node_text(child, source)
                    break

            if not callee:
                continue

            args: list[str] = []
            for child in node.children:
                if child.type == "value_arguments":
                    for arg_child in child.children:
                        if arg_child.type == "value_argument":
                            args.append(self._node_text(arg_child, source))
                        elif arg_child.type not in ("(", ")", ","):
                            text = self._node_text(arg_child, source).strip()
                            if text:
                                args.append(text)

            enclosing = self._find_enclosing_function(node, source, ("function_declaration",))
            enclosing_node = self._find_enclosing_node(node, ("function_declaration",))
            scope_types = self._kotlin_scope_types(enclosing_node, node, source)
            receiver_type = scope_types.get(receiver or "", "")
            argument_types = [
                self._infer_expression_type(argument, scope_types, kotlin=True) for argument in args
            ]
            calls.append(
                CallSite(
                    callee=callee,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    arguments=args,
                    argument_types=argument_types,
                    receiver=receiver,
                    receiver_type=receiver_type,
                    in_function=enclosing,
                )
            )

        self._extract_kotlin_fallback_member_calls(
            functions,
            source,
            file_path,
            calls,
        )

        return FileAST(
            file_path=file_path,
            language=lang,
            functions=functions,
            classes=classes,
            imports=imports,
            calls=calls,
        )

    def _extract_kotlin_fallback_member_calls(
        self,
        functions: list[FunctionDef],
        source: bytes,
        file_path: str,
        calls: list[CallSite],
    ) -> None:
        """Recover member calls represented as ERROR/user_type by the grammar.

        The pinned tree-sitter-kotlin grammar can recover a valid expression
        such as ``port.run(value)`` without a ``call_expression`` node.  Keep
        the fallback function-bounded and deduplicate it against structural
        calls instead of silently losing Spring/Kotlin dispatch evidence.
        """

        text = source.decode("utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        existing = {(call.line, call.column, call.receiver, call.callee) for call in calls}
        member_call = re.compile(
            r"(?P<receiver>[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*)"
            r"\s*\.\s*(?P<callee>[a-zA-Z_$][\w$]*)\s*"
            r"\((?P<arguments>[^()]*?)\)"
        )
        for function in functions:
            start = max(function.line_start - 1, 0)
            snippet = "".join(lines[start : function.line_end])
            scope_types = dict(zip(function.parameters, function.parameter_types, strict=False))
            for match in member_call.finditer(snippet):
                prefix = snippet[: match.start()]
                line = function.line_start + prefix.count("\n")
                line_prefix = prefix.rsplit("\n", 1)[-1]
                column = len(line_prefix)
                receiver = match.group("receiver")
                callee = match.group("callee")
                identity = (line, column, receiver, callee)
                if identity in existing:
                    continue
                arguments = self._split_kotlin_call_arguments(match.group("arguments"))
                calls.append(
                    CallSite(
                        callee=callee,
                        file_path=file_path,
                        line=line,
                        column=column,
                        arguments=arguments,
                        argument_types=[
                            self._infer_expression_type(
                                argument,
                                scope_types,
                                kotlin=True,
                            )
                            for argument in arguments
                        ],
                        receiver=receiver,
                        receiver_type=scope_types.get(receiver, ""),
                        in_function=function.name,
                    )
                )
                existing.add(identity)

    @staticmethod
    def _split_kotlin_call_arguments(value: str) -> list[str]:
        if not value.strip():
            return []
        result: list[str] = []
        start = 0
        depth = 0
        for index, character in enumerate(value):
            if character in "<[{":
                depth += 1
            elif character in ">]}" and depth:
                depth -= 1
            elif character == "," and depth == 0:
                result.append(value[start:index].strip())
                start = index + 1
        result.append(value[start:].strip())
        return [item for item in result if item]

    def _kotlin_func_name_node(self, node: Node, source: bytes) -> Node | None:
        for child in node.children:
            if child.type == "identifier":
                return child
        return None

    def _is_inside_class(self, node: Node) -> bool:
        current = node.parent
        while current:
            if current.type in ("class_body", "class_declaration"):
                return True
            current = current.parent
        return False

    def _extract_kotlin_param_details(
        self,
        node: Node,
        source: bytes,
    ) -> tuple[list[str], list[str], list[bool], bool]:
        params: list[str] = []
        types: list[str] = []
        defaults: list[bool] = []
        variadic = False
        for child in node.children:
            if child.type == "function_value_parameters":
                pending_vararg = False
                children = list(child.children)
                for index, param_child in enumerate(children):
                    if param_child.type == "parameter_modifiers":
                        pending_vararg = "vararg" in self._node_text(param_child, source)
                        continue
                    if param_child.type == "parameter":
                        text = self._node_text(param_child, source).strip()
                        match = re.search(
                            r"(?P<name>[A-Za-z_$][\w$]*)\s*:\s*"
                            r"(?P<type>[^=]+?)(?:\s*=|$)",
                            text,
                        )
                        if not match:
                            continue
                        params.append(match.group("name"))
                        types.append(match.group("type").strip())
                        defaults.append(
                            index + 1 < len(children) and children[index + 1].type == "="
                        )
                        variadic = variadic or pending_vararg
                        pending_vararg = False
        return params, types, defaults, variadic

    def _kotlin_scope_types(
        self,
        function: Node | None,
        call: Node,
        source: bytes,
    ) -> dict[str, str]:
        if function is None:
            return {}
        names, types, _, _ = self._extract_kotlin_param_details(function, source)
        scope = dict(zip(names, types, strict=True))
        for declaration in self._find_nodes(function, "property_declaration"):
            if declaration.start_byte > call.start_byte:
                continue
            text = self._node_text(declaration, source).strip()
            explicit = re.search(
                r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)\s*:\s*"
                r"([^=\n]+)",
                text,
            )
            if explicit:
                scope[explicit.group(1)] = explicit.group(2).strip()
                continue
            inferred = re.search(
                r"\b(?:val|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)",
                text,
                re.DOTALL,
            )
            if inferred:
                inferred_type = self._infer_expression_type(inferred.group(2), scope, kotlin=True)
                if inferred_type:
                    scope[inferred.group(1)] = inferred_type
        return scope

    def _extract_kotlin_annotations(self, node: Node, source: bytes) -> list[str]:
        """Extract Kotlin annotations (e.g., @GetMapping, @PreAuthorize)."""
        annotations: list[str] = []
        # Kotlin tree-sitter: annotations are in modifiers child
        for child in node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    if mod.type == "annotation":
                        text = self._node_text(mod, source).strip()
                        annotations.append(text)
        # Also check direct annotation children (varies by tree-sitter version)
        for child in node.children:
            if child.type == "annotation":
                text = self._node_text(child, source).strip()
                annotations.append(text)
        return annotations


# Extractor registry
_EXTRACTORS: dict[Lang, _BaseExtractor] = {}


def _get_extractor(lang: Lang) -> _BaseExtractor:
    if lang not in _EXTRACTORS:
        match lang:
            case Lang.PYTHON:
                _EXTRACTORS[lang] = _PythonExtractor()
            case Lang.JAVASCRIPT | Lang.TYPESCRIPT:
                _EXTRACTORS[lang] = _JavaScriptExtractor()
            case Lang.JAVA:
                _EXTRACTORS[lang] = _JavaExtractor()
            case Lang.GO:
                _EXTRACTORS[lang] = _GoExtractor()
            case Lang.RUST:
                _EXTRACTORS[lang] = _RustExtractor()
            case Lang.SWIFT:
                _EXTRACTORS[lang] = _SwiftExtractor()
            case Lang.KOTLIN:
                _EXTRACTORS[lang] = _KotlinExtractor()
    return _EXTRACTORS[lang]
