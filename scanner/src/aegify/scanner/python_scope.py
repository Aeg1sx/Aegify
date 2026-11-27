"""Resolve stable Python imports within lexical scopes without importing scanned code."""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from importlib.util import resolve_name
from pathlib import PurePosixPath

from aegify.models import FileAST


class PythonModules:
    def __init__(self, files: list[FileAST]) -> None:
        self.counts = Counter(
            (file.repository_id, module_name(file.module_path))
            for file in files
            if file.module_path.endswith(".py")
        )
        self.packages = {(repo, name.partition(".")[0]) for repo, name in self.counts if name}
        self.custom_request_data = {
            file.repository_id for file in files if file.python_custom_request_data
        }

    def external(self, file: FileAST, api: str) -> bool:
        return (file.repository_id, api.partition(".")[0]) not in self.packages


type ScopeNode = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
type Imports = dict[str, tuple[str, int]]


def module_name(module_path: str) -> str:
    path = PurePosixPath(module_path)
    parts = list(path.with_suffix("").parts) if path.suffix == ".py" else []
    if parts[:1] == ["src"]:
        parts.pop(0)
    if parts[-1:] == ["__init__"]:
        parts.pop()
    return ".".join(parts) if all(p.isidentifier() for p in parts) else ""


def imported_name(module_path: str, reference: str) -> str:
    if not reference.startswith("."):
        return reference
    module = module_name(module_path)
    package = (
        module if PurePosixPath(module_path).name == "__init__.py" else module.rpartition(".")[0]
    )
    try:
        return resolve_name(reference, package)
    except ImportError, ValueError:
        return ""


_SCOPED_EXPRESSIONS = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

SANITIZER_DOMAINS = {
    "html.escape": ["xss"],
    "markupsafe.escape": ["xss"],
    "bleach.clean": ["xss"],
    "shlex.quote": ["os_command"],
    # Legacy modeled validation hooks used by the core corpus. A local
    # implementation or rebinding takes precedence over the name convention.
    "validate_path": ["file_access", "file_metadata"],
    "validate_command": ["os_command"],
}


def call_argument(call: ast.Call, index: int, keyword: str) -> tuple[int, ast.expr] | None:
    """Select a fixed positional or named argument in source order."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        item.arg is None for item in call.keywords
    ):
        return None
    if index < len(call.args):
        if any(item.arg == keyword for item in call.keywords):
            return None
        return index, call.args[index]
    return next(
        (
            (len(call.args) + i, item.value)
            for i, item in enumerate(call.keywords)
            if item.arg == keyword
        ),
        None,
    )


@dataclass
class PythonScope:
    owner: ScopeNode
    nodes: list[ast.AST]
    parents: dict[ast.AST, ast.AST]
    imports: Imports
    definitions: dict[str, int]
    hidden: set[str]
    modified: set[str]

    def resolve(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            name, line = self.imports.get(node.id, ("", 0))
            return name if line <= node.lineno and name not in self.modified else ""
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            name = f"{base}.{node.attr}"
            return name if base and name not in self.modified else ""
        return ""

    def precedes(self, assignment: ast.stmt, use: ast.expr) -> bool:
        """Prove the statement ran on the path to the use, including a try's success arm."""
        container = self.parents[assignment]
        cursor: ast.AST = use
        while cursor in self.parents and self.parents[cursor] is not container:
            cursor = self.parents[cursor]
        if not isinstance(cursor, ast.stmt) or assignment.lineno >= cursor.lineno:
            return False
        # Only normal completion of the entire try suite enters else. A nested
        # conditional write, an exception handler and finally lack that guarantee.
        if isinstance(container, ast.Try | ast.TryStar) and cursor in container.orelse:
            if assignment in container.body:
                return True
        return any(
            isinstance(body, list) and assignment in body and cursor in body
            for _, body in ast.iter_fields(container)
        )


type _Condition = tuple[ast.expr, bool]


def _exits(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], ast.Return | ast.Raise)


def _previous(statements: list[ast.stmt], depth: int = 0) -> Iterator[_Condition]:
    if depth >= 8:
        return
    for stmt in reversed(statements[-64:]):
        if isinstance(stmt, ast.If):
            if _exits(stmt.body):
                yield stmt.test, False
            if _exits(stmt.orelse):
                yield stmt.test, True
        elif (
            isinstance(stmt, ast.Try)
            and not stmt.finalbody
            and all(_exits(h.body) for h in stmt.handlers)
        ):
            # Only the successful path reaches the following statement.
            yield from _previous(stmt.orelse, depth + 1)
            yield from _previous(stmt.body, depth + 1)


def _conditions(scope: PythonScope, node: ast.AST) -> Iterator[_Condition]:
    cursor: ast.AST = node
    while cursor in scope.parents:
        owner = scope.parents[cursor]
        if isinstance(cursor, ast.stmt):
            if isinstance(owner, ast.If):
                if cursor in owner.body:
                    yield owner.test, True
                elif cursor in owner.orelse:
                    yield owner.test, False
            for _, siblings in ast.iter_fields(owner):
                if isinstance(siblings, list) and cursor in siblings:
                    yield from _previous(siblings[: siblings.index(cursor)])
                    break
            if isinstance(owner, ast.ExceptHandler) or (
                isinstance(owner, ast.Try | ast.TryStar) and cursor in owner.finalbody
            ):
                return
        cursor = owner


def _facts(test: ast.expr, truth: bool, depth: int = 0) -> Iterator[_Condition]:
    if depth >= 12:
        return
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        yield from _facts(test.operand, not truth, depth + 1)
    elif isinstance(test, ast.BoolOp) and (
        (truth and isinstance(test.op, ast.And)) or (not truth and isinstance(test.op, ast.Or))
    ):
        for value in test.values:
            yield from _facts(value, truth, depth + 1)
    else:
        yield test, truth


def dominating_facts(scope: PythonScope, node: ast.AST) -> Iterator[_Condition]:
    """Atomic branch outcomes required to reach a node inside this lexical scope."""
    for condition, outcome in _conditions(scope, node):
        yield from _facts(condition, outcome)


def _scopes(
    owner: ScopeNode, inherited: Imports, outer_hidden: set[str], outer_modified: set[str]
) -> Iterator[PythonScope]:
    bindings = inherited.copy()
    definitions: dict[str, list[tuple[str, int]]] = defaultdict(list)
    children: list[ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = []
    parents: dict[ast.AST, ast.AST] = {}
    nodes: list[ast.AST] = []
    mutations: list[ast.Attribute] = []
    direct = set(owner.body)
    pending: list[tuple[ast.AST, ast.AST]] = [(owner, item) for item in owner.body]
    if isinstance(owner, ast.FunctionDef | ast.AsyncFunctionDef):
        pending.append((owner, owner.args))
    while pending:
        parent, node = pending.pop()
        parents[node] = parent
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            definitions[node.name].append(("", node.lineno))
            children.append(node)
            continue
        if isinstance(node, _SCOPED_EXPRESSIONS):
            # Assignment expressions in comprehensions can bind an enclosing name.
            for inner in ast.walk(node):
                if isinstance(inner, ast.NamedExpr) and isinstance(inner.target, ast.Name):
                    definitions[inner.target.id].append(("", inner.lineno))
            continue
        nodes.append(node)
        if isinstance(node, ast.Import | ast.ImportFrom):
            for item in node.names:
                if item.name == "*":
                    return
                name = item.asname or item.name.split(".")[0]
                if isinstance(node, ast.ImportFrom):
                    prefix = f"{node.module}." if node.module else ""
                    exported = f"{'.' * node.level}{prefix}{item.name}"
                else:
                    exported = item.name if item.asname else name
                definitions[name].append((exported if node in direct else "", node.lineno))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            definitions[node.id].append(("", node.lineno))
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
            mutations.append(node)
        elif isinstance(node, ast.arg):
            definitions[node.arg].append(("", node.lineno))
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            definitions[node.name].append(("", node.lineno))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            definitions[node.rest].append(("", node.lineno))
        elif isinstance(node, ast.Global | ast.Nonlocal):
            for name in node.names:
                definitions[name].append(("", node.lineno))
        pending.extend((node, child) for child in ast.iter_child_nodes(node))
    for name, bindings_here in definitions.items():
        bindings.pop(name, None)
        origins = {origin for origin, _ in bindings_here}
        if len(origins) == 1 and bindings_here[0][0]:
            # For example, importing both xml.sax and xml.dom binds the same root.
            bindings[name] = min(bindings_here, key=lambda binding: binding[1])
    hidden = outer_hidden | definitions.keys()
    scope = PythonScope(
        owner,
        nodes,
        parents,
        bindings,
        {n: len(v) for n, v in definitions.items()},
        hidden,
        outer_modified.copy(),
    )
    scope.modified.update(filter(None, [scope.resolve(node) for node in mutations]))
    yield scope
    for child in children:
        if isinstance(owner, ast.ClassDef):
            yield from _scopes(child, inherited, outer_hidden, outer_modified)
        else:
            yield from _scopes(child, bindings, hidden, scope.modified)


def python_scopes(source: bytes | ast.Module) -> Iterator[PythonScope]:
    try:
        module = source if isinstance(source, ast.Module) else ast.parse(source)
        yield from _scopes(module, {}, set(), set())
    except SyntaxError, ValueError, RecursionError:
        return


def function_scopes(source: bytes) -> Iterator[PythonScope]:
    for scope in python_scopes(source):
        if isinstance(scope.owner, ast.FunctionDef | ast.AsyncFunctionDef):
            yield scope


def assigned_sanitizers(source: bytes) -> dict[tuple[int, int, int, int], str]:
    """Prove an imported encoder produced the whole assigned value with default options."""
    if not any(api.split(".")[0].encode() in source for api in SANITIZER_DOMAINS):
        return {}
    matched = {}
    for scope in function_scopes(source):
        for stmt in scope.nodes:
            if not isinstance(stmt, ast.Assign | ast.AnnAssign) or not isinstance(
                stmt.value, ast.Call
            ):
                continue
            call = stmt.value
            if len(call.args) != 1 or call.keywords or isinstance(call.args[0], ast.Starred):
                continue
            api = scope.resolve(call.func)
            if (
                isinstance(call.func, ast.Name)
                and call.func.id in {"validate_path", "validate_command"}
                and call.func.id not in scope.hidden
            ):
                api = call.func.id
            if (
                api in SANITIZER_DOMAINS
                and call.end_lineno is not None
                and call.end_col_offset is not None
            ):
                matched[(call.lineno, call.col_offset, call.end_lineno, call.end_col_offset)] = api
    return matched
