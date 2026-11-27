"""Recognize local Python expressions whose normal result is a built-in string."""

from __future__ import annotations

import ast
from collections.abc import Iterator

from aegify.scanner.python_requests import request_collection
from aegify.scanner.python_scope import PythonScope, function_scopes
from aegify.scanner.python_storage import LocalValues

_REQUEST_STRINGS = {
    "flask.request.args",
    "flask.request.form",
    "flask.request.headers",
    "flask.request.cookies",
    "flask.request.values",
}


class TextValues(LocalValues):
    def __init__(self, scope: PythonScope) -> None:
        super().__init__(scope)
        self.string_types: dict[tuple[ast.expr, int], bool] = {}

    def string_value(self, node: ast.expr, depth: int = 0) -> bool:
        """Check the type of a local value before trusting string-specific operations."""
        if depth >= 12:
            return False
        key = node, depth
        if key not in self.string_types:
            self.string_types[key] = self._string_value(node, depth)
        return self.string_types[key]

    def _string_value(self, node: ast.expr, depth: int) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.IfExp):
            return self.string_value(node.body, depth + 1) and self.string_value(
                node.orelse, depth + 1
            )
        if isinstance(node, ast.Name):
            if node.id in self.closed_over:
                return False
            if (value := self.assigned(node)) is not None:
                return self.string_value(value, depth + 1)
            stores = self.stores.get(node.id, [])
            if len(stores) != self.scope.definitions.get(node.id, 0) or len(stores) > 8:
                return False
            if len(stores) == 1:
                parent = self.scope.parents[stores[0]]
                if (
                    isinstance(parent, ast.For)
                    and parent.target is stores[0]
                    and parent.lineno <= node.lineno
                ):
                    iteration = request_collection(self.scope, parent.iter)
                    return iteration is not None and not iteration[1]
            # For a conditional store, every possible preceding value must be a string.
            possible = [self.scope.parents[n] for n in stores if n.lineno < node.lineno]
            return (
                bool(possible)
                and all(
                    (
                        isinstance(stmt, ast.Assign | ast.AnnAssign)
                        or isinstance(stmt, ast.AugAssign)
                        and isinstance(stmt.op, ast.Add)
                    )
                    and stmt.value is not None
                    and self.string_value(stmt.value, depth + 1)
                    for stmt in possible
                )
                and not self.in_loop(node)
            )
        if stored := self.stored_source(node):
            return self.string_value(stored[0], depth + 1)
        if isinstance(node, ast.Subscript):
            if self.scope.resolve(node.value) in _REQUEST_STRINGS:
                return True
            collection = self.assigned(node.value) or node.value
            if isinstance(collection, ast.Call) and isinstance(collection.func, ast.Attribute):
                if (
                    collection.func.attr in {"getlist", "get_all"}
                    and self.scope.resolve(collection.func.value) in _REQUEST_STRINGS
                    and len(collection.args) == 1
                    and not collection.keywords
                    and isinstance(node.slice, ast.Constant)
                    and type(node.slice.value) is int
                ):
                    return True
            return self.string_value(node.value, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.string_value(node.left, depth + 1) and self.string_value(
                node.right, depth + 1
            )
        if not isinstance(node, ast.Call):
            return False
        name = self.scope.resolve(node.func)
        if name in {"urllib.parse.unquote", "urllib.parse.unquote_plus", "builtins.str"}:
            return True
        if isinstance(node.func, ast.Name):
            return node.func.id == "str" and "str" not in self.scope.hidden
        if not isinstance(node.func, ast.Attribute):
            return False
        receiver = node.func.value
        if self.scope.resolve(receiver) in _REQUEST_STRINGS and node.func.attr == "get":
            # The optional converter and arbitrary defaults can change the result type.
            return (
                not node.keywords
                and len(node.args) in {1, 2}
                and all(
                    isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    for arg in node.args
                )
            )
        if node.func.attr == "decode":
            value = self.assigned(receiver) or receiver
            return self.scope.resolve(value) in {
                "flask.request.data",
                "flask.request.query_string",
            } or (
                isinstance(value, ast.Call)
                and self.scope.resolve(value.func)
                in {"base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode"}
            )
        return False


def _scalar_parameters(scope: PythonScope, arguments: ast.arguments) -> set[str]:
    """Annotations add a possible scalar flow and never establish an input is safe."""
    result: set[str] = set()
    for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs):
        if arg.annotation is None or scope.definitions.get(arg.arg) != 1:
            continue
        name = scope.resolve(arg.annotation)
        if isinstance(arg.annotation, ast.Name) and arg.annotation.id not in scope.hidden:
            name = "builtins." + arg.annotation.id
        if name in {"builtins.str", "builtins.bytes"} and name not in scope.modified:
            result.add(arg.arg)
    return result


def iteration_bindings(source: bytes) -> Iterator[tuple[tuple[int, str], int, str, list[str], str]]:
    if b"for" not in source:
        return
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    for scope in function_scopes(source):
        assert isinstance(scope.owner, ast.FunctionDef | ast.AsyncFunctionDef)
        loops = [node for node in scope.nodes if isinstance(node, ast.For)]
        if not loops:
            continue
        local = TextValues(scope)
        scalar_parameters = _scalar_parameters(scope, scope.owner.args)
        for loop in loops:
            origin = request_collection(scope, loop.iter)
            if origin:
                operand, pairs = origin
                kind = "request_iteration"
            elif isinstance(loop.iter, ast.Name) and (
                loop.iter.id in scalar_parameters
                or local.string_value(loop.iter)
                or scope.resolve(local.assigned(loop.iter) or loop.iter)
                in {"flask.request.data", "flask.request.query_string"}
            ):
                operand, pairs = loop.iter.id, False
                kind = "value_iteration"
            else:
                continue
            if isinstance(loop.target, ast.Name):
                names = [loop.target.id]
            elif (
                pairs
                and isinstance(loop.target, ast.Tuple | ast.List)
                and len(loop.target.elts) == 2
            ):
                names = [part.id for part in loop.target.elts if isinstance(part, ast.Name)]
                if len(names) != 2:
                    continue
            else:
                continue
            yield (
                (scope.owner.lineno, scope.owner.name),
                offsets[loop.lineno - 1] + loop.col_offset,
                kind,
                names,
                operand,
            )
