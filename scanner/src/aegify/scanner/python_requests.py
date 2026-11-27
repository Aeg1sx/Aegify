"""Resolve request collections and standard-library download destinations."""

from __future__ import annotations

import ast
import re

from aegify.models import PythonCallOperand
from aegify.scanner.python_scope import PythonScope, call_argument, python_scopes

# A literal separator after the authority keeps appended data in the path,
# query or fragment. A fixed scheme alone does not establish the destination.
_ORIGIN_PREFIX = re.compile(
    r"^https?://(?:\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::[0-9]{1,5})?[/\?#]",
    re.ASCII | re.I,
)


def _fixed_origin(node: ast.expr) -> bool:
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.left
    if isinstance(node, ast.JoinedStr) and node.values:
        node = node.values[0]
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _ORIGIN_PREFIX.match(node.value) is not None
    )


def download_urls(source: bytes) -> dict[tuple[int, int, int, int], PythonCallOperand]:
    if b"urlretrieve" not in source:
        return {}
    found = {}
    for scope in python_scopes(source):
        for call in scope.nodes:
            if (
                not isinstance(call, ast.Call)
                or call.end_lineno is None
                or call.end_col_offset is None
            ):
                continue
            api = scope.resolve(call.func)
            if api != "urllib.request.urlretrieve":
                continue
            operand = call_argument(call, 0, "url")
            if not operand or isinstance(operand[1], ast.Constant) or _fixed_origin(operand[1]):
                continue
            key = call.lineno, call.col_offset, call.end_lineno, call.end_col_offset
            found[key] = PythonCallOperand(api=api, argument_index=operand[0])
    return found


_COLLECTIONS = {
    "flask.request.args",
    "flask.request.form",
    "flask.request.headers",
    "flask.request.cookies",
    "flask.request.values",
}
_REQUEST_HOOKS = {
    "request_class",
    "parameter_storage_class",
    "dict_storage_class",
    "list_storage_class",
    "form_data_parser_class",
}


def custom_request_data(source: bytes) -> bool:
    """A configured request or storage class may supply application-defined values."""
    if not any(hook.encode() in source for hook in _REQUEST_HOOKS):
        return False
    try:
        tree = ast.parse(source)
    except SyntaxError, ValueError, RecursionError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute | ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            if (node.attr if isinstance(node, ast.Attribute) else node.id) in _REQUEST_HOOKS:
                return True
        if isinstance(node, ast.Call) and len(node.args) >= 2:
            fn = node.func
            if isinstance(fn, ast.Name | ast.Attribute) and (
                fn.id if isinstance(fn, ast.Name) else fn.attr
            ) in {"setattr", "delattr"}:
                field = node.args[1]
                if isinstance(field, ast.Constant) and field.value in _REQUEST_HOOKS:
                    return True
    return False


def request_collection(scope: PythonScope, expression: ast.expr) -> tuple[str, bool] | None:
    """Return the resolved collection and whether it yields (name, value) pairs."""
    method = ""
    if isinstance(expression, ast.Call):
        call = expression
        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr not in {"keys", "values", "items"}
            or call.args
            or call.keywords
        ):
            return None
        method = call.func.attr
        expression = call.func.value
    api = scope.resolve(expression)
    if api not in _COLLECTIONS:
        return None
    return api.removeprefix("flask."), method == "items" or (
        not method and api == "flask.request.headers"
    )
