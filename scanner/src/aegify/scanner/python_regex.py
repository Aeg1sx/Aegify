"""Bind the pattern operand of standard-library regular expression calls."""

from __future__ import annotations

import ast

from aegify.models import CallSite, FileAST, PythonRegexPattern
from aegify.scanner.python_requests import request_collection
from aegify.scanner.python_scope import PythonModules, call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

_APIS = {
    "re.compile",
    "re.search",
    "re.match",
    "re.prefixmatch",
    "re.fullmatch",
    "re.findall",
    "re.finditer",
    "re.split",
    "re.sub",
    "re.subn",
}


def _value(node: ast.expr, local: LocalValues) -> ast.expr:
    for _ in range(12):
        assigned = local.assigned(node)
        if assigned is None:
            break
        node = assigned
    return node


def _escaped_request_text(node: ast.expr, local: LocalValues) -> bool:
    # Fixed anchors surround a complete escaped value. Other pattern syntax can
    # change the interpretation of an inserted fragment.
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.right, ast.Constant) and node.right.value in ("$", r"\Z", r"\z"):
            node = node.left
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.left, ast.Constant) and node.left.value in ("^", r"\A"):
            node = node.right
    node = _value(node, local)
    if (
        not isinstance(node, ast.Call)
        or local.scope.resolve(node.func) != "re.escape"
        or len(node.args) + len(node.keywords) != 1
    ):
        return False
    arg = call_argument(node, 0, "pattern")
    if arg is None:
        return False
    text = _value(arg[1], local)
    if isinstance(text, ast.Subscript):
        return request_collection(local.scope, text.value) is not None and not isinstance(
            text.value, ast.Call
        )
    if isinstance(text, ast.Call) and isinstance(text.func, ast.Attribute):
        return (
            text.func.attr == "get"
            and not isinstance(text.func.value, ast.Call)
            and request_collection(local.scope, text.func.value) is not None
            and not text.keywords
            and len(text.args) in (1, 2)
            and not any(isinstance(a, ast.Starred) for a in text.args)
            and (len(text.args) == 1 or isinstance(text.args[1], ast.Constant))
        )
    return False


def regex_patterns(source: bytes) -> dict[tuple[int, int, int, int], PythonRegexPattern]:
    if not any(api[3:].encode() in source for api in _APIS):
        return {}
    found = {}
    for scope in python_scopes(source):
        local = None
        for call in scope.nodes:
            if (
                not isinstance(call, ast.Call)
                or call.end_lineno is None
                or call.end_col_offset is None
            ):
                continue
            api = scope.resolve(call.func)
            if api not in _APIS or not (arg := call_argument(call, 0, "pattern")):
                continue
            if isinstance(arg[1], ast.Constant):
                continue
            local = local or LocalValues(scope)
            value = _value(arg[1], local)
            if isinstance(value, ast.Constant):
                continue
            found[call.lineno, call.col_offset, call.end_lineno, call.end_col_offset] = (
                PythonRegexPattern(
                    api=api,
                    argument_index=arg[0],
                    escaped_request_text=_escaped_request_text(value, local),
                )
            )
    return found


def regex_operand(call: CallSite, file: FileAST, modules: PythonModules) -> tuple[str, int] | None:
    if not modules.external(file, "re"):
        return None
    fact = call.python_regex_pattern
    if fact is None:
        # Older snapshots have the original argument strings but no import or escape facts.
        name = f"re.{call.callee}"
        if file.python_regex_resolved or call.receiver != "re" or name not in _APIS:
            return None
        try:
            expression = ast.parse("f(" + ",".join(call.arguments) + ")", mode="eval").body
        except SyntaxError, ValueError, RecursionError:
            return None
        if isinstance(expression, ast.Call) and (arg := call_argument(expression, 0, "pattern")):
            if not isinstance(arg[1], ast.Constant):
                return name, arg[0]
        return None
    if (
        fact.escaped_request_text
        and file.repository_id not in modules.custom_request_data
        and modules.external(file, "flask")
        and modules.external(file, "werkzeug")
    ):
        return None
    return fact.api, fact.argument_index
