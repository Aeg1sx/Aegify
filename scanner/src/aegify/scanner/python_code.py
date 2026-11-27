"""Bind Python's dynamic-code source and recognize inputs limited to a literal."""

from __future__ import annotations

import ast
from typing import Literal

from aegify.models import CallSite, FileAST, PythonCodeInput
from aegify.scanner.python_scope import PythonModules, PythonScope, dominating_facts, python_scopes
from aegify.scanner.python_text import TextValues

type _Constraint = Literal["", "quoted_text", "repr_text"]
type _Origin = Literal["", "runtime", "inferred"]


def _builtin(scope: PythonScope, expression: ast.expr) -> str:
    api = scope.resolve(expression)
    if api.startswith("builtins."):
        return api.removeprefix("builtins.")
    if (
        isinstance(expression, ast.Name)
        and expression.id not in scope.hidden
        and f"builtins.{expression.id}" not in scope.modified
    ):
        return expression.id
    return ""


class _CodeValues(TextValues):
    """Only use text origins whose representation cannot be supplied by application code."""

    def _string_value(self, node: ast.expr, depth: int) -> bool:
        if isinstance(node, ast.JoinedStr):
            # A user-defined __format__ can return a string subclass.
            return all(isinstance(part, ast.Constant) for part in node.values)
        if isinstance(node, ast.Call):
            if _builtin(self.scope, node.func) == "str":
                return not node.keywords and (
                    not node.args
                    or len(node.args) == 1
                    and self.string_value(node.args[0], depth + 1)
                )
            if isinstance(node.func, ast.Name) and node.func.id == "str":
                return False
            api = self.scope.resolve(node.func)
            if api in {"urllib.parse.unquote", "urllib.parse.unquote_plus"}:
                return (
                    len(node.args) == 1
                    and not node.keywords
                    and self.string_value(node.args[0], depth + 1)
                )
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == "get" and not api:
                    return False
                if node.func.attr == "decode" and (node.args or node.keywords):
                    return False
        return super()._string_value(node, depth)


def _index(node: ast.expr | None) -> int | None:
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        if isinstance(node.operand, ast.Constant) and type(node.operand.value) is int:
            return -node.operand.value
    return None


def _quote(node: ast.expr) -> str:
    return node.value if isinstance(node, ast.Constant) and node.value in ("'", '"') else ""


def _exact_type(local: _CodeValues, test: ast.expr, truth: bool, name: str, use: ast.Call) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    op = test.ops[0]
    if not (isinstance(op, ast.Is) and truth or isinstance(op, ast.IsNot) and not truth):
        return False
    left, right = test.left, test.comparators[0]
    if _builtin(local.scope, left) == "str":
        left, right = right, left
    return (
        _builtin(local.scope, right) == "str"
        and isinstance(left, ast.Call)
        and _builtin(local.scope, left.func) == "type"
        and not left.keywords
        and len(left.args) == 1
        and local.unchanged(name, left.args[0], use)
    )


def _quote_fact(
    local: _CodeValues, test: ast.expr, truth: bool, name: str, use: ast.Call
) -> tuple[str, str] | None:
    if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute):
        if (
            truth
            and test.func.attr in {"startswith", "endswith"}
            and not test.keywords
            and len(test.args) == 1
            and (quote := _quote(test.args[0]))
            and local.unchanged(name, test.func.value, use)
        ):
            return quote, test.func.attr
        return None
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    left, right, op = test.left, test.comparators[0], test.ops[0]
    if isinstance(op, ast.In | ast.NotIn):
        if (
            isinstance(op, ast.NotIn) == truth
            and (quote := _quote(left))
            and isinstance(right, ast.Subscript)
            and isinstance(right.slice, ast.Slice)
            and _index(right.slice.lower) == 1
            and _index(right.slice.upper) == -1
            and right.slice.step is None
            and local.unchanged(name, right.value, use)
        ):
            return quote, "interior"
    elif isinstance(op, ast.Eq | ast.NotEq) and isinstance(op, ast.Eq) == truth:
        if isinstance(right, ast.Subscript):
            left, right = right, left
        if (
            isinstance(left, ast.Subscript)
            and (quote := _quote(right))
            and local.unchanged(name, left.value, use)
        ):
            edge = _index(left.slice)
            if edge in (0, -1):
                return quote, "startswith" if edge == 0 else "endswith"
    return None


def _text_origin(local: _CodeValues, use: ast.Call, value: ast.expr, *, quoted: bool) -> _Origin:
    edges: dict[str, set[str]] = {}
    exact = False
    if isinstance(value, ast.Name) and value.id in local.scope.definitions:
        for test, truth in dominating_facts(local.scope, use):
            if _exact_type(local, test, truth, value.id, use):
                exact = True
            elif quoted and (fact := _quote_fact(local, test, truth, value.id, use)):
                delimiter, edge = fact
                edges.setdefault(delimiter, set()).add(edge)
    if quoted and not any(len(parts) == 3 for parts in edges.values()):
        return ""
    if exact:
        return "runtime"
    if any(api.startswith("flask.request") for api in local.scope.modified):
        return ""
    return "inferred" if local.string_value(value) else ""


def _constraint(local: _CodeValues, call: ast.Call, value: ast.expr) -> tuple[_Constraint, _Origin]:
    if not isinstance(local.scope.owner, ast.FunctionDef | ast.AsyncFunctionDef) or local.in_loop(
        call
    ):
        return "", ""
    if origin := _text_origin(local, call, value, quoted=True):
        return "quoted_text", origin
    expression = local.assigned(value) or value
    if (
        isinstance(expression, ast.Call)
        and _builtin(local.scope, expression.func) == "repr"
        and len(expression.args) == 1
        and not expression.keywords
        and not local.in_loop(expression)
        and (origin := _text_origin(local, expression, expression.args[0], quoted=False))
    ):
        return "repr_text", origin
    return "", ""


def code_inputs(source: bytes) -> dict[tuple[int, int, int, int], PythonCodeInput]:
    if b"eval" not in source and b"exec" not in source:
        return {}
    found = {}
    for scope in python_scopes(source):
        local = None
        for node in scope.nodes:
            if not isinstance(node, ast.Call) or not node.args:
                continue
            api = _builtin(scope, node.func)
            if (
                api not in {"eval", "exec"}
                and isinstance(node.func, ast.Name)
                and node.func.id in scope.definitions
            ):
                if local is None:
                    local = _CodeValues(scope)
                target = local.assigned(node.func)
                if target is not None:
                    api = _builtin(scope, target)
            if (
                api not in {"eval", "exec"}
                or node.end_lineno is None
                or node.end_col_offset is None
            ):
                continue
            if local is None:
                local = _CodeValues(scope)
            constraint, origin = _constraint(local, node, node.args[0])
            found[node.lineno, node.col_offset, node.end_lineno, node.end_col_offset] = (
                PythonCodeInput(
                    api="builtins.eval" if api == "eval" else "builtins.exec",
                    literal_constraint=constraint,
                    runtime_text_check=origin == "runtime",
                )
            )
    return found


def code_operand(call: CallSite, file: FileAST, modules: PythonModules) -> tuple[str, int] | None:
    fact = call.python_code_input
    if fact:
        if fact.literal_constraint and modules.external(file, "builtins"):
            if fact.runtime_text_check or (
                file.repository_id not in modules.custom_request_data
                and all(modules.external(file, api) for api in ("flask", "urllib", "base64"))
            ):
                return None
        name = fact.api.removeprefix("builtins.")
        return (name if call.callee == name and not call.receiver else fact.api), 0
    # Preserve existing generic method matches and snapshots without binding metadata.
    if call.callee in {"eval", "exec"}:
        return (f"{call.receiver}.{call.callee}" if call.receiver else call.callee), 0
    return None
