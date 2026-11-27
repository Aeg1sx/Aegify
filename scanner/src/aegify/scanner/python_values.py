"""Bounded Python syntax inspection; no imports or source evaluation."""

from __future__ import annotations

import ast
import operator
import textwrap
from functools import lru_cache

_MAX_TEXT = 16_384
_MAX_NODES = 4_096

_ARITHMETIC = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
_COMPARISONS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


def _small_int(node: ast.expr, constants: dict[str, int]) -> int | None:
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value if node.value.bit_length() <= 63 else None
    if isinstance(node, ast.BinOp):
        operation = _ARITHMETIC.get(type(node.op))
        if operation:
            left, right = _small_int(node.left, constants), _small_int(node.right, constants)
            if left is not None and right is not None:
                value = operation(left, right)
                return value if value.bit_length() <= 63 else None
    return None


type _Scalar = int | str | bool


def _scalar(node: ast.expr, constants: dict[str, _Scalar]) -> _Scalar | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str) and len(node.value) <= 256:
            return node.value
        if type(node.value) is bool:
            return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.Subscript):
        subject = _scalar(node.value, constants)
        index = _small_int(node.slice, {})
        if isinstance(subject, str) and index is not None and -len(subject) <= index < len(subject):
            return subject[index]
        return None
    return _small_int(node, {k: v for k, v in constants.items() if type(v) is int})


def _constant_assignments(preceding: tuple[str, ...]) -> dict[str, _Scalar]:
    constants: dict[str, _Scalar] = {}
    for text in preceding:
        if len(text) > 256:
            constants.clear()
            continue
        parsed = ast.parse(textwrap.dedent(text).strip()).body
        if len(parsed) != 1 or not isinstance(stmt := parsed[0], ast.Assign):
            constants.clear()
            continue
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            constants.clear()
            continue
        value = _scalar(stmt.value, constants)
        if value is None:
            constants.clear()
        else:
            constants[stmt.targets[0].id] = value
    return constants


def _condition(test: ast.expr, constants: dict[str, _Scalar]) -> bool | None:
    if isinstance(test, ast.Constant) and type(test.value) is bool:
        return test.value
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return None
    left = _scalar(test.left, constants)
    right = _scalar(test.comparators[0], constants)
    operation = test.ops[0]
    if isinstance(left, str) and isinstance(right, str):
        if isinstance(operation, ast.In | ast.NotIn):
            return (left in right) == isinstance(operation, ast.In)
        if isinstance(operation, ast.Eq | ast.NotEq):
            return (left == right) == isinstance(operation, ast.Eq)
    if type(left) is int and type(right) is int and (compare := _COMPARISONS.get(type(operation))):
        return bool(compare(left, right))
    return None


def constant_condition(text: str, previous: str) -> bool | None:
    if len(text) > 256:
        return None
    try:
        return _condition(
            ast.parse(text.strip(), mode="eval").body, _constant_assignments((previous,))
        )
    except SyntaxError, ValueError, IndexError, RecursionError:
        return None


def constant_match(text: str, preceding: tuple[str, ...]) -> int | None:
    """Return the selected arm only for ordered, unguarded scalar literal patterns."""
    if len(text) > 8192:
        return None
    try:
        statement = ast.parse(textwrap.dedent(text).strip()).body[0]
        if not isinstance(statement, ast.Match):
            return None
        value = _scalar(statement.subject, _constant_assignments(preceding))
        if value is None:
            return None
        for index, case in enumerate(statement.cases):
            if case.guard is not None:
                return None
            pattern = case.pattern
            if (
                isinstance(pattern, ast.MatchAs)
                and pattern.pattern is None
                and pattern.name is None
            ):
                return index
            for arm in pattern.patterns if isinstance(pattern, ast.MatchOr) else [pattern]:
                if not isinstance(arm, ast.MatchValue) or not isinstance(arm.value, ast.Constant):
                    return None
                if value == arm.value.value:
                    return index
    except SyntaxError, ValueError, IndexError, RecursionError:
        pass
    return None


def constant_branch(code: str, previous: str) -> str | None:
    """Select a simple ternary value using only literal operations in this block."""
    if " if " not in code or len(code) > 1000:
        return None
    try:
        statement = ast.parse(textwrap.dedent(code).strip()).body[0]
        if not isinstance(statement, ast.Assign | ast.AnnAssign) or not isinstance(
            statement.value, ast.IfExp
        ):
            return None
        ternary = statement.value
        if not all(
            isinstance(arm, ast.Constant | ast.Name) for arm in (ternary.body, ternary.orelse)
        ):
            return None
        result = _condition(ternary.test, _constant_assignments((previous,)))
        if result is not None:
            return ast.unparse(ternary.body if result else ternary.orelse)
    except SyntaxError, ValueError, IndexError, RecursionError:
        pass
    return None


def _name(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return ".".join([node.id, *reversed(parts)])
    return None


@lru_cache(maxsize=512)
def expression_accesses(expression: str) -> tuple[str, ...] | None:
    """Return actual reads, including f-string fields but excluding literal text.

    None leaves unsupported/oversized expressions to the conservative fallback.
    A call's function name is not a value read; its receiver and arguments are.
    """
    if len(expression) > _MAX_TEXT:
        return None
    try:
        try:
            tree = ast.parse(expression.strip(), mode="eval")
        except SyntaxError:
            # Call argument excerpts may contain keyword or unpacking syntax.
            tree = ast.parse(f"_({expression})", mode="eval")
    except SyntaxError, ValueError, RecursionError:
        return None
    pending: list[ast.AST] = [tree]
    reads: list[str] = []
    visited = 0
    while pending:
        visited += 1
        if visited > _MAX_NODES:
            return None
        node = pending.pop()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                pending.append(node.func.value)
            elif not isinstance(node.func, ast.Name):
                pending.append(node.func)
            pending.extend(node.args)
            pending.extend(keyword.value for keyword in node.keywords)
        elif isinstance(node, ast.IfExp):
            # Predicates select a branch. Explicit data flow follows its values.
            pending.extend((node.body, node.orelse))
        elif isinstance(node, ast.Name | ast.Attribute):
            name = _name(node)
            if name is not None:
                if name not in reads:
                    reads.append(name)
            else:
                pending.extend(ast.iter_child_nodes(node))
        else:
            pending.extend(ast.iter_child_nodes(node))
    return tuple(reads)


@lru_cache(maxsize=512)
def assignment(code: str) -> tuple[str, str] | None:
    """Select the assigned value, not its annotation or an embedded '=' string.

    This retains the solver's last-target convention for chained assignments.
    Destructuring and control-flow joins need separate models.
    """
    if len(code) > _MAX_TEXT:
        return None
    source = textwrap.dedent(code).strip()
    try:
        tree = ast.parse(source)
    except SyntaxError, ValueError, RecursionError:
        return None
    if len(tree.body) != 1:
        return None
    statement = tree.body[0]
    if isinstance(statement, ast.Assign):
        target = statement.targets[-1]
        value: ast.expr | None = statement.value
    elif isinstance(statement, ast.AnnAssign | ast.AugAssign):
        target = statement.target
        value = statement.value
    else:
        return None
    name = _name(target)
    if name is None or value is None:
        return None
    rhs = ast.get_source_segment(source, value)
    if rhs is None:
        return None
    if isinstance(statement, ast.AugAssign):
        # The read set includes the prior left-hand value for every augmented op.
        rhs = f"({name}, {rhs})"
    return name, rhs
