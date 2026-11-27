"""Bounded static evaluation of locally constructed Python string and bytes inputs."""

from __future__ import annotations

import ast
import base64
import binascii
from itertools import islice

from aegify.scanner.python_storage import LocalValues
from aegify.scanner.python_values import constant_condition, constant_match

type _Constants = frozenset[str | bytes]
_MAX_BYTES = 4096
_CONVERSIONS = {
    "base64.b64encode": base64.b64encode,
    "base64.b64decode": base64.b64decode,
    "base64.urlsafe_b64encode": base64.urlsafe_b64encode,
    "base64.urlsafe_b64decode": base64.urlsafe_b64decode,
}


class LiteralInputs:
    """Enumerate bounded plain text and bytes alternatives at the point of use."""

    def __init__(self, local: LocalValues, *, codecs: bool = False) -> None:
        self.codecs = codecs
        self.local = local
        self.remaining = 128

    def _previous(self, node: ast.AST) -> tuple[str, ...]:
        parents = self.local.scope.parents
        while not isinstance(node, ast.stmt) and node in parents:
            node = parents[node]
        if node not in parents:
            return ()
        for _, body in ast.iter_fields(parents[node]):
            if not isinstance(body, list) or len(body) > 512 or node not in body:
                continue
            offset = body.index(node)
            preceding = []
            for stmt in reversed(body[max(0, offset - 4) : offset]):
                if not isinstance(stmt, ast.Assign) or len(list(islice(ast.walk(stmt), 33))) > 32:
                    break
                if (
                    not isinstance(stmt.targets[0], ast.Name)
                    or stmt.targets[0].id in self.local.closed_over
                ):
                    break
                preceding.append(ast.unparse(stmt))
            return tuple(reversed(preceding))
        return ()

    def condition(self, test: ast.expr) -> bool | None:
        if len(list(islice(ast.walk(test), 33))) > 32:
            return None
        previous = self._previous(test)
        return constant_condition(ast.unparse(test), previous[-1] if previous else "")

    def _unreachable(self, node: ast.AST) -> bool:
        parents = self.local.scope.parents
        while node in parents:
            parent = parents[node]
            if isinstance(parent, ast.If):
                branch = self.condition(parent.test)
                if branch is not None and node in (parent.orelse if branch else parent.body):
                    return True
            elif isinstance(parent, ast.Match) and isinstance(node, ast.match_case):
                if len(list(islice(ast.walk(parent), 129))) <= 128:
                    selected = constant_match(ast.unparse(parent), self._previous(parent))
                    if selected is not None and parent.cases[selected] is not node:
                        return True
            node = parent
        return False

    @staticmethod
    def _join(left: _Constants | None, right: _Constants | None) -> _Constants | None:
        if left is None or right is None or len(left) * len(right) > 8:
            return None
        combined: set[str | bytes] = set()
        for first in left:
            for second in right:
                if len(first) + len(second) > _MAX_BYTES:
                    return None
                if isinstance(first, str) and isinstance(second, str):
                    combined.add(first + second)
                elif isinstance(first, bytes) and isinstance(second, bytes):
                    combined.add(first + second)
                else:
                    return None
        return frozenset(combined)

    def values(self, node: ast.expr, depth: int = 0) -> _Constants | None:
        if depth >= 16 or self.remaining <= 0:
            return None
        self.remaining -= 1
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            return frozenset({node.value}) if len(node.value) <= _MAX_BYTES else None
        if isinstance(node, ast.Name):
            assignment = self.local.assigned(node) if isinstance(node.ctx, ast.Load) else None
            if assignment is not None:
                return self.values(assignment, depth + 1)
            stores = self.local.stores[node.id]
            if (
                node.id in self.local.closed_over
                or self.local.in_loop(node)
                or not 0 < len(stores) <= 8
                or len(stores) != self.local.scope.definitions.get(node.id)
            ):
                return None
            alternatives: set[str | bytes] = set()
            for target in stores:
                if target is node or self._unreachable(target):
                    continue
                if target.lineno == node.lineno:
                    return None
                if target.lineno > node.lineno:
                    continue
                stmt = self.local.scope.parents[target]
                if isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, ast.Add):
                    branch = self._join(
                        self.values(target, depth + 1), self.values(stmt.value, depth + 1)
                    )
                elif isinstance(stmt, ast.Assign | ast.AnnAssign) and stmt.value is not None:
                    branch = self.values(stmt.value, depth + 1)
                else:
                    return None
                if branch is None:
                    return None
                alternatives.update(branch)
                if len(alternatives) > 8:
                    return None
            return frozenset(alternatives) if alternatives else None
        if stored := self.local.stored_source(node):
            choices = self.values(stored[0], depth + 1)
            if isinstance(node, ast.Call) and choices is not None:
                # ConfigParser may interpolate a percent marker held in an alias.
                if any(not isinstance(value, str) or "%" in value for value in choices):
                    return None
            return choices
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._join(self.values(node.left, depth + 1), self.values(node.right, depth + 1))
        if isinstance(node, ast.IfExp):
            condition = self.condition(node.test)
            if condition is not None:
                return self.values(node.body if condition else node.orelse, depth + 1)
            yes, no = self.values(node.body, depth + 1), self.values(node.orelse, depth + 1)
            if yes is not None and no is not None and len(yes | no) <= 8:
                return yes | no
        if self.codecs and isinstance(node, ast.Call) and not node.keywords:
            api = self.local.scope.resolve(node.func)
            if api in _CONVERSIONS and len(node.args) == 1:
                inputs = self.values(node.args[0], depth + 1)
                if inputs is None:
                    return None
                converted = set()
                for value in inputs:
                    try:
                        data = value.encode("ascii") if isinstance(value, str) else value
                        result = _CONVERSIONS[api](data)
                    except binascii.Error, ValueError:
                        # An invalid literal does not reach the downstream reader.
                        continue
                    if len(result) > _MAX_BYTES:
                        return None
                    converted.add(result)
                return frozenset(converted)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"encode", "decode"}:
                if node.args and not (
                    len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value in ("ascii", "utf-8", "utf8")
                ):
                    return None
                codec = (
                    node.args[0].value
                    if node.args and isinstance(node.args[0], ast.Constant)
                    else "utf-8"
                )
                if not isinstance(codec, str):
                    return None
                inputs = self.values(node.func.value, depth + 1)
                if inputs is None:
                    return None
                output: set[str | bytes] = set()
                for value in inputs:
                    try:
                        if node.func.attr == "encode" and isinstance(value, str):
                            output.add(value.encode(codec))
                        elif node.func.attr == "decode" and isinstance(value, bytes):
                            output.add(value.decode(codec))
                        else:
                            return None
                    except UnicodeError:
                        continue
                return frozenset(output) if all(len(v) <= _MAX_BYTES for v in output) else None
        return None
