"""Recognize partial comparisons of parsed URL hosts against host-shaped literals."""

import ast
import re

from aegify.models import PythonHostCheck
from aegify.scanner.python_scope import python_scopes
from aegify.scanner.python_storage import LocalValues

_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_HOST = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}|localhost", re.IGNORECASE | re.ASCII)


def _origin(node: ast.expr, local: LocalValues) -> ast.expr:
    for _ in range(6):
        value = local.assigned(node)
        if value is None:
            break
        node = value
    return node


def host_checks(source: bytes) -> list[PythonHostCheck]:
    if b"urllib" not in source or not any(op in source for op in (b"startswith", b"endswith")):
        return []
    scopes = iter(python_scopes(source))
    module = next(scopes, None)
    if module is None:
        return []
    constants = {
        target.id: stmt.value
        for stmt in module.owner.body
        if isinstance(stmt, ast.Assign | ast.AnnAssign) and isinstance(stmt.value, ast.Constant)
        for target in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        if isinstance(target, ast.Name) and module.definitions[target.id] == 1
    }
    global_readers = set(module.owner.body)
    for child in module.owner.body:
        if isinstance(child, ast.ClassDef):
            global_readers.update(child.body)
    facts = []
    for scope in [module, *scopes]:
        local = LocalValues(scope)
        for node in scope.nodes:
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"startswith", "endswith"}
                and len(node.args) == 1
                and not node.keywords
            ):
                continue
            host = _origin(node.func.value, local)
            if not isinstance(host, ast.Attribute) or host.attr not in {"netloc", "hostname"}:
                continue
            parsed = _origin(host.value, local)
            if not isinstance(parsed, ast.Call):
                continue
            api = scope.resolve(parsed.func)
            if api not in {"urllib.parse.urlparse", "urllib.parse.urlsplit"}:
                continue
            operand = _origin(node.args[0], local)
            if (
                isinstance(operand, ast.Name)
                and operand.id not in scope.definitions
                and scope.owner in global_readers
            ):
                operand = constants.get(operand.id, operand)
            if not isinstance(operand, ast.Constant) or not isinstance(operand.value, str):
                continue
            if len(operand.value) <= 253 and _HOST.fullmatch(operand.value):
                facts.append(
                    PythonHostCheck(
                        parser=api,
                        component=host.attr,
                        comparison=node.func.attr,
                        line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                    )
                )
    return sorted(facts, key=lambda fact: fact.line)
