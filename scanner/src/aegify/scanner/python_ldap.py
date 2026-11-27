"""Resolve LDAP search filter operands and RFC 4515 value encoders in static source."""

from __future__ import annotations

import ast
import re

from aegify.models import CallSite, FileAST, LDAPFilterOperand, PythonLDAPSearch
from aegify.scanner.python_scope import (
    PythonModules,
    PythonScope,
    call_argument,
    imported_name,
    module_name,
    python_scopes,
)
from aegify.scanner.python_storage import LocalValues

_LDAP3 = {"ldap3.Connection", "ldap3.core.connection.Connection"}
_CONSTRUCTORS = _LDAP3 | {
    "ldap.initialize",
    "ldap.ldapobject.LDAPObject",
    "ldap.ldapobject.SimpleLDAPObject",
    "ldap.ldapobject.ReconnectLDAPObject",
}
_SEARCH = {"search", "search_s", "search_st", "search_ext", "search_ext_s"}
_ENCODERS = {"ldap3.utils.conv.escape_filter_chars", "ldap.filter.escape_filter_chars"}
_VALUE_PREFIX = re.compile(r"\([A-Za-z][A-Za-z0-9-]*=")


def _value(node: ast.expr, local: LocalValues) -> ast.expr:
    for _ in range(12):
        assigned = local.assigned(node)
        if assigned is None:
            break
        node = assigned
    return node


def _text(node: ast.expr) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _assertion(template: ast.expr, slot: str) -> bool:
    text = _text(template)
    return text.endswith(slot + ")") and bool(_VALUE_PREFIX.fullmatch(text[: -len(slot) - 1]))


def _encoder(node: ast.expr, local: LocalValues) -> str:
    value = _value(node, local)
    if not isinstance(value, ast.Call) or len(value.args) != 1 or value.keywords:
        return ""
    name = local.scope.resolve(value.func)
    return name if name in _ENCODERS and not isinstance(value.args[0], ast.Starred) else ""


def _value_encoder(value: ast.expr, local: LocalValues) -> str:
    """An encoder for a value is only applicable inside a fixed assertion."""
    if isinstance(value, ast.JoinedStr) and len(value.values) == 3:
        prefix, field, suffix = value.values
        if (
            isinstance(field, ast.FormattedValue)
            and field.conversion in {-1, 115}
            and field.format_spec is None
            and _VALUE_PREFIX.fullmatch(_text(prefix))
            and _text(suffix) == ")"
        ):
            return _encoder(field.value, local)
    if isinstance(value, ast.BinOp):
        if isinstance(value.op, ast.Mod) and _assertion(value.left, "%s"):
            return _encoder(value.right, local)
        if (
            isinstance(value.op, ast.Add)
            and _text(value.right) == ")"
            and isinstance(value.left, ast.BinOp)
            and isinstance(value.left.op, ast.Add)
            and _VALUE_PREFIX.fullmatch(_text(value.left.left))
        ):
            return _encoder(value.left.right, local)
    if isinstance(value, ast.Call) and not value.keywords:
        if (
            isinstance(value.func, ast.Attribute)
            and value.func.attr == "format"
            and _assertion(value.func.value, "{}")
            and len(value.args) == 1
        ):
            return _encoder(value.args[0], local)
        if (
            local.scope.resolve(value.func) == "ldap.filter.filter_format"
            and len(value.args) == 2
            and _assertion(value.args[0], "%s")
            and isinstance(value.args[1], ast.List | ast.Tuple)
            and len(value.args[1].elts) == 1
            and not isinstance(value.args[1].elts[0], ast.Starred)
        ):
            return "ldap.filter.filter_format"
    return ""


def _operand(
    call: ast.Call, local: LocalValues, position: int, name: str
) -> LDAPFilterOperand | None:
    selected = call_argument(call, position, name)
    if selected is None:
        return None
    value = _value(selected[1], local)
    if isinstance(value, ast.Constant):
        return None
    return LDAPFilterOperand(index=selected[0], value_encoder=_value_encoder(value, local))


def _replacements(local: LocalValues) -> set[ast.expr]:
    return {
        _value(node.value, local)
        for node in local.scope.nodes
        if isinstance(node, ast.Attribute)
        and node.attr in _SEARCH
        and isinstance(node.ctx, ast.Store | ast.Del)
    }


def _export(scope: PythonScope, module: PythonScope) -> tuple[str, str] | None:
    owner = scope.owner
    if (
        not isinstance(owner, ast.FunctionDef)
        or owner not in module.owner.body
        or owner.decorator_list
        or module.definitions.get(owner.name) != 1
        or not isinstance(owner.body[-1], ast.Return)
    ):
        return None
    returns = set()
    local = LocalValues(scope)
    replaced = _replacements(local)
    for node in scope.nodes:
        if isinstance(node, ast.Yield | ast.YieldFrom):
            return None
        if isinstance(node, ast.Return):
            result = _value(node.value, local) if node.value else None
            if not isinstance(result, ast.Call) or result in replaced:
                return None
            constructor = scope.resolve(result.func)
            if constructor not in _CONSTRUCTORS or any(
                f"{constructor}.{method}" in scope.modified for method in _SEARCH
            ):
                return None
            returns.add(constructor)
    return (owner.name, returns.pop()) if len(returns) == 1 else None


def search_facts(
    source: bytes,
) -> tuple[dict[str, str], dict[tuple[int, int, int, int], PythonLDAPSearch]]:
    if b"search" not in source and b"ldap" not in source:
        return {}, {}
    scopes = list(python_scopes(source))
    if not scopes:
        return {}, {}
    module = scopes[0]
    factories = (
        dict(export for scope in scopes if (export := _export(scope, module)))
        if b"ldap" in source
        else {}
    )
    searches = {}
    for scope in scopes:
        calls = [
            n
            for n in scope.nodes
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in _SEARCH
        ]
        if not calls:
            continue
        local = LocalValues(scope)
        replaced = _replacements(local)
        for call in calls:
            func = call.func
            assert isinstance(func, ast.Attribute)
            receiver = _value(func.value, local)
            if not isinstance(receiver, ast.Call) or receiver in replaced:
                continue
            factory = scope.resolve(receiver.func)
            if (
                not factory
                and isinstance(receiver.func, ast.Name)
                and scope.owner in module.owner.body
                and receiver.func.id not in scope.definitions
            ):
                factory = factories.get(receiver.func.id, "")
            if not factory or f"{factory}.{func.attr}" in scope.modified:
                continue
            ldap3 = _operand(call, local, 1, "search_filter") if func.attr == "search" else None
            ldap = _operand(call, local, 2, "filterstr")
            if (ldap3 or ldap) and call.end_lineno is not None and call.end_col_offset is not None:
                searches[call.lineno, call.col_offset, call.end_lineno, call.end_col_offset] = (
                    PythonLDAPSearch(
                        factory=factory,
                        ldap3_filter=ldap3,
                        python_ldap_filter=ldap,
                    )
                )
    return factories, searches


class LDAPConnections:
    """Connect a search to a unique synchronous factory in its own parsed repository."""

    def __init__(self, files: list[FileAST], modules: PythonModules | None = None) -> None:
        self.modules = modules or PythonModules(files)
        self.factories = {
            (f.repository_id, module + "." + name): constructor
            for f in files
            if f.python_ldap_factories
            and (module := module_name(f.module_path))
            and self.modules.counts[f.repository_id, module] == 1
            for name, constructor in f.python_ldap_factories.items()
        }

    def operand(self, call: CallSite, file: FileAST) -> tuple[str, int] | None:
        fact = call.python_ldap_search
        if fact is None:
            return None
        name = imported_name(file.module_path, fact.factory)
        ctor = name if name in _CONSTRUCTORS else self.factories.get((file.repository_id, name), "")
        if not ctor or not self.modules.external(file, ctor):
            return None
        operand = fact.ldap3_filter if ctor in _LDAP3 else fact.python_ldap_filter
        if operand is None:
            return None
        if operand.value_encoder and self.modules.external(file, operand.value_encoder):
            return None
        family = "ldap3.Connection" if ctor in _LDAP3 else "ldap.ldapobject.LDAPObject"
        return f"{family}.{call.callee}", operand.index
