"""Identify unescaped Jinja environments used for HTML or web application settings."""

import ast
from typing import Literal

from aegify.models import JinjaEnvironment
from aegify.scanner.python_scope import PythonScope, python_scopes
from aegify.scanner.python_storage import LocalValues

_ENVIRONMENTS = {"jinja2.Environment", "jinja2.environment.Environment"}
_LOADERS = {
    f"jinja2.{prefix}{loader}"
    for prefix in ("", "loaders.")
    for loader in ("FileSystemLoader", "PackageLoader", "DictLoader")
}


def _defaults_to_none(scope: PythonScope, parameter: ast.Name) -> bool:
    if not isinstance(scope.owner, ast.FunctionDef | ast.AsyncFunctionDef):
        return False
    args = scope.owner.args
    positional = [*args.posonlyargs, *args.args]
    defaults: list[tuple[ast.arg, ast.expr | None]] = list(
        zip(reversed(positional), reversed(args.defaults), strict=False)
    )
    defaults.extend(zip(args.kwonlyargs, args.kw_defaults, strict=True))
    return scope.definitions.get(parameter.id) == 1 and any(
        arg.arg == parameter.id and isinstance(default, ast.Constant) and default.value is None
        for arg, default in defaults
    )


def _optional_empty(value: ast.expr, local: LocalValues) -> bool:
    """An omitted optional parameter selects an empty literal mapping."""
    parameter: ast.expr
    if isinstance(value, ast.IfExp) and isinstance(value.test, ast.Name):
        parameter = value.test
        if not isinstance(value.body, ast.Name) or value.body.id != parameter.id:
            return False
        fallback = value.orelse
    elif isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or) and len(value.values) == 2:
        parameter, fallback = value.values
    else:
        return False
    return (
        isinstance(parameter, ast.Name)
        and _defaults_to_none(local.scope, parameter)
        and parameter.id not in local.closed_over
        and set(local.loads[parameter.id]).issubset(ast.walk(value))
        and isinstance(fallback, ast.Dict)
        and not fallback.keys
    )


def _unescaped(call: ast.Call, local: LocalValues) -> str:
    if call.args or not any(
        kw.arg == "loader"
        and isinstance(kw.value, ast.Call)
        and local.scope.resolve(kw.value.func) in _LOADERS
        for kw in call.keywords
    ):
        return ""
    optional = False
    for kw in call.keywords:
        if kw.arg == "autoescape":
            if not isinstance(kw.value, ast.Constant) or kw.value.value is not False:
                return ""
        elif kw.arg is None:
            value: ast.expr | None = kw.value
            if isinstance(value, ast.Name):
                # An options mapping may be amended through a method call or alias.
                if len(local.loads[value.id]) != 1:
                    return ""
                value = local.assigned(value)
            if isinstance(value, ast.Dict) and not value.keys:
                continue
            if value is None or not _optional_empty(value, local):
                return ""
            optional = True
    return "optional" if optional else "unescaped"


def _web_settings_use(node: ast.Name, local: LocalValues) -> bool:
    scope = local.scope
    parent = scope.parents[node]
    if isinstance(parent, ast.keyword) and parent.arg in {"jinja_env", "jinja2_env"}:
        mapping = scope.parents[parent]
        if not (
            isinstance(mapping, ast.Call)
            and isinstance(mapping.func, ast.Name)
            and mapping.func.id == "dict"
            and "dict" not in scope.hidden
        ):
            return False
    elif isinstance(parent, ast.Dict):
        keys = [
            key.value
            for key in parent.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        if (
            len(keys) != len(parent.keys)
            or len(set(keys)) != len(keys)
            or not any(
                key in {"jinja_env", "jinja2_env"} and value is node
                for key, value in zip(keys, parent.values, strict=True)
            )
        ):
            return False
        mapping = parent
    else:
        return False
    # The application's method must return this mapping, directly or through a local.
    return any(
        isinstance(stmt, ast.Return)
        and stmt.value is not None
        and (stmt.value is mapping or local.assigned(stmt.value) is mapping)
        for stmt in scope.nodes
    )


def _use(
    node: ast.Name, local: LocalValues, web_method: bool
) -> Literal["html_template", "web_settings"] | None:
    parent = local.scope.parents[node]
    if isinstance(parent, ast.Attribute) and parent.attr == "get_template":
        call = local.scope.parents[parent]
        if isinstance(call, ast.Call) and call.func is parent:
            name = (
                call.args[0]
                if call.args
                else next((kw.value for kw in call.keywords if kw.arg == "name"), None)
            )
            if (
                isinstance(name, ast.Constant)
                and isinstance(name.value, str)
                and (name.value.lower().endswith((".html", ".htm", ".xhtml")))
            ):
                return "html_template"
    if web_method and _web_settings_use(node, local):
        return "web_settings"
    return None


def environments(source: bytes) -> list[JinjaEnvironment]:
    if b"jinja2" not in source or b"Environment" not in source:
        return []
    found = []
    web_methods: set[ast.AST] = set()
    for scope in python_scopes(source):
        for cls in scope.parents:
            if isinstance(cls, ast.ClassDef) and any(
                scope.resolve(base) == "tornado.web.Application" for base in cls.bases
            ):
                web_methods.update(cls.body)
        local = None
        for stmt in scope.nodes:
            if not (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Call)
                and scope.resolve(stmt.value.func) in _ENVIRONMENTS
            ):
                continue
            local = local or LocalValues(scope)
            name = stmt.targets[0].id
            if scope.definitions.get(name) != 1 or name in local.closed_over:
                continue
            mode = _unescaped(stmt.value, local)
            if not mode:
                continue
            # An earlier unknown use may mutate the environment or let it escape.
            node = min(
                local.loads[name], key=lambda use: (use.lineno, use.col_offset), default=None
            )
            if node is None or local.assigned(node) is not stmt.value:
                continue
            use = _use(node, local, scope.owner in web_methods)
            if use:
                found.append(
                    JinjaEnvironment(
                        line=stmt.value.lineno,
                        use_line=node.lineno,
                        use=use,
                        optional_options=mode == "optional",
                    )
                )
    return found
