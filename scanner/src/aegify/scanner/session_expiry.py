"""Find framework configuration that selects an unbounded session lifetime."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from typing import Literal

from tree_sitter import Node

from aegify.models import SessionExpiry
from aegify.scanner.python_scope import call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

_STARLETTE = "starlette.middleware.sessions.SessionMiddleware"
_APPS: dict[str, Literal["starlette", "fastapi"]] = {
    "starlette.applications.Starlette": "starlette",
    "fastapi.FastAPI": "fastapi",
}


def python_settings(source: bytes) -> list[SessionExpiry]:
    if b"starlette" not in source:
        return []
    facts = []
    for scope in python_scopes(source):
        values = None
        for node in scope.nodes:
            if not isinstance(node, ast.Call):
                continue
            api = scope.resolve(node.func)
            owner: Literal["starlette", "fastapi"] = "starlette"
            if api == _STARLETTE:
                if not call_argument(node, 0, "app") or not call_argument(node, 1, "secret_key"):
                    continue
                setting = call_argument(node, 3, "max_age")
            elif node.args and scope.resolve(node.args[0]) == _STARLETTE:
                if api != "starlette.middleware.Middleware":
                    if (
                        not isinstance(node.func, ast.Attribute)
                        or node.func.attr != "add_middleware"
                    ):
                        continue
                    values = values or LocalValues(scope)
                    instance = values.assigned(node.func.value)
                    if (
                        not isinstance(instance, ast.Call)
                        or scope.resolve(instance.func) not in _APPS
                    ):
                        continue
                    owner = _APPS[scope.resolve(instance.func)]
                if not call_argument(node, 1, "secret_key"):
                    continue
                # Both wrappers forward arguments following the middleware class
                # to its constructor, with the ASGI application supplied separately.
                setting = call_argument(node, 3, "max_age")
            else:
                continue
            if setting is None:
                continue
            value: ast.expr | None = setting[1]
            if isinstance(value, ast.Name):
                values = values or LocalValues(scope)
                value = values.assigned(value)
            if isinstance(value, ast.Constant) and value.value is None:
                facts.append(SessionExpiry(line=node.lineno, api="starlette", owner=owner))
    return sorted(facts, key=lambda fact: fact.line)


def _walk(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _text(node: Node | None) -> str:
    return (node.text or b"").decode(errors="replace") if node is not None else ""


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return (
        [
            n
            for n in args.named_children
            if n.type not in {"comment", "block_comment", "line_comment"}
        ]
        if args
        else []
    )


def _properties(obj: Node) -> dict[str, Node] | None:
    if obj.type != "object":
        return None
    properties = {}
    for item in obj.named_children:
        if item.type == "comment":
            continue
        key = item.child_by_field_name("key")
        value = item.child_by_field_name("value")
        if item.type == "shorthand_property_identifier":
            key = value = item
        if (
            key is None
            or value is None
            or key.type not in {"property_identifier", "shorthand_property_identifier", "string"}
        ):
            return None
        name = _text(key)
        if key.type == "string":
            name = name[1:-1]
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", name) or name == "__proto__" or name in properties:
            return None
        properties[name] = value
    return properties


def _express_factory(statement: Node) -> Node | None:
    if statement.type == "import_statement":
        module = statement.child_by_field_name("source")
        clause = next((n for n in statement.named_children if n.type == "import_clause"), None)
        if (
            _text(module) in {'"express-session"', "'express-session'"}
            and clause is not None
            and not any(n.type == "type" for n in statement.children)
        ):
            return next((n for n in clause.named_children if n.type == "identifier"), None)
    if statement.type not in {"lexical_declaration", "variable_declaration"}:
        return None
    for binding in statement.named_children:
        value = binding.child_by_field_name("value")
        name = binding.child_by_field_name("name")
        if (
            value is None
            or value.type != "call_expression"
            or name is None
            or name.type != "identifier"
        ):
            continue
        if _text(value.child_by_field_name("function")) == "require" and [
            _text(n) for n in _arguments(value)
        ] in [['"express-session"'], ["'express-session'"]]:
            return name
    return None


def javascript_settings(root: Node, source: bytes) -> list[SessionExpiry]:
    if b"express-session" not in source or root.has_error:
        return []
    factories = [
        decl for stmt in root.named_children if (decl := _express_factory(stmt)) is not None
    ]
    if not factories:
        return []
    bindings = {_text(name): name for name in factories}
    calls = []
    # A local shadow, reassignment or escaped factory leaves its identity unknown.
    for ref in _walk(root):
        if ref.type not in {
            "identifier",
            "shorthand_property_identifier_pattern",
            "shorthand_property_identifier",
        }:
            continue
        name = _text(ref)
        if name not in bindings and name != "require":
            continue
        if ref == bindings.get(name):
            continue
        parent = ref.parent
        if (
            parent
            and parent.type == "call_expression"
            and parent.child_by_field_name("function") == ref
        ):
            if name in bindings and ref.start_byte > bindings[name].end_byte:
                calls.append((name, parent))
        elif name == "require":
            for alias, binding in list(bindings.items()):
                if binding.parent and binding.parent.type == "variable_declarator":
                    del bindings[alias]
        else:
            bindings.pop(name, None)
    facts = []
    for name, call in calls:
        if name not in bindings or len(args := _arguments(call)) != 1:
            continue
        opts = _properties(args[0])
        if opts is None or "store" in opts or "secret" not in opts:
            continue
        cookie = _properties(opts["cookie"]) if "cookie" in opts else {}
        if cookie is not None and all(
            key not in cookie or cookie[key].type == "null" for key in ("maxAge", "expires")
        ):
            facts.append(SessionExpiry(line=call.start_point[0] + 1, api="express"))
    return facts


def servlet_setting(call: Node, method: Node | None, types: dict[str, str]) -> bool:
    if method is None or method.has_error or len(args := _arguments(call)) != 1:
        return False
    number = re.fullmatch(r"(-?)[ \t]*(0|[1-9][0-9_]{0,18})", _text(args[0]))
    if not number or not -(2**31) <= int(number[1] + number[2].replace("_", "")) <= 0:
        return False
    obj = call.child_by_field_name("object")
    expected = "HttpSession"
    if obj is not None and obj.type == "method_invocation":
        if _text(obj.child_by_field_name("name")) != "getSession" or [
            _text(n) for n in _arguments(obj)
        ] not in ([], ["true"], ["false"]):
            return False
        obj = obj.child_by_field_name("object")
        expected = "HttpServletRequest"
    if obj is None or obj.type != "identifier":
        return False
    parent = call.parent
    while parent is not None and parent != method:
        if parent.type in {"class_body", "lambda_expression"}:
            return False
        parent = parent.parent
    params = method.child_by_field_name("parameters")
    return bool(
        params
        and any(
            _text(param.child_by_field_name("name")) == _text(obj)
            and types.get(_text(param.child_by_field_name("type")))
            in {f"javax.servlet.http.{expected}", f"jakarta.servlet.http.{expected}"}
            for param in params.named_children
            if param.type == "formal_parameter"
        )
    )
