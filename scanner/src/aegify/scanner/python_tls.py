"""Static TLS policy at known Python client APIs. Scanned modules are never imported."""

from __future__ import annotations

import ast
from collections import defaultdict

from aegify.models import PythonTLSSetting
from aegify.scanner.python_scope import PythonScope, python_scopes

_CLIENTS = {
    "smtplib.SMTP": "smtplib.SMTP",
    "smtplib.SMTP_SSL": "smtplib.SMTP",
    "smtplib.LMTP": "smtplib.SMTP",
    "requests.Session": "requests.Session",
    "requests.session": "requests.Session",
    "requests.sessions.Session": "requests.Session",
    "requests.sessions.session": "requests.Session",
    "aiohttp.ClientSession": "aiohttp.ClientSession",
}
_HTTP_METHODS = {"request", "get", "post", "put", "patch", "delete", "head", "options"}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _annotation(scope: PythonScope, node: ast.expr | None) -> str:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = _annotation(scope, node.left), _annotation(scope, node.right)
        if isinstance(node.right, ast.Constant) and node.right.value is None:
            return left
        if isinstance(node.left, ast.Constant) and node.left.value is None:
            return right
        return left if left == right else ""
    return _CLIENTS.get(scope.resolve(node), "") if node else ""


def _self_name(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    params = method.args.posonlyargs + method.args.args
    return params[0].arg if params and not method.decorator_list else ""


def _member(node: ast.expr, receiver: str) -> str:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
    ):
        return node.attr
    return ""


def _attribute_path(node: ast.expr) -> tuple[str, ...]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return (node.id, *reversed(parts)) if isinstance(node, ast.Name) else ()


def _factories(scope: PythonScope) -> dict[str, str]:
    return {
        node.name: kind
        for node in scope.owner.body
        if isinstance(node, ast.FunctionDef)
        and not node.decorator_list
        and scope.definitions.get(node.name) == 1
        and (kind := _annotation(scope, node.returns))
    }


def _targets(node: ast.AST) -> tuple[list[ast.expr], ast.expr | None]:
    if isinstance(node, ast.Assign):
        return node.targets, node.value
    if isinstance(node, ast.AnnAssign):
        return [node.target], node.value
    if isinstance(node, ast.withitem) and node.optional_vars is not None:
        return [node.optional_vars], node.context_expr
    return [], None


class _Clients:
    def __init__(
        self, scope: PythonScope, functions: dict[str, str], methods: dict[str, str], receiver: str
    ):
        self.scope = scope
        self.functions = functions
        self.methods = methods
        self.receiver = receiver
        self.locals: dict[str, tuple[str, int]] = {}
        self.members: dict[str, list[tuple[str, ast.AST]]] = defaultdict(list)
        self.replaced: set[tuple[str, ...]] = set()
        for node in scope.nodes:
            targets, value = _targets(node)
            for target in targets:
                kind = self.constructed(value)
                if isinstance(target, ast.Name) and scope.definitions.get(target.id) == 1 and kind:
                    self.locals[target.id] = (kind, target.lineno)
                elif field := _member(target, receiver):
                    self.members[field].append((kind, node))
            if isinstance(node, ast.arg) and scope.definitions.get(node.arg) == 1:
                if kind := _annotation(scope, node.annotation):
                    self.locals[node.arg] = (kind, node.lineno)
            # In-place writes and removal invalidate a previously inferred member type.
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
                if path := _attribute_path(node):
                    self.replaced.add(path)
                parent = scope.parents[node]
                if node not in _targets(parent)[0] and (field := _member(node, receiver)):
                    self.members[field].append(("", parent))

    def constructed(self, value: ast.expr | None) -> str:
        if not isinstance(value, ast.Call):
            return ""
        callee = value.func
        if kind := _CLIENTS.get(self.scope.resolve(callee)):
            return kind
        if _attribute_path(callee) in self.replaced:
            return ""
        if isinstance(callee, ast.Name) and (
            isinstance(self.scope.owner, ast.Module) or callee.id not in self.scope.definitions
        ):
            return self.functions.get(callee.id, "")
        return self.methods.get(_member(callee, self.receiver), "")

    def family(self, value: ast.expr, fields: dict[str, str]) -> str:
        if isinstance(value, ast.Name):
            kind, line = self.locals.get(value.id, ("", 0))
            return kind if line <= value.lineno else ""
        if field := _member(value, self.receiver):
            writes = self.members.get(field, [])
            if len(writes) == 1:
                kind, node = writes[0]
                if isinstance(node, ast.stmt) and self.scope.precedes(node, value):
                    return kind
            return fields.get(field, "")
        return self.constructed(value)


def _class_fields(methods: list[_Clients]) -> dict[str, str]:
    # A client installed by one method can be read by another. A reset to None
    # has no callable methods. Any other unresolved write makes the field unknown.
    candidates: dict[str, set[str]] = defaultdict(set)
    for method in methods:
        for name, writes in method.members.items():
            for kind, node in writes:
                value = _targets(node)[1]
                if isinstance(value, ast.Constant) and value.value is None:
                    continue
                candidates[name].add(kind)
    return {name: next(iter(values)) for name, values in candidates.items() if len(values) == 1}


def _setting(call: ast.Call, clients: _Clients, fields: dict[str, str]) -> PythonTLSSetting | None:
    scope = clients.scope
    callee = scope.resolve(call.func)
    if any(k.arg is None for k in call.keywords) or any(
        isinstance(arg, ast.Starred) for arg in call.args
    ):
        return None
    options = {k.arg: k.value for k in call.keywords}
    if len(options) != len(call.keywords):
        return None
    api = callee
    family = ""
    if isinstance(call.func, ast.Attribute):
        if _attribute_path(call.func) in clients.replaced:
            return None
        family = clients.family(call.func.value, fields)
        if family:
            api = family + "." + call.func.attr
    receiver, _, method = api.rpartition(".")
    if api in scope.modified or (receiver in _CLIENTS.values() and not family):
        return None
    if method in _HTTP_METHODS or api in {"httpx.Client", "httpx.AsyncClient"}:
        option = ""
        if receiver in {"requests", "requests.api", "requests.Session", "httpx"}:
            option = "verify"
        elif receiver == "aiohttp.ClientSession" or api == "aiohttp.request":
            if {"verify_ssl", "ssl_context", "fingerprint"}.intersection(options):
                return None
            option = "ssl"
        value = options.get(option)
        if option and isinstance(value, ast.Constant) and value.value is False:
            if method in _HTTP_METHODS:
                index = 1 if method == "request" else 0
                url = call.args[index] if len(call.args) > index else options.get("url")
                if isinstance(url, ast.Constant) and isinstance(url.value, str):
                    if url.value.lower().startswith("http://"):
                        return None
            return PythonTLSSetting(api=api, mode="http_option", line=value.lineno, option=option)
    if api == "smtplib.SMTP.starttls":
        if call.args or set(options) - {"context"}:
            return None
    elif api == "smtplib.SMTP_SSL":
        # Additional positional arguments have different meanings across Python versions.
        if len(call.args) > 2 or set(options) - {
            "host",
            "port",
            "local_hostname",
            "context",
            "timeout",
            "source_address",
        }:
            return None
    else:
        return None
    context = options.get("context")
    if context is None or isinstance(context, ast.Constant) and context.value is None:
        return PythonTLSSetting(api=api, mode="implicit_context", line=call.lineno)
    if (
        isinstance(context, ast.Call)
        and scope.resolve(context.func) == "ssl._create_unverified_context"
        and not context.args
        and not context.keywords
    ):
        return PythonTLSSetting(api=api, mode="unverified_context", line=context.lineno)
    return None


def tls_settings(source: bytes) -> list[PythonTLSSetting]:
    if not any(name in source for name in (b"requests", b"smtplib", b"aiohttp", b"httpx", b"ssl")):
        return []
    scopes = list(python_scopes(source))
    if not scopes:
        return []
    module = scopes[0]
    top = set(module.owner.body)
    functions = _factories(module)
    classes: dict[ast.AST, PythonScope] = {
        node: scope
        for scope in scopes
        if isinstance(scope.owner, ast.ClassDef)
        for node in scope.owner.body
        if isinstance(node, _FUNCTIONS)
    }
    methods: dict[ast.AST, dict[str, str]] = {
        scope.owner: _factories(scope) for scope in scopes if isinstance(scope.owner, ast.ClassDef)
    }
    bindings = []
    by_class: dict[ast.AST, list[_Clients]] = defaultdict(list)
    for scope in scopes:
        enclosing = classes.get(scope.owner)
        receiver = (
            _self_name(scope.owner) if enclosing and isinstance(scope.owner, _FUNCTIONS) else ""
        )
        if receiver and scope.definitions.get(receiver) != 1:
            receiver = ""
        clients = _Clients(
            scope,
            functions
            if scope is module or scope.owner in top or (enclosing and enclosing.owner in top)
            else {},
            methods[enclosing.owner] if enclosing else {},
            receiver,
        )
        bindings.append(clients)
        if enclosing and receiver:
            by_class[enclosing.owner].append(clients)
    fields = {owner: _class_fields(group) for owner, group in by_class.items()}
    facts = []
    for clients in bindings:
        scope = clients.scope
        enclosing = classes.get(scope.owner)
        members = fields.get(enclosing.owner, {}) if enclosing else {}
        for node in scope.nodes:
            if isinstance(node, ast.Call):
                if setting := _setting(node, clients, members):
                    facts.append(setting)
            elif (
                isinstance(node, ast.Assign | ast.AnnAssign)
                and node.value
                and scope.resolve(node.value) == "ssl._create_unverified_context"
            ):
                for target in _targets(node)[0]:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "_create_default_https_context"
                        and scope.resolve(target.value) == "ssl"
                    ):
                        facts.append(
                            PythonTLSSetting(
                                api="ssl._create_default_https_context",
                                mode="https_default",
                                line=target.lineno,
                            )
                        )
    return sorted(facts, key=lambda fact: (fact.line, fact.api, fact.mode))
