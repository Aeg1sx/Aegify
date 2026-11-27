"""Local Java PRNG flows into servlet session credentials."""

from __future__ import annotations

from collections import Counter

from tree_sitter import Node

from aegify.models import CredentialRandomness

_REQUESTS = {"javax.servlet.http.HttpServletRequest", "jakarta.servlet.http.HttpServletRequest"}
_SESSIONS = {"javax.servlet.http.HttpSession", "jakarta.servlet.http.HttpSession"}
_COOKIES = {"javax.servlet.http.Cookie", "jakarta.servlet.http.Cookie"}
_NUMERIC = {"java.lang.Double", "java.lang.Float", "java.lang.Integer", "java.lang.Long"}
_GENERATORS = {"nextInt", "nextLong", "nextDouble", "nextFloat", "nextGaussian", "nextBoolean"}
_KEYS = {
    "sessionid",
    "session_id",
    "session_token",
    "csrf_token",
    "auth_token",
    "access_token",
    "refresh_token",
    "reset_token",
    "remember_token",
    "rememberMe",
    "api_key",
}
_BOUNDARIES = {"class_body", "lambda_expression", "method_declaration", "constructor_declaration"}


def _text(node: Node | None) -> str:
    return (node.text or b"").decode(errors="replace") if node is not None else ""


def _name(call: Node) -> str:
    return _text(call.child_by_field_name("name"))


def _args(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return (
        []
        if args is None
        else [n for n in args.named_children if n.type not in {"block_comment", "line_comment"}]
    )


def _controls_branch(call: Node) -> bool:
    expr = call
    while (parent := expr.parent) is not None:
        if parent.type == "parenthesized_expression":
            expr = parent
        elif (
            parent.type == "unary_expression"
            and _text(parent.child_by_field_name("operator")) == "!"
        ):
            expr = parent
        elif parent.type == "binary_expression" and _text(
            parent.child_by_field_name("operator")
        ) in {"&&", "||"}:
            expr = parent
        else:
            return parent.type == "if_statement" and parent.child_by_field_name("condition") == expr
    return False


class _Method:
    def __init__(self, method: Node, types: dict[str, str]) -> None:
        self.types = types
        self.locals: dict[str, Node] = {}
        self.params: dict[str, str] = {}
        self.writes: Counter[str] = Counter()
        self.calls: list[Node] = []
        params = method.child_by_field_name("parameters")
        if params is not None:
            for param in params.named_children:
                if param.type == "formal_parameter":
                    name = _name(param)
                    self.params[name] = types.get(_text(param.child_by_field_name("type")), "")
                    self.writes[name] += 1
        body = method.child_by_field_name("body")
        pending = [body] if body is not None else []
        while pending:
            n = pending.pop()
            if n.type in _BOUNDARIES:
                continue
            if n.type == "variable_declarator":
                self.locals[_name(n)] = n
                self.writes[_name(n)] += 1
            elif n.type in {
                "catch_formal_parameter",
                "enhanced_for_statement",
                "resource",
                "type_pattern",
                "instanceof_expression",
            }:
                self.writes[_name(n)] += 1
            elif n.type == "assignment_expression":
                self.writes[_text(n.child_by_field_name("left"))] += 1
            elif n.type == "update_expression":
                for operand in n.named_children:
                    self.writes[_text(operand)] += 1
            elif n.type == "method_invocation":
                self.calls.append(n)
            pending.extend(reversed(n.named_children))

    def value(self, ref: Node) -> Node | None:
        if ref.type != "identifier":
            return None
        name = _text(ref)
        definition = self.locals.get(name)
        if definition is None or self.writes[name] != 1 or definition.end_byte > ref.start_byte:
            return None
        declaration = definition.parent
        block = declaration.parent if declaration is not None else None
        if (
            block is None
            or block.type != "block"
            or ref.end_byte > block.end_byte
            or declaration is None
            or declaration.type != "local_variable_declaration"
        ):
            return None
        return definition.child_by_field_name("value")

    def parameter(self, ref: Node | None, allowed: set[str]) -> str:
        name = _text(ref)
        return name if self.writes[name] == 1 and self.params.get(name) in allowed else ""

    def origin(self, expr: Node | None, depth: int = 0) -> tuple[str, int] | None:
        if expr is None or depth > 12:
            return None
        if expr.type == "identifier":
            return self.origin(self.value(expr), depth + 1)
        if expr.type == "parenthesized_expression" and expr.named_child_count == 1:
            return self.origin(expr.named_child(0), depth + 1)
        if expr.type != "method_invocation":
            return None
        receiver = expr.child_by_field_name("object")
        if receiver is None:
            return None
        name, args = _name(expr), _args(expr)
        receiver_name = _text(receiver)
        owner = (
            self.types.get(receiver_name) if not self.writes[receiver_name.split(".")[0]] else None
        )
        if owner == "java.lang.Math" and name == "random" and not args:
            return "java.lang.Math.random", expr.start_point.row + 1
        if name in _GENERATORS:
            allocated = self.value(receiver) if receiver.type == "identifier" else receiver
            if (
                allocated is not None
                and allocated.type == "object_creation_expression"
                and allocated.children[0].type == "new"
                and self.types.get(_text(allocated.child_by_field_name("type")))
                == "java.util.Random"
                and not any(n.type == "class_body" for n in allocated.named_children)
            ):
                return f"java.util.Random.{name}", expr.start_point.row + 1
        if len(args) == 1 and (
            (owner in _NUMERIC and name == "toString")
            or (owner == "java.lang.String" and name == "valueOf")
        ):
            return self.origin(args[0], depth + 1)
        if (
            name == "substring"
            and len(args) in (1, 2)
            and all(a.type == "decimal_integer_literal" for a in args)
        ):
            return self.origin(receiver, depth + 1)
        return None

    def request(self, call: Node | None, method: str) -> str:
        if call is None or call.type != "method_invocation" or _name(call) != method or _args(call):
            return ""
        return self.parameter(call.child_by_field_name("object"), _REQUESTS)

    def slot(self, call: Node, key: Node) -> tuple[str, str] | None:
        owner = call.child_by_field_name("object")
        session = self.parameter(owner, _SESSIONS) or self.request(owner, "getSession")
        if not session:
            return None
        if key.type == "string_literal":
            return session, _text(key)
        if key.type == "identifier" and (value := self.value(key)) is not None:
            return session, _text(value) if value.type == "string_literal" else _text(key)
        return None

    def cookie_value(self, call: Node) -> bool:
        if call.type != "method_invocation" or _name(call) != "getValue" or _args(call):
            return False
        owner = call.child_by_field_name("object")
        if self.parameter(owner, _COOKIES):
            return True
        value = self.value(owner) if owner is not None else None
        if value is None or value.type != "array_access" or owner is None:
            return False
        declaration = self.locals[_text(owner)].parent
        if (
            declaration is None
            or self.types.get(_text(declaration.child_by_field_name("type"))) not in _COOKIES
        ):
            return False
        array = value.child_by_field_name("array")
        if array is not None and array.type == "identifier":
            array = self.value(array)
        return bool(self.request(array, "getCookies"))

    def credential_key(self, key: Node, *, prefix: bool = False) -> bool:
        value = self.value(key) if key.type == "identifier" else key
        if value is None:
            return False
        if prefix and value.type == "binary_expression":
            if _text(value.child_by_field_name("operator")) != "+":
                return False
            value = value.child_by_field_name("left")
        return value is not None and value.type == "string_literal" and _text(value)[1:-1] in _KEYS

    def facts(self) -> list[CredentialRandomness]:
        checked: dict[tuple[str, str], int] = {}
        pending: list[tuple[Node, tuple[str, str], Node]] = []
        changes: Counter[tuple[str, str]] = Counter()
        for call in self.calls:
            name, args = _name(call), _args(call)
            if name in {"setAttribute", "removeAttribute"} and args:
                if slot := self.slot(call, args[0]):
                    changes[slot] += 1
                    if name == "setAttribute" and len(args) == 2:
                        pending.append((call, slot, args[1]))
            if name != "equals" or len(args) != 1 or not _controls_branch(call):
                continue
            receiver = call.child_by_field_name("object")
            if receiver is None:
                continue
            for cookie, read in ((receiver, args[0]), (args[0], receiver)):
                if (
                    self.cookie_value(cookie)
                    and read.type == "method_invocation"
                    and _name(read) == "getAttribute"
                    and len(keys := _args(read)) == 1
                    and (slot := self.slot(read, keys[0]))
                ):
                    checked[slot] = call.start_point.row + 1
        facts = []
        for call, slot, value in pending:
            compare_line = checked.get(slot) if changes[slot] == 1 else None
            # A preference can also be compared with a cookie. Dynamic keys require
            # both an evidenced credential prefix and a branch testing the same slot.
            key = _args(call)[0]
            if not self.credential_key(key) and not (
                compare_line and self.credential_key(key, prefix=True)
            ):
                continue
            if origin := self.origin(value):
                facts.append(
                    CredentialRandomness(
                        generator=origin[0],
                        generator_line=origin[1],
                        use="servlet session value compared with a cookie"
                        if compare_line
                        else "servlet session credential field",
                        use_line=call.start_point.row + 1,
                        comparison_line=compare_line,
                    )
                )
        return facts


def credential_uses(methods: list[Node], types: dict[str, str]) -> list[CredentialRandomness]:
    return [
        fact
        for method in methods
        if not method.has_error and b"setAttribute" in (method.text or b"")
        for fact in _Method(method, types).facts()
    ]
