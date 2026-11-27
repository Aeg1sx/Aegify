"""Trace JDK PRNG values into servlet credentials and returned session registry keys."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter, defaultdict
from dataclasses import dataclass

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


@dataclass(frozen=True)
class _Origin:
    api: str
    line: int
    encoding_line: int | None = None


_MAPS = {
    "java.util.Map",
    "java.util.HashMap",
    "java.util.LinkedHashMap",
    "java.util.concurrent.ConcurrentMap",
    "java.util.concurrent.ConcurrentHashMap",
}


def _allocation(expr: Node | None, types: dict[str, str]) -> str:
    if expr is None or expr.type != "object_creation_expression" or expr.children[0].type != "new":
        return ""
    if any(child.type == "class_body" for child in expr.named_children):
        return ""
    return types.get(_text(expr.child_by_field_name("type")).split("<", 1)[0], "")


@dataclass
class _Fields:
    generators: set[str]
    stores: dict[str, str]
    names: set[str]

    @classmethod
    def read(cls, body: Node, types: dict[str, str]) -> _Fields:
        fields = cls(set(), {}, set())
        for decl in body.named_children:
            if decl.type != "field_declaration":
                continue
            typ = decl.child_by_field_name("type")
            bindings = [
                child for child in decl.named_children if child.type == "variable_declarator"
            ]
            fields.names.update(_name(binding) for binding in bindings)
            modifiers = next(
                (child for child in decl.named_children if child.type == "modifiers"), None
            )
            if (
                typ is None
                or modifiers is None
                or not any(c.type == "private" for c in modifiers.children)
            ):
                continue
            for binding in bindings:
                name = _name(binding)
                allocation = _allocation(binding.child_by_field_name("value"), types)
                if types.get(_text(typ)) == allocation == "java.util.Random":
                    fields.generators.add(name)
                if typ.type != "generic_type" or allocation not in _MAPS:
                    continue
                base = typ.named_child(0)
                args = next(
                    (child for child in typ.named_children if child.type == "type_arguments"), None
                )
                if (
                    types.get(_text(base)) not in _MAPS
                    or args is None
                    or args.named_child_count != 2
                ):
                    continue
                value_type = _text(args.named_child(1))
                if types.get(
                    _text(args.named_child(0))
                ) == "java.lang.String" and value_type.endswith("Session"):
                    fields.stores[name] = value_type
        if fields.generators or fields.stores:
            # A private field may be assigned in any initializer, method or inner class.
            # Discard ambiguous assignments even when a same-named local might be the target.
            pending = [body]
            while pending:
                n = pending.pop()
                if n.type == "assignment_expression":
                    left = n.child_by_field_name("left")
                    field = left.child_by_field_name("field") if left is not None else None
                    name = _text(field if field is not None else left)
                    fields.generators.discard(name)
                    fields.stores.pop(name, None)
                pending.extend(n.named_children)
        return fields


class _Method:
    def __init__(self, method: Node, types: dict[str, str], fields: _Fields) -> None:
        self.types = types
        self.fields = fields
        self.method = method
        self.returns: list[Node] = []
        self._buffer_refs: dict[str, list[Node]] | None = None
        self.locals: dict[tuple[str, Node], Node | None] = {}
        self.declarations: Counter[str] = Counter()
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
                name = _name(n)
                self.writes[name] += 1
                declaration = n.parent
                block = declaration.parent if declaration else None
                if (
                    declaration
                    and declaration.type == "local_variable_declaration"
                    and block
                    and block.type == "block"
                ):
                    key = (name, block)
                    self.locals[key] = None if key in self.locals else n
                    self.declarations[name] += 1
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
            elif n.type == "return_statement" and n.named_child_count == 1:
                self.returns.append(n.named_children[0])
            elif n.type == "method_invocation":
                self.calls.append(n)
            pending.extend(reversed(n.named_children))

    def binding(self, ref: Node) -> Node | None:
        if ref.type != "identifier":
            return None
        name = _text(ref)
        if not self.declarations[name] or self.writes[name] != self.declarations[name]:
            return None
        scope = ref.parent
        while scope is not None and scope.type not in _BOUNDARIES:
            if scope.type == "block" and (name, scope) in self.locals:
                definition = self.locals[(name, scope)]
                if definition is not None and definition.end_byte <= ref.start_byte:
                    return definition
                return None
            scope = scope.parent
        return None

    def value(self, ref: Node) -> Node | None:
        definition = self.binding(ref)
        return definition.child_by_field_name("value") if definition is not None else None

    def parameter(self, ref: Node | None, allowed: set[str]) -> str:
        name = _text(ref)
        return name if self.writes[name] == 1 and self.params.get(name) in allowed else ""

    def owner(self, expr: Node | None) -> str | None:
        name = _text(expr)
        first = name.split(".")[0]
        return None if self.writes[first] or first in self.fields.names else self.types.get(name)

    def field(self, obj: Node | None) -> str:
        if (
            obj is not None
            and obj.type == "field_access"
            and _text(obj.child_by_field_name("object")) == "this"
        ):
            return _text(obj.child_by_field_name("field"))
        name = _text(obj)
        return name if not self.writes[name] else ""

    def weak_receiver(self, obj: Node) -> bool:
        if self.field(obj) in self.fields.generators:
            return True
        allocated = self.value(obj) if obj.type == "identifier" else obj
        return _allocation(allocated, self.types) == "java.util.Random"

    def predictable_part(self, expr: Node | None, depth: int) -> bool:
        if expr is None or depth > 12:
            return False
        if expr.type in {"string_literal", "decimal_integer_literal", "character_literal"}:
            return True
        if expr.type == "identifier":
            return self.predictable_part(self.value(expr), depth + 1)
        if expr.type == "binary_expression" and _text(expr.child_by_field_name("operator")) == "+":
            return all(
                self.predictable_part(expr.child_by_field_name(side), depth + 1)
                for side in ("left", "right")
            )
        return (
            expr.type == "method_invocation"
            and self.owner(expr.child_by_field_name("object")) == "java.lang.System"
            and _name(expr) in {"currentTimeMillis", "nanoTime"}
            and not _args(expr)
        )

    def buffer_refs(self) -> dict[str, list[Node]]:
        if self._buffer_refs is not None:
            return self._buffer_refs
        indexed: dict[str, list[Node]] = {
            name: []
            for (name, _), definition in self.locals.items()
            if definition is not None
            and (value := definition.child_by_field_name("value")) is not None
            and value.type == "array_creation_expression"
        }
        # Include references captured by lambdas and nested classes. A second
        # traversal indexes only array uses, once per method, in source order.
        pending = [self.method]
        steps = 0
        while pending:
            node = pending.pop()
            steps += 1
            if steps > 100_000:
                indexed.clear()
                break
            if node.type == "identifier" and (name := _text(node)) in indexed:
                indexed[name].append(node)
            pending.extend(reversed(node.named_children))
        self._buffer_refs = indexed
        return indexed

    def byte_origin(self, ref: Node, encoder: Node) -> _Origin | None:
        definition = self.binding(ref)
        if definition is None:
            return None
        initial = definition.child_by_field_name("value")
        if (
            initial is None
            or initial.type != "array_creation_expression"
            or _text(initial.child_by_field_name("type")) != "byte"
        ):
            return None
        dimensions = initial.children_by_field_name("dimensions")
        if len(dimensions) != 1:
            return None
        size = next(iter(dimensions[0].named_children), None)
        items = initial.child_by_field_name("value")
        if (items is not None and items.named_child_count == 0) or (
            size is not None and size.type == "decimal_integer_literal" and _text(size) == "0"
        ):
            return None
        declaration = definition.parent
        block = declaration.parent if declaration is not None else None
        if block is None or declaration is None:
            return None
        # Allocation, fill and encoding must execute in order on the same pass.
        statement = encoder
        while statement.parent is not None and statement.parent != block:
            statement = statement.parent
        if statement.parent != block or statement.type not in {
            "local_variable_declaration",
            "expression_statement",
            "return_statement",
        }:
            return None
        references = self.buffer_refs().get(_text(ref), [])
        start = bisect_left(references, definition.end_byte, key=lambda n: n.start_byte)
        stop = bisect_left(references, ref.start_byte, key=lambda n: n.start_byte)
        if stop - start != 1:
            # Any other reference could expose or overwrite the array.
            return None
        operand = references[start]
        args = operand.parent
        fill = args.parent if args is not None and args.type == "argument_list" else None
        if fill is None or fill.type != "method_invocation" or _name(fill) != "nextBytes":
            return None
        parent = fill.parent
        receiver = fill.child_by_field_name("object")
        if (
            _args(fill) != [operand]
            or parent is None
            or parent.type != "expression_statement"
            or parent.parent != block
            or receiver is None
            or not self.weak_receiver(receiver)
        ):
            return None
        return _Origin(
            "java.util.Random.nextBytes", fill.start_point.row + 1, encoder.start_point.row + 1
        )

    def known_encoder(self, expr: Node, receiver: Node, args: list[Node]) -> bool:
        if receiver.type != "method_invocation":
            return False
        factory = receiver
        if _name(factory) == "withoutPadding" and not _args(factory):
            inner = factory.child_by_field_name("object")
            if inner is None or inner.type != "method_invocation":
                return False
            factory = inner
        owner = self.owner(factory.child_by_field_name("object"))
        if _args(factory):
            return False
        factory_name, name = _name(factory), _name(expr)
        if owner == "java.util.Base64":
            return (
                factory_name in {"getEncoder", "getUrlEncoder", "getMimeEncoder"}
                and name == "encodeToString"
                and len(args) == 1
            )
        if receiver != factory:
            return False
        if owner == "java.util.HexFormat":
            return factory_name == "of" and name == "formatHex" and len(args) == 1
        return (
            owner == "org.owasp.esapi.ESAPI"
            and factory_name == "encoder"
            and name == "encodeForBase64"
            and len(args) == 2
            and args[1].type in {"true", "false"}
        )

    def origin(self, expr: Node | None, depth: int = 0) -> _Origin | None:
        if expr is None or depth > 12:
            return None
        if expr.type == "identifier":
            return self.origin(self.value(expr), depth + 1)
        if expr.type == "parenthesized_expression" and expr.named_child_count == 1:
            return self.origin(expr.named_child(0), depth + 1)
        if expr.type == "binary_expression" and _text(expr.child_by_field_name("operator")) == "+":
            left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
            if self.predictable_part(left, depth + 1):
                return self.origin(right, depth + 1)
            if self.predictable_part(right, depth + 1):
                return self.origin(left, depth + 1)
        if expr.type != "method_invocation":
            return None
        receiver = expr.child_by_field_name("object")
        if receiver is None:
            return None
        name, args = _name(expr), _args(expr)
        owner = self.owner(receiver)
        if owner == "java.lang.Math" and name == "random" and not args:
            return _Origin("java.lang.Math.random", expr.start_point.row + 1)
        if name in _GENERATORS and self.weak_receiver(receiver):
            return _Origin(f"java.util.Random.{name}", expr.start_point.row + 1)
        if args and self.known_encoder(expr, receiver, args):
            return self.byte_origin(args[0], expr)
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
        definition = self.binding(owner) if owner is not None else None
        if definition is None:
            return False
        value = definition.child_by_field_name("value")
        if value is None or value.type != "array_access":
            return False
        declaration = definition.parent
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
                        generator=origin.api,
                        generator_line=origin.line,
                        encoding_line=origin.encoding_line,
                        use="servlet session value compared with a cookie"
                        if compare_line
                        else "servlet session credential field",
                        use_line=call.start_point.row + 1,
                        comparison_line=compare_line,
                    )
                )
        return facts

    def looked_up_stores(self) -> set[str]:
        result = set()
        for returned in self.returns:
            read = self.value(returned) if returned.type == "identifier" else returned
            if read is None or read.type != "method_invocation" or _name(read) != "get":
                continue
            field = self.field(read.child_by_field_name("object"))
            args = _args(read)
            if (
                field in self.fields.stores
                and self.fields.stores[field] == _text(self.method.child_by_field_name("type"))
                and len(args) == 1
                and self.parameter(args[0], {"java.lang.String"})
            ):
                result.add(field)
        return result

    def registered_sessions(self, stores: set[str]) -> list[CredentialRandomness]:
        if (
            not stores
            or self.types.get(_text(self.method.child_by_field_name("type"))) != "java.lang.String"
        ):
            return []
        facts = []
        for call in self.calls:
            field = self.field(call.child_by_field_name("object"))
            args = _args(call)
            if field not in stores or _name(call) != "put" or len(args) != 2:
                continue
            key, record = args
            statement = call.parent
            if (
                key.type != "identifier"
                or record.type != "object_creation_expression"
                or _text(record.child_by_field_name("type")) != self.fields.stores[field]
                or not _args(record)
                or _text(_args(record)[0]) != _text(key)
                or statement is None
                or statement.type != "expression_statement"
            ):
                continue
            following = statement.next_named_sibling
            while following is not None and following.type in {"line_comment", "block_comment"}:
                following = following.next_named_sibling
            if (
                following is None
                or following.type != "return_statement"
                or not any(
                    value.type == "identifier" and _text(value) == _text(key)
                    for value in following.named_children
                )
            ):
                continue
            if origin := self.origin(key):
                facts.append(
                    CredentialRandomness(
                        generator=origin.api,
                        generator_line=origin.line,
                        encoding_line=origin.encoding_line,
                        use="session registry key returned to the caller",
                        use_line=call.start_point.row + 1,
                    )
                )
        return facts


def credential_uses(methods: list[Node], types: dict[str, str]) -> list[CredentialRandomness]:
    by_class: dict[Node, list[Node]] = defaultdict(list)
    for method in methods:
        if method.parent is not None and not method.has_error:
            by_class[method.parent].append(method)
    facts = []
    for body, declarations in by_class.items():
        fields = _Fields.read(body, types)
        analyzed = [
            _Method(method, types, fields)
            for method in declarations
            if fields.stores or b"setAttribute" in (method.text or b"")
        ]
        stores = (
            {store for method in analyzed for store in method.looked_up_stores()}
            if fields.stores
            else set()
        )
        for review in analyzed:
            facts.extend(review.facts())
            if stores:
                facts.extend(review.registered_sessions(stores))
    return facts
