"""Select raw operands of Flask HTML responses without importing the scanned application."""

from __future__ import annotations

import ast
import re
from collections import Counter
from string import Formatter
from typing import Literal

from aegify.models import FileAST, FlaskBodyPart, FlaskResponse
from aegify.scanner.python_literals import LiteralInputs
from aegify.scanner.python_scope import (
    PythonScope,
    call_argument,
    dominating_facts,
    imported_name,
    module_name,
    python_scopes,
)
from aegify.scanner.python_storage import LocalValues
from aegify.source_files import read_scanned_source

type _Binding = tuple[Literal["declared", "imported", "injected"], str]

_ROUTERS = {"flask.Flask", "flask.Blueprint", "flask.app.Flask", "flask.blueprints.Blueprint"}
_ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete"}
_TEXT_INPUTS = {"args", "form", "cookies", "headers", "values"}
_ENCODERS = {"html.escape", "markupsafe.escape", "bleach.clean"}
_RESPONSE_APIS = {"flask.make_response", "flask.Response", "flask.wrappers.Response"}
# Complete ordinary tags cannot change the lexical context of a following interpolation.
_TEXT_TAG = re.compile(
    r"</?(?:p|div|span|em|strong|b|i|u|h[1-6]|ul|ol|li|br|section|main|article|pre|code)"
    r"""(?:\s+(?:class|id|lang|dir|title)=(?:"[^"<>]*"|'[^'<>]*'))*\s*/?>""",
    re.I,
)
_FIELD = re.compile(r"(\w*)(?:\[([\w-]+)\])?\Z")
_PERCENT = re.compile(r"%(?:\(([\w-]+)\))?[-+# 0]*\d*(?:\.\d+)?([sra%])")
# A restricted grammar for a negated character class. A bare hyphen is accepted
# only at the end so a range cannot accidentally include HTML delimiters.
_TEXT_ALPHABET = re.compile(r"\[\^(?:a-z|A-Z|0-9|[A-Za-z0-9 .,!_?]|\\[s.?!,\-])+-?\]")


def _string(node: ast.expr | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _plain_text(literals: list[str]) -> bool:
    return all(
        len(piece) <= 16_384 and not re.search("[<>]", _TEXT_TAG.sub("", piece))
        for piece in literals
    )


def _declared_routers(scope: PythonScope) -> dict[str, int]:
    declared = {}
    for statement in scope.owner.body:
        if not isinstance(statement, ast.Assign | ast.AnnAssign):
            continue
        if (
            not isinstance(statement.value, ast.Call)
            or scope.resolve(statement.value.func) not in _ROUTERS
        ):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        for target in targets:
            if isinstance(target, ast.Name) and scope.definitions.get(target.id) == 1:
                declared[target.id] = statement.lineno
    for node in scope.nodes:
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Store | ast.Del)
            and isinstance(node.value, ast.Name)
            and node.attr in _ROUTE_METHODS | {"response_class", "make_response"}
        ):
            declared.pop(node.value.id, None)
    return declared


def _binding(
    scope: PythonScope,
    parents: dict[ast.AST, PythonScope],
    declared: dict[ast.AST, dict[str, int]],
) -> _Binding | None:
    view = scope.owner
    assert isinstance(view, ast.FunctionDef | ast.AsyncFunctionDef)
    outer = parents.get(view)
    if outer is None:
        return None
    for decorator in view.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        method = decorator.func
        if method.attr not in _ROUTE_METHODS:
            continue
        receiver = method.value
        if isinstance(receiver, ast.Name):
            name = receiver.id
            enclosing: PythonScope | None = outer
            while enclosing is not None:
                if name in enclosing.definitions:
                    if declared[enclosing.owner].get(name, view.lineno) < view.lineno:
                        return "declared", ""
                    if enclosing is outer and isinstance(
                        outer.owner, ast.FunctionDef | ast.AsyncFunctionDef
                    ):
                        args = outer.owner.args
                        for param in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                            if param.arg != name or outer.definitions[name] != 1:
                                continue
                            if param.annotation is not None:
                                if outer.resolve(param.annotation) in _ROUTERS:
                                    return "declared", ""
                            elif method.attr == "route" and any(
                                isinstance(n, ast.expr) and scope.resolve(n) == "flask.request"
                                for n in scope.nodes
                            ):
                                return "injected", ""
                    break
                enclosing = parents.get(enclosing.owner)
        if reference := outer.resolve(receiver):
            return "imported", reference
    return None


def _headers(node: ast.expr) -> bool:
    if isinstance(node, ast.Dict):
        pairs = list(zip(node.keys, node.values, strict=True))
    elif isinstance(node, ast.Tuple | ast.List):
        pairs = []
        for pair in node.elts:
            if not isinstance(pair, ast.List | ast.Tuple) or len(pair.elts) != 2:
                return False
            pairs.append((pair.elts[0], pair.elts[1]))
    else:
        return False
    for key, value in pairs:
        name = _string(key)
        if name is None:
            return False
        if name.lower() == "content-type" and not _html_type(value):
            return False
        if name.lower() == "content-disposition":
            disposition = _string(value)
            if disposition is None or disposition.split(";")[0].strip().lower() != "inline":
                return False
    return True


def _html_type(node: ast.expr) -> bool:
    text = _string(node)
    return text is not None and text.split(";")[0].strip().lower() == "text/html"


class _Body:
    def __init__(self, scope: PythonScope, literals: dict[str, str]) -> None:
        self.literals = literals
        self.local = LocalValues(scope)
        self.inputs = LiteralInputs(self.local)
        self.scope = scope
        self.has_re_sub = any(name in {"re", "re.sub"} for name, _ in scope.imports.values())
        self.budget = 256
        self.return_line = 0
        counts = Counter(n.lineno for n in scope.nodes if isinstance(n, ast.stmt))
        self.ambiguous_lines = {line for line, count in counts.items() if count > 1}

    def _line(self, node: ast.expr) -> int:
        current: ast.AST = node
        while current in self.scope.parents and not isinstance(current, ast.stmt):
            current = self.scope.parents[current]
        return current.lineno if isinstance(current, ast.stmt) else node.lineno

    def _source(self, node: ast.expr) -> str:
        receiver: ast.expr
        if isinstance(node, ast.Subscript):
            receiver = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
        ):
            receiver = node.func.value
        else:
            return ""
        path = self.scope.resolve(receiver)
        if (
            path.startswith("flask.request.")
            and path.removeprefix("flask.request.") in _TEXT_INPUTS
        ):
            return path.removeprefix("flask.")
        return ""

    def _numeric_get(self, node: ast.expr) -> bool:
        if not isinstance(node, ast.Call) or not self._source(node):
            return False
        cast = call_argument(node, 2, "type")
        return bool(
            cast
            and isinstance(cast[1], ast.Name)
            and cast[1].id in {"int", "float"}
            and cast[1].id not in self.scope.hidden
        )

    def _object_alias(self, node: ast.expr, depth: int = 0) -> bool:
        if isinstance(node, ast.Call):
            return self.scope.resolve(node.func) in _RESPONSE_APIS
        if isinstance(node, ast.Name) and depth < 12:
            target = self.local.assigned(node)
            return target is not None and self._object_alias(target, depth + 1)
        return False

    def _literal(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant):
            return _string(node)
        return self.literals.get(self.scope.resolve(node)) if self.literals else None

    def _header_write(self, read: ast.Name) -> bool:
        """Recognize only direct assignments to literal response metadata."""
        headers = self.scope.parents.get(read)
        target = self.scope.parents.get(headers) if headers is not None else None
        stmt = self.scope.parents.get(target) if target is not None else None
        if not (
            isinstance(headers, ast.Attribute)
            and headers.value is read
            and headers.attr == "headers"
            and isinstance(target, ast.Subscript)
            and target.value is headers
            and isinstance(stmt, ast.Assign)
            and stmt.targets == [target]
        ):
            return False
        key = _string(target.slice)
        value = _string(stmt.value)
        return bool(
            key
            and key.lower() in {"cache-control", "x-request-id", "x-xss-protection"}
            and value is not None
            and all(32 <= ord(char) < 127 for char in value)
        )

    def _ordinary_piece(self, node: ast.expr, depth: int = 0) -> bool:
        """A fixed prefix or suffix may move a later insertion into an attribute or script."""
        if depth > 12 or not self.budget:
            return False
        self.budget -= 1
        if (literal := self._literal(node)) is not None:
            return _plain_text([literal])
        if isinstance(node, ast.Name):
            value = self.local.assigned(node)
            return value is not None and self._ordinary_piece(value, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._ordinary_piece(node.left, depth + 1) and self._ordinary_piece(
                node.right, depth + 1
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            literal = self._literal(node.left)
            return literal is not None and _plain_text([literal])
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            literal = self._literal(node.func.value)
            return literal is not None and _plain_text([literal])
        if isinstance(node, ast.JoinedStr):
            return _plain_text(
                [
                    v.value
                    for v in node.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                ]
            )
        return bool(
            self._source(node)
            or (isinstance(node, ast.Call) and self.scope.resolve(node.func) in _ENCODERS)
        )

    def _atom(self, node: ast.expr, text: bool) -> list[FlaskBodyPart]:
        return [
            FlaskBodyPart(
                line=self._line(node),
                expression=ast.unparse(node),
                text_context=text,
                request_source=self._source(node),
                source_line=node.lineno,
            )
        ]

    def _returns_before(self, assignment: ast.stmt, use: ast.Name) -> bool:
        """A write followed immediately by a return cannot reach a later sibling path."""
        parent = self.scope.parents.get(assignment)
        if not isinstance(parent, ast.If):
            return False
        arm = parent.body if assignment in parent.body else parent.orelse
        if len(arm) < 2 or arm[-2] is not assignment or not isinstance(arm[-1], ast.Return):
            return False
        outer: ast.stmt = parent
        while (container := self.scope.parents.get(outer)) is not self.scope.owner:
            if not isinstance(container, ast.If | ast.For | ast.While):
                return False
            outer = container
        return self.scope.precedes(outer, use)

    def _last_values(self, name: ast.Name) -> list[ast.expr] | None:
        stores = self.local.stores.get(name.id, [])
        if name.id in self.local.closed_over or len(stores) != self.scope.definitions.get(
            name.id, 0
        ):
            return None
        values: list[ast.expr] = []
        for target in stores:
            if target.lineno > name.lineno and not self.local.in_loop(name):
                continue
            stmt = self.scope.parents[target]
            if isinstance(stmt, ast.Assign | ast.AnnAssign) and stmt.lineno == self._line(name):
                continue
            if isinstance(stmt, ast.Assign | ast.AnnAssign) and self._returns_before(stmt, name):
                continue
            if not isinstance(
                stmt, ast.Assign | ast.AnnAssign | ast.AugAssign
            ) or not self.scope.precedes(stmt, name):
                return None
            if stmt.value is None or (
                isinstance(stmt, ast.AugAssign) and not isinstance(stmt.op, ast.Add)
            ):
                return None
            values.append(stmt.value)
            if not isinstance(stmt, ast.AugAssign):
                return list(reversed(values))
        return None

    def _substituted_body(
        self, node: ast.expr, text: bool, depth: int
    ) -> list[FlaskBodyPart] | None:
        """Track the subject and replacements of bounded, statically bound re.sub calls."""
        if not self.has_re_sub or not isinstance(node, ast.Call | ast.Name):
            return None
        current: ast.expr = node
        calls: list[ast.Call] = []
        for _ in range(32):
            if current.lineno in self.ambiguous_lines or self.local.in_loop(current):
                break
            if isinstance(current, ast.Name):
                reaching = self._last_values(current)
                if not reaching or len(reaching) != 1:
                    break
                bound = reaching[0]
                if not (
                    isinstance(bound, ast.Name)
                    or isinstance(bound, ast.Call)
                    and self.scope.resolve(bound.func) == "re.sub"
                ):
                    break
                current = bound
                continue
            if not (
                isinstance(current, ast.Call)
                and self.scope.resolve(current.func) == "re.sub"
                and len(current.args) == 3
                and _string(current.args[0]) is not None
                and all(kw.arg in {"count", "flags"} for kw in current.keywords)
            ):
                break
            calls.append(current)
            current = current.args[2]
        if not calls:
            return None
        empty_replacements = all(_string(call.args[1]) == "" for call in calls)
        parts = self._value(current, text and empty_replacements, depth + 1)
        for call in reversed(calls):
            replacement = call.args[1]
            pattern = _string(call.args[0])
            if _string(replacement) != "":
                parts.extend(self._value(replacement, False, depth + 1))
                for part in parts:
                    part.html_text_filter_line = 0
            elif (
                not call.keywords
                and pattern
                and len(pattern) <= 256
                and _TEXT_ALPHABET.fullmatch(pattern)
            ):
                for part in parts:
                    part.html_text_filter_line = call.lineno
            for part in parts:
                part.substitution_lines.append(call.lineno)
        return parts

    def _value(self, node: ast.expr, text: bool, depth: int) -> list[FlaskBodyPart]:
        """A field is converted to text. Only model known value-preserving operations."""
        if isinstance(node, ast.Constant) or not self.budget or depth > 18:
            return []
        self.budget -= 1
        if (substituted := self._substituted_body(node, text, depth)) is not None:
            return substituted
        if isinstance(node, ast.IfExp):
            if (outcome := self._known_condition(node.test)) is not None:
                return self._value(node.body if outcome else node.orelse, text, depth + 1)
            return self._value(node.body, text, depth + 1) + self._value(
                node.orelse, text, depth + 1
            )
        if isinstance(node, ast.Subscript) and (stored := self.local.stored_source(node)):
            return self._value(stored[0], text, depth + 1)
        if isinstance(node, ast.Name):
            assigned = self.local.assigned(node)
            if assigned is None:
                reaching = self._last_values(node)
                if reaching and len(reaching) == 1:
                    assigned = reaching[0]
            if assigned is not None and (
                isinstance(assigned, ast.Name | ast.Constant | ast.IfExp) or self._source(assigned)
            ):
                return self._value(assigned, text, depth + 1)
            if isinstance(assigned, ast.JoinedStr | ast.BinOp) or (
                isinstance(assigned, ast.Call)
                and (
                    self.scope.resolve(assigned.func) in _ENCODERS
                    or isinstance(assigned.func, ast.Attribute)
                    and assigned.func.attr == "format"
                    and self._literal(assigned.func.value) is not None
                )
            ):
                parts = self._body(assigned, depth + 1, text)
                if parts is not None:
                    return parts
            return self._atom(node, text)
        if isinstance(node, ast.Call):
            api = self.scope.resolve(node.func)
            if self._numeric_get(node):
                fallback = call_argument(node, 1, "default")
                return self._value(fallback[1], text, depth + 1) if fallback else []
            if api in _ENCODERS and len(node.args) == 1 and not node.keywords:
                return [] if text else self._value(node.args[0], False, depth + 1)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "str"
                and "str" not in self.scope.hidden
            ):
                if len(node.args) == 1 and not node.keywords:
                    return self._value(node.args[0], text, depth + 1)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and (literal := self._literal(node.func.value)) is not None
            ):
                return self._format(literal, node, text, depth)
            if not self._source(node):
                return []
        return self._atom(node, text)

    def _mapping(self, obj: ast.expr, key: str, text: bool, depth: int) -> list[FlaskBodyPart]:
        if isinstance(obj, ast.Dict):
            if any(_string(k) is None for k in obj.keys):
                return []
            values = [v for k, v in zip(obj.keys, obj.values, strict=True) if _string(k) == key]
            return self._value(values[-1], text, depth + 1) if values else []
        selected = self.local.mapping_item(obj, key)
        return self._value(selected[0], text, depth + 1) if selected else []

    def _format(self, literal: str, call: ast.Call, text: bool, depth: int) -> list[FlaskBodyPart]:
        if len(literal) > 16_384:
            return []
        try:
            fields = list(Formatter().parse(literal))
        except ValueError:
            return []
        if (
            len(fields) > 64
            or any(isinstance(a, ast.Starred) for a in call.args)
            or any(k.arg is None for k in call.keywords)
        ):
            return []
        ordinary = text and _plain_text([s for s, _, _, _ in fields])
        named = {item.arg: item.value for item in call.keywords}
        parts = []
        numbered = automatic = False
        next_index = 0
        for _, field, spec, conversion in fields:
            if field is None:
                continue
            match = _FIELD.fullmatch(field)
            if (
                not match
                or conversion not in {None, "s", "r", "a"}
                or "{" in (spec or "")
                or "}" in (spec or "")
            ):
                return []
            name, key = match.groups()
            if name == "" or name.isdecimal():
                automatic |= name == ""
                numbered |= name != ""
                if (automatic and numbered) or len(name) > 6:
                    return []
                index = int(name) if name else next_index
                next_index += 1
                value = call.args[index] if index < len(call.args) else None
            else:
                value = named.get(name)
            if value is None:
                return []
            parts.extend(
                self._mapping(value, key, ordinary, depth)
                if key
                else self._value(value, ordinary, depth + 1)
            )
        return parts

    def _percent(
        self, literal: str, operand: ast.expr, text: bool, depth: int
    ) -> list[FlaskBodyPart]:
        if len(literal) > 16_384:
            return []
        offset = 0
        pieces = []
        fields = []
        for match in _PERCENT.finditer(literal):
            pieces.append(literal[offset : match.start()])
            offset = match.end()
            if match[2] != "%":
                fields.append(match)
        pieces.append(literal[offset:])
        if len(fields) > 64 or any("%" in piece for piece in pieces):
            return []
        ordinary = text and _plain_text(pieces)
        if fields and all(field[1] for field in fields):
            return [
                part
                for field in fields
                for part in self._mapping(operand, field[1], ordinary, depth)
            ]
        values = operand.elts if isinstance(operand, ast.Tuple) else [operand]
        if any(field[1] for field in fields) or len(fields) != len(values):
            return []
        return [part for value in values for part in self._value(value, ordinary, depth + 1)]

    def _body(self, node: ast.expr, depth: int, text: bool = True) -> list[FlaskBodyPart] | None:
        if not self.budget or depth > 18:
            return None
        self.budget -= 1
        if (substituted := self._substituted_body(node, text, depth)) is not None:
            return substituted
        if isinstance(node, ast.Constant):
            return [] if isinstance(node.value, str | bytes) else None
        if isinstance(node, ast.Subscript) and (stored := self.local.stored_source(node)):
            return self._body(stored[0], depth + 1, text)
        if isinstance(node, ast.Name):
            values = self._last_values(node)
            if not values:
                return None
            if len(values) > 1:
                text = text and all(self._ordinary_piece(value) for value in values)
            parts: list[FlaskBodyPart] = []
            for value in values:
                if self._object_alias(value):
                    if any(
                        read is not node
                        and value.lineno <= read.lineno <= self.return_line
                        and not self._header_write(read)
                        for read in self.local.loads[node.id]
                    ):
                        return None
                item = self._body(value, depth + 1, text)
                if item is None:
                    return None
                parts.extend(item)
            return parts
        if isinstance(node, ast.JoinedStr):
            ordinary = text and _plain_text(
                [
                    v.value
                    for v in node.values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                ]
            )
            return [
                part
                for field in node.values
                if isinstance(field, ast.FormattedValue)
                for part in self._value(field.value, ordinary, depth + 1)
            ]
        if isinstance(node, ast.Tuple) and len(node.elts) in {2, 3}:
            final = node.elts[-1]
            if (
                len(node.elts) == 2
                and isinstance(final, ast.Constant)
                and isinstance(final.value, int | str)
            ):
                return self._body(node.elts[0], depth + 1, text)
            return self._body(node.elts[0], depth + 1, text) if _headers(final) else None
        if self._numeric_get(node):
            return self._value(node, text, depth + 1)
        if self._source(node):
            return self._atom(node, text)
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mod)
            and (literal := self._literal(node.left)) is not None
        ):
            return self._percent(literal, node.right, text, depth)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            text = text and self._ordinary_piece(node)
            left = self._body(node.left, depth + 1, text)
            right = self._body(node.right, depth + 1, text)
            if left is None and right is None:
                return None
            return (self._value(node.left, text, depth + 1) if left is None else left) + (
                self._value(node.right, text, depth + 1) if right is None else right
            )
        if isinstance(node, ast.Call):
            api = self.scope.resolve(node.func)
            if api in _ENCODERS or isinstance(node.func, ast.Name) and node.func.id == "str":
                return self._value(node, text, depth + 1)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and (literal := self._literal(node.func.value)) is not None
            ):
                return self._format(literal, node, text, depth)
            if api == "flask.make_response" and node.args and not node.keywords:
                if len(node.args) == 1:
                    return self._body(node.args[0], depth + 1, text)
                if len(node.args) in {2, 3}:
                    return self._body(ast.Tuple(elts=node.args, ctx=ast.Load()), depth + 1, text)
            if api in _RESPONSE_APIS - {"flask.make_response"}:
                selected = call_argument(node, 0, "response")
                if selected is None:
                    return None
                for index, key in ((2, "headers"), (3, "mimetype"), (4, "content_type")):
                    option = call_argument(node, index, key)
                    if option and not (
                        _headers(option[1]) if key == "headers" else _html_type(option[1])
                    ):
                        return None
                return self._body(selected[1], depth + 1, text)
        return None

    def _known_condition(self, test: ast.expr) -> bool | None:
        if isinstance(test, ast.Constant) and isinstance(test.value, bool):
            return test.value
        # If builtin len returns at all, its result is a nonnegative integer.
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.left, ast.Call)
            and isinstance(test.left.func, ast.Name)
            and test.left.func.id == "len"
            and "len" not in self.scope.hidden
            and "builtins.len" not in self.scope.modified
            and len(test.left.args) == 1
            and not test.left.keywords
            and isinstance(test.comparators[0], ast.Constant)
            and type(test.comparators[0].value) is int
            and test.comparators[0].value == 0
        ):
            if isinstance(test.ops[0], ast.GtE):
                return True
            if isinstance(test.ops[0], ast.Lt):
                return False
        return self.inputs.condition(test)

    def response(self, node: ast.Return, binding: _Binding) -> FlaskResponse | None:
        self.budget = 256
        self.return_line = node.lineno
        if node.value is None or node.lineno in self.ambiguous_lines:
            return None
        parts = self._body(node.value, 0)
        if not parts or not self.budget or any(p.line in self.ambiguous_lines for p in parts):
            return None
        if any(
            (known := self._known_condition(test)) is not None and known != required
            for test, required in dominating_facts(self.scope, node)
        ):
            return None
        owner = self.scope.owner
        assert isinstance(owner, ast.FunctionDef | ast.AsyncFunctionDef)
        unique = {
            (
                part.line,
                part.expression,
                part.text_context,
                part.request_source,
                part.html_text_filter_line,
                tuple(part.substitution_lines),
            ): part
            for part in parts
        }
        constructed = self.local.assigned(node.value)
        return FlaskResponse(
            function_line=owner.lineno,
            return_line=node.lineno,
            construction_line=(
                constructed.lineno
                if isinstance(constructed, ast.Call)
                and self.scope.resolve(constructed.func) in _RESPONSE_APIS
                else 0
            ),
            binding=binding[0],
            router=binding[1],
            parts=list(unique.values()),
        )


type ResponseFacts = tuple[list[str], list[FlaskResponse]]


def response_facts(
    source: bytes | ast.Module, literals: dict[str, str] | None = None
) -> ResponseFacts:
    if isinstance(source, bytes) and b"flask" not in source and b"@" not in source:
        return [], []
    scopes = iter(python_scopes(source))
    module = next(scopes, None)
    if module is None:
        return [], []
    declared: dict[ast.AST, dict[str, int]] = {}
    parents: dict[ast.AST, PythonScope] = {}
    responses = []
    for scope in (module, *scopes):
        declared[scope.owner] = _declared_routers(scope)
        parents.update(
            {
                node: scope
                for node in scope.parents
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
            }
        )
        view = scope.owner
        if not isinstance(view, ast.FunctionDef | ast.AsyncFunctionDef) or not view.decorator_list:
            continue
        if (binding := _binding(scope, parents, declared)) is None:
            continue
        body = _Body(scope, literals or {})
        returns = [node for node in scope.nodes if isinstance(node, ast.Return)]
        lines = Counter(node.lineno for node in returns)
        for node in returns:
            if lines[node.lineno] == 1 and (fact := body.response(node, binding)):
                responses.append(fact)
    return sorted(declared[module.owner]), sorted(
        responses, key=lambda fact: (fact.function_line, fact.return_line)
    )


def _snapshot_module(file: FileAST) -> ast.Module | None:
    material = read_scanned_source(file, 512 * 1024)
    if material is not None:
        try:
            return ast.parse(material)
        except SyntaxError, ValueError, RecursionError:
            pass
    return None


type _Exports = tuple[dict[str, str], list[str]]


def _static_exports(file: FileAST) -> _Exports | None:
    """Accept only a complete module of literal assignments, including its star namespace."""
    module = _snapshot_module(file)
    if module is None or len(module.body) > 128:
        return None
    names: set[str] = set()
    literals: dict[str, str] = {}
    explicit = None
    for stmt in module.body:
        if (
            isinstance(stmt, ast.Expr)
            and stmt is module.body[0]
            and _string(stmt.value) is not None
        ):
            continue
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            return None
        name = stmt.targets[0].id
        if name in names or name.startswith("__") and name != "__all__":
            return None
        names.add(name)
        if name == "__all__":
            if not isinstance(stmt.value, ast.List | ast.Tuple):
                return None
            explicit = []
            for item in stmt.value.elts:
                if (exported := _string(item)) is None or not exported.isidentifier():
                    return None
                explicit.append(exported)
        elif (value := _string(stmt.value)) is not None:
            if len(value) <= 16_384:
                literals[name] = value
        elif any(
            not isinstance(node, ast.Dict | ast.List | ast.Tuple | ast.Constant | ast.Load)
            or isinstance(node, ast.Dict)
            and any(not isinstance(key, ast.Constant) for key in node.keys)
            for node in ast.walk(stmt.value)
        ):
            return None
    if explicit is not None and not names.issuperset(explicit):
        return None
    return literals, sorted(
        set(explicit)
        if explicit is not None
        else {name for name in names if not name.startswith("_")}
    )


def linked_response_facts(files: list[FileAST]) -> dict[tuple[str, str], ResponseFacts]:
    """Bind string formats using only unique modules in this repository's scan inventory."""
    modules: dict[tuple[str, str], FileAST | None] = {}
    for file in files:
        if name := module_name(file.module_path):
            key = (file.repository_id, name)
            modules[key] = None if key in modules else file
    cache: dict[tuple[str, str], _Exports | None] = {}
    linked = {}
    for file in files:
        if not file.module_path.endswith(".py") or not any(f.decorators for f in file.functions):
            continue
        providers = {}
        for imp in file.imports:
            key = (file.repository_id, imported_name(file.module_path, imp.module))
            candidate = modules.get(key)
            if candidate is None or candidate.imports or candidate.functions or candidate.classes:
                continue
            if key not in cache:
                cache[key] = _static_exports(candidate)
            if (exports := cache[key]) is not None:
                providers[imp.module] = exports
        if not providers or (tree := _snapshot_module(file)) is None:
            continue
        literals = {
            (ref + ("" if ref.endswith(".") else ".") + name): literal
            for ref, (strings, _) in providers.items()
            for name, literal in strings.items()
        }
        # Never remove an unresolved star. The scope resolver abstains if any remain.
        for stmt in tree.body:
            if isinstance(stmt, ast.ImportFrom) and any(item.name == "*" for item in stmt.names):
                ref = "." * stmt.level + (stmt.module or "")
                if ref in providers:
                    stmt.names = [ast.alias(name=name) for name in providers[ref][1]]
        linked[file.repository_id, file.file_path] = response_facts(tree, literals)
    return linked


def project_routers(
    files: list[FileAST], linked: dict[tuple[str, str], ResponseFacts] | None = None
) -> set[tuple[str, str]]:
    modules = Counter(
        (file.repository_id, module_name(file.module_path))
        for file in files
        if file.module_path.endswith(".py")
    )
    return {
        (file.repository_id, f"{module}.{router}")
        for file in files
        if (module := module_name(file.module_path)) and modules[file.repository_id, module] == 1
        for router in (
            linked[file.repository_id, file.file_path][0]
            if linked and (file.repository_id, file.file_path) in linked
            else file.flask_routers
        )
    }


def registered_import(file: FileAST, reference: str, routers: set[tuple[str, str]]) -> bool:
    return (file.repository_id, imported_name(file.module_path, reference)) in routers
