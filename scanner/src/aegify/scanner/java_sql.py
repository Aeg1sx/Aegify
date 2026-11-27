"""Static SQL-text evidence at typed JDBC calls, bounded to one Java method."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from tree_sitter import Node

from aegify.models import FileAST, QueryExpression
from aegify.scanner.java_types import known_types

CONNECTION_METHODS = frozenset({"prepareStatement", "prepareCall"})
STATEMENT_METHODS = frozenset(
    {"execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch"}
)
JDBC_METHODS = CONNECTION_METHODS | STATEMENT_METHODS
_REQUESTS = {"javax.servlet.http.HttpServletRequest", "jakarta.servlet.http.HttpServletRequest"}
_INPUTS = {
    "getParameter": 1,
    "getHeader": 1,
    "getQueryString": 0,
    "getPathInfo": 0,
    "getRequestURI": 0,
}
_METHODS = {"method_declaration", "constructor_declaration"}
_BOUNDARIES = _METHODS | {"lambda_expression", "class_body", "enum_body", "interface_body"}
_SCOPES = {
    "block",
    "constructor_body",
    "for_statement",
    "enhanced_for_statement",
    "try_with_resources_statement",
    "switch_block",
}
_SQL = re.compile(rb"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|WITH|MERGE|CALL)\b", re.I)
_MAX_NODES = 100_000
_MAX_EXPRESSION = 128


def _text(node: Node | None) -> str:
    if node is None or node.end_byte - node.start_byte > 256:
        return ""
    return (node.text or b"").decode(errors="replace")


def _operand(node: Node, field: str) -> str:
    return _text(node.child_by_field_name(field))


def _null_default(write: Node, name: str) -> bool:
    """A literal default on the null path preserves non-null input on the other path."""
    right = write.child_by_field_name("right")
    stmt = write.parent
    if (
        right is None
        or right.type != "string_literal"
        or _operand(write, "operator") != "="
        or stmt is None
        or stmt.type != "expression_statement"
    ):
        return False
    parent = stmt.parent
    if parent is not None and parent.type == "block" and parent.named_child_count == 1:
        stmt, parent = parent, parent.parent
    if (
        parent is None
        or parent.type != "if_statement"
        or parent.child_by_field_name("consequence") != stmt
        or parent.child_by_field_name("alternative") is not None
    ):
        return False
    test = parent.child_by_field_name("condition")
    if test is None or test.named_child_count != 1:
        return False
    check = test.named_child(0)
    return (
        check is not None
        and check.type == "binary_expression"
        and _operand(check, "operator") == "=="
        and {_operand(check, "left"), _operand(check, "right")} == {name, "null"}
    )


@dataclass(frozen=True)
class _Binding:
    declared: Node
    type_name: str
    value: Node | None
    scope: Node
    parameter: bool


@dataclass(frozen=True)
class _Value:
    sql: bool = False
    origins: frozenset[int] = frozenset()
    joined: bool = False


class _Method:
    def __init__(self, node: Node, types: dict[str, str]) -> None:
        self.bindings: dict[str, list[_Binding]] = defaultdict(list)
        self.changed: set[str] = set()
        self.calls: list[Node] = []
        self.limited = False
        pending = [(child, node) for child in node.named_children]
        steps = 0
        while pending:
            current, scope = pending.pop()
            steps += 1
            if steps > _MAX_NODES:
                self.limited = True
                return
            if current.type in _BOUNDARIES:
                continue
            if current.type in _SCOPES:
                scope = current
            if current.type in {"variable_declarator", "formal_parameter", "resource"}:
                owner = current.parent if current.type == "variable_declarator" else current
                if owner is not None:
                    name = _operand(current, "name")
                    spelling = _operand(owner, "type")
                    typ = "var" if spelling == "var" else types.get(spelling, "")
                    if owner.child_by_field_name("dimensions") or current.child_by_field_name(
                        "dimensions"
                    ):
                        typ = ""
                    self.bindings[name].append(
                        _Binding(
                            current,
                            typ,
                            current.child_by_field_name("value"),
                            scope,
                            current.type == "formal_parameter",
                        )
                    )
            elif current.type in {
                "catch_formal_parameter",
                "enhanced_for_statement",
                "type_pattern",
                "instanceof_expression",
            }:
                self.changed.add(_operand(current, "name"))
            elif current.type == "assignment_expression":
                name = _operand(current, "left")
                if not _null_default(current, name):
                    self.changed.add(name)
            elif current.type == "update_expression":
                self.changed.add(_text(current.named_child(0)))
            elif current.type == "method_invocation" and _operand(current, "name") in JDBC_METHODS:
                self.calls.append(current)
            pending.extend((child, scope) for child in current.named_children)

    def binding(self, ref: Node | None) -> _Binding | None:
        if ref is None or ref.type != "identifier":
            return None
        name = _text(ref)
        bindings = self.bindings.get(name)
        if not name or not bindings or len(bindings) != 1 or name in self.changed:
            return None
        binding = bindings[0]
        if (
            binding.declared.end_byte <= ref.start_byte
            and binding.scope.start_byte <= ref.start_byte < binding.scope.end_byte
        ):
            return binding
        return None

    def value(self, node: Node | None, budget: list[int]) -> _Value:
        budget[0] -= 1
        if budget[0] < 0 or node is None:
            return _Value()
        if node.type == "string_literal":
            return _Value(
                sql=node.end_byte - node.start_byte <= 4096 and bool(_SQL.search(node.text or b""))
            )
        if node.type == "identifier":
            binding = self.binding(node)
            if binding is None or binding.type_name != "java.lang.String":
                return _Value()
            if binding.parameter:
                return _Value(origins=frozenset({binding.declared.start_point[0] + 1}))
            return self.value(binding.value, budget)
        if node.type == "parenthesized_expression":
            return self.value(node.named_child(0), budget)
        if node.type == "binary_expression" and _operand(node, "operator") == "+":
            left = self.value(node.child_by_field_name("left"), budget)
            right = self.value(node.child_by_field_name("right"), budget)
            return _Value(left.sql or right.sql, left.origins | right.origins, True)
        if node.type == "method_invocation":
            binding = self.binding(node.child_by_field_name("object"))
            args = node.child_by_field_name("arguments")
            if (
                binding
                and binding.type_name in _REQUESTS
                and args is not None
                and _INPUTS.get(_operand(node, "name")) == args.named_child_count
            ):
                return _Value(origins=frozenset({node.start_point[0] + 1}))
        return _Value()

    def receiver_type(self, node: Node | None, depth: int = 0) -> str:
        if node is None or depth >= 6:
            return ""
        if node.type == "method_invocation":
            receiver = self.receiver_type(node.child_by_field_name("object"), depth + 1)
            name = _operand(node, "name")
            if receiver == "javax.sql.DataSource" and name == "getConnection":
                return "java.sql.Connection"
            if receiver == "java.sql.Connection" and name == "createStatement":
                return "java.sql.Statement"
        binding = self.binding(node)
        if binding:
            if binding.type_name == "var":
                return self.receiver_type(binding.value, depth + 1)
            return binding.type_name
        return ""

    def query(self, call: Node) -> QueryExpression | None:
        receiver = self.receiver_type(call.child_by_field_name("object"))
        expected = (
            "java.sql.Connection"
            if _operand(call, "name") in CONNECTION_METHODS
            else "java.sql.Statement"
        )
        args = call.child_by_field_name("arguments")
        if receiver != expected or args is None:
            return None
        first = next(
            (
                arg
                for arg in args.named_children
                if arg.type not in {"line_comment", "block_comment"}
            ),
            None,
        )
        if first is None:
            return None
        budget = [_MAX_EXPRESSION]
        value = self.value(first, budget)
        if budget[0] < 0:
            return QueryExpression(uncertainties=["expression_limit"])
        if value.sql and value.origins and value.joined:
            return QueryExpression(
                state="constructed",
                has_sql=True,
                selection="first_positional",
                constructions=["concatenation"],
                origin_lines=sorted(value.origins),
            )
        return None


def annotate(ast: FileAST, root: Node) -> None:
    sites = {
        (call.line, call.column, call.callee): call
        for call in ast.calls
        if call.callee in JDBC_METHODS
    }
    if not sites or root.has_error:
        return
    types = known_types(root, ast.imports)
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type in _METHODS:
            method = _Method(node, types)
            if method.limited:
                ast.query_expression_limit_count += 1
            else:
                for call in method.calls:
                    site = sites.get(
                        (call.start_point[0] + 1, call.start_point[1], _operand(call, "name"))
                    )
                    if site is not None:
                        site.query_expression = method.query(call)
                        if (
                            site.query_expression
                            and "expression_limit" in site.query_expression.uncertainties
                        ):
                            ast.query_expression_limit_count += 1
        pending.extend(node.named_children)
