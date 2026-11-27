"""Lexical structure shared by JavaScript and TypeScript source analysis."""

from __future__ import annotations

from collections import defaultdict

from tree_sitter import Node

CALLABLES = {
    "function_declaration",
    "arrow_function",
    "function_expression",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
}


def single_return(function: Node) -> Node | None:
    body = function.child_by_field_name("body")
    if body is not None and body.type == "statement_block":
        statements = [child for child in body.named_children if child.type != "comment"]
        if len(statements) != 1 or statements[0].type != "return_statement":
            return None
        values = [child for child in statements[0].named_children if child.type != "comment"]
        body = values[0] if len(values) == 1 else None
    return body


def eager_text(node: Node, source: bytes) -> str:
    """Read an expression without attributing deferred function bodies to its caller."""
    chunks: list[bytes] = []
    offset = node.start_byte
    pending = [node]
    while pending:
        child = pending.pop()
        if child.type in CALLABLES:
            chunks.extend((source[offset : child.start_byte], b"void 0"))
            offset = child.end_byte
        else:
            pending.extend(reversed(child.named_children))
    chunks.append(source[offset : node.end_byte])
    return b"".join(chunks).decode("utf-8", errors="replace")


def _scope(node: Node, *, function_only: bool = False) -> Node:
    while node.parent is not None:
        if node.type in CALLABLES or (
            not function_only
            and node.type
            in {"statement_block", "catch_clause", "for_statement", "for_in_statement"}
        ):
            break
        node = node.parent
    return node


def dynamic_calls(root: Node, source: bytes) -> set[Node]:
    """Direct calls through a parameter, reassigned name or unknown local value."""
    bindings: dict[bytes, set[Node]] = defaultdict(set)
    calls = []
    pending = [root]
    while pending:
        node = pending.pop()
        pending.extend(node.named_children)
        name = None
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee and callee.type == "member_expression":
                callee = callee.child_by_field_name("object")
            if callee and callee.type == "identifier":
                calls.append((node, source[callee.start_byte : callee.end_byte]))
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is None or value.type not in CALLABLES:
                name = node.child_by_field_name("name")
        elif node.type in {"assignment_expression", "augmented_assignment_expression"}:
            name = node.child_by_field_name("left")
        elif node.type in CALLABLES:
            params = node.child_by_field_name("parameters")
            for param in params.named_children if params else []:
                ident = (
                    param.child_by_field_name("pattern")
                    or param.child_by_field_name("left")
                    or param
                )
                if ident.type == "identifier":
                    bindings[source[ident.start_byte : ident.end_byte]].add(node)
            name = node.child_by_field_name("parameter")
        elif node.type == "catch_clause":
            name = node.child_by_field_name("parameter")
        if name is not None and name.type == "identifier":
            is_var = node.parent is not None and node.parent.type == "variable_declaration"
            bindings[source[name.start_byte : name.end_byte]].add(
                _scope(node, function_only=is_var)
            )

    dynamic = set()
    for call, name_text in calls:
        if name_text not in bindings:
            continue
        scope: Node | None = call
        while scope is not None:
            if scope in bindings[name_text]:
                dynamic.add(call)
                break
            scope = scope.parent
    return dynamic
