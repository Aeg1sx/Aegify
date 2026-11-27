"""Identify calls that use JavaScript's global RegExp pattern operand."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from tree_sitter import Node

_FUNCTIONS = {
    "arrow_function",
    "function_declaration",
    "function_expression",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
}


def _walk(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _scope(node: Node) -> Node:
    while node.parent is not None and node.type not in _FUNCTIONS:
        node = node.parent
    return node


def _member(node: Node, field: bytes) -> bool:
    if node.type != "member_expression":
        return False
    prop = node.child_by_field_name("property")
    return prop is not None and prop.text == field


def _arguments(call: Node) -> list[Node]:
    args = call.child_by_field_name("arguments")
    return [n for n in args.named_children if n.type != "comment"] if args else []


def _callee(call: Node) -> Node | None:
    if call.type == "new_expression":
        return call.child_by_field_name("constructor")
    if call.type == "call_expression":
        return call.child_by_field_name("function")
    return None


def pattern_calls(root: Node, source: bytes) -> set[Node]:
    if b"RegExp" not in source:
        return set()
    calls = {}
    escapes = {}
    escape_replaced = False
    hidden: dict[bytes, set[Node]] = defaultdict(set)
    for name in _walk(root):
        if name.type not in {
            "identifier",
            "type_identifier",
            "shorthand_property_identifier_pattern",
        }:
            continue
        binding = name.text
        if binding not in {b"RegExp", b"globalThis"} or name.parent is None:
            continue
        ref, parent = name, name.parent
        if name.type == "type_identifier" and not (
            parent.type in {"class_declaration", "abstract_class_declaration"}
            and parent.child_by_field_name("name") == name
        ):
            continue
        if binding == b"globalThis" and _member(parent, b"RegExp"):
            ref = parent
            if ref.parent is None:
                continue
            parent = ref.parent
        elif binding == b"globalThis" and parent.type == "member_expression":
            continue
        if (binding == b"RegExp" or ref != name) and _callee(parent) == ref:
            calls[parent] = binding
        elif _member(parent, b"escape") and parent.child_by_field_name("object") == ref:
            use = parent.parent
            if use is not None and use.type == "call_expression" and _callee(use) == parent:
                escapes[use] = binding
            else:
                escape_replaced = True
        elif ref != name:
            # Exposing or replacing the global constructor can affect other functions.
            hidden[b"RegExp"].add(root)
            hidden[b"globalThis"].add(root)
        elif parent.type != "member_expression":
            owner = (
                parent.parent
                if parent.type in _FUNCTIONS and parent.child_by_field_name("name") == name
                else parent
            )
            hidden[binding].add(_scope(owner or parent))

    def visible(call: Node, binding: bytes) -> bool:
        cursor: Node | None = call
        while cursor is not None:
            if cursor in hidden[binding]:
                return False
            cursor = cursor.parent
        return True

    result = set()
    for call, binding in calls.items():
        args = _arguments(call)
        if not args or not visible(call, binding):
            continue
        pattern = args[0]
        if pattern.type in {"spread_element", "regex", "string", "number", "null"}:
            continue
        if pattern.type == "template_string" and not any(
            n.type == "template_substitution" for n in pattern.named_children
        ):
            continue
        if not escape_replaced and pattern in escapes and visible(pattern, escapes[pattern]):
            operands = _arguments(pattern)
            if len(operands) == 1 and operands[0].type != "spread_element":
                continue
        result.add(call)
    return result
