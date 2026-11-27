"""Identify calls that use JavaScript's global RegExp pattern operand."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator

from tree_sitter import Node

from aegify.scanner.javascript_functions import single_return

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


def _covers_syntax(literal: Node) -> bool:
    """Verify a single global ASCII character class without compiling source regexes."""
    pattern = literal.child_by_field_name("pattern")
    flags = literal.child_by_field_name("flags")
    if pattern is None or flags is None or flags.text not in {b"g", b"gu", b"ug"}:
        return False
    text = pattern.text or b""
    if text.startswith(b"(") and text.endswith(b")"):
        text = text[1:-1]
    if not (3 <= len(text) <= 256 and text.startswith(b"[") and text.endswith(b"]")):
        return False
    if text[1:2] == b"^":
        return False
    # Hex ranges are common in encoders which escape every ASCII character.
    syntax = set(rb"\^$.*+?()[]{}|")
    if limits := re.fullmatch(rb"\[\\x([0-9A-Fa-f]{2})-\\x([0-9A-Fa-f]{2})\]", text):
        return int(limits[1], 16) <= min(syntax) and max(syntax) <= int(limits[2], 16)
    body = text[1:-1]
    seen: set[int] = set()
    i = 0
    while i < len(body):
        char = body[i]
        if char == ord("\\"):
            i += 1
            if i == len(body) or body[i] not in syntax | {ord("/"), ord("-")}:
                return False
            char = body[i]
        elif char in b"[]-":
            return False
        seen.add(char)
        i += 1
    return syntax <= seen


def escaping_replacement(value: Node | None) -> bool:
    """Recognize a replacement that warrants checking the resulting pattern."""
    if value is None or value.type != "call_expression":
        return False
    method = value.child_by_field_name("function")
    if method is None or not _member(method, b"replace"):
        return False
    args = _arguments(value)
    if len(args) != 2 or args[0].type != "regex" or not _covers_syntax(args[0]):
        return False
    replacement = args[1]
    if replacement.type == "string":
        return (replacement.text or b"")[1:-1] == rb"\\$&"
    if replacement.type not in {"function_expression", "arrow_function"}:
        return False
    result = single_return(replacement)
    if result is None or result.type != "binary_expression":
        return False
    left = result.child_by_field_name("left")
    op = result.child_by_field_name("operator")
    right = result.child_by_field_name("right")
    params = replacement.child_by_field_name("parameters")
    identifiers = (
        params.named_children if params else [replacement.child_by_field_name("parameter")]
    )
    if not (
        left
        and left.type == "string"
        and right
        and op
        and op.text == b"+"
        and len(identifiers) == 1
        and (param := identifiers[0])
        and param.type == "identifier"
    ):
        return False
    prefix = (left.text or b"")[1:-1]
    if prefix == rb"\\":
        return right.type == "identifier" and right.text == param.text
    if prefix not in {rb"\\x", rb"\\u"} or right.end_byte - right.start_byte > 256:
        return False
    # Only the matched character may supply the hex digits. Accept fixed-width
    # padding before slicing, or a hexadecimal string padded to the required width.
    width = b"2" if prefix == rb"\\x" else b"4"
    zeros = b"0" * int(width)
    number = (
        re.escape(param.text or b"")
        + rb"\s*\.\s*charCodeAt\s*\(\s*0?\s*\)\s*\.\s*toString\s*\(\s*16\s*\)"
    )
    padded = number + rb"""\s*\.\s*padStart\s*\(\s*""" + width + rb"""\s*,\s*(['"])0\1\s*\)"""
    sliced = (
        rb"""\(\s*(['"])"""
        + zeros
        + rb"""\1\s*\+\s*"""
        + number
        + rb"\s*\)\s*\.\s*(?:slice|substr)\s*\(\s*-\s*"
        + width
        + rb"\s*\)"
    )
    expression = right.text or b""
    return (
        re.fullmatch(padded, expression) is not None or re.fullmatch(sliced, expression) is not None
    )


def rewritten_operand(call: Node) -> bool:
    operands = _arguments(call)
    if not operands:
        return False
    pattern = operands[0]
    if escaping_replacement(pattern):
        return True
    if pattern.type != "identifier":
        return False
    # Only follow a direct use immediately after a single initializer. Intervening
    # statements, mixed expressions and mutable aliases retain their usual policy.
    statement = call.parent
    if statement is None or statement.type not in {"expression_statement", "return_statement"}:
        return False
    previous = statement.prev_named_sibling
    if previous is None or previous.type not in {"variable_declaration", "lexical_declaration"}:
        return False
    declarations = [n for n in previous.named_children if n.type != "comment"]
    if len(declarations) != 1:
        return False
    name = declarations[0].child_by_field_name("name")
    return (
        name is not None
        and name.text == pattern.text
        and escaping_replacement(declarations[0].child_by_field_name("value"))
    )
