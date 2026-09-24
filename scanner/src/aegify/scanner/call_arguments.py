"""Literal boolean option facts from parser nodes, never application execution."""

from __future__ import annotations

import ast as python_ast
from typing import Literal

from tree_sitter import Node

from aegify.models import BooleanOption, CallArgument, FileAST, Language

SUPPORTED = {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT, Language.GO}
MAX_ITEMS = 128
MAX_DEPTH = 8


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _unwrap(node: Node) -> Node:
    for _ in range(MAX_DEPTH):
        if (
            node.type in {"parenthesized_expression", "literal_element"}
            and len(node.named_children) == 1
        ):
            node = node.named_children[0]
        elif (
            node.type in {"as_expression", "satisfies_expression", "non_null_expression"}
            and node.named_children
        ):
            node = node.named_children[0]
        else:
            break
    return node


def _boolean(node: Node | None) -> Literal["true", "false", "unknown"]:
    if node is not None:
        node = _unwrap(node)
        if node.type in {"true", "false"}:
            return "true" if node.type == "true" else "false"
    return "unknown"


def _key(node: Node | None, source: bytes, language: Language) -> str | None:
    if node is None or node.end_byte - node.start_byte > 256:
        return None
    node = _unwrap(node)
    if node.type == "computed_property_name" and len(node.named_children) == 1:
        node = node.named_children[0]
    elif language != Language.PYTHON and node.type in {
        "property_identifier",
        "identifier",
        "field_identifier",
    }:
        return _text(node, source)
    if node.type not in {"string", "interpreted_string_literal"}:
        return None
    try:
        # Literal strings only. Interpolation, bytes and non-string expressions
        # remain unknown; literal_eval cannot invoke application code.
        value = python_ast.literal_eval(_text(node, source))
    except ValueError, SyntaxError, TypeError, MemoryError, RecursionError:
        return None
    return value if isinstance(value, str) else None


def _options(
    node: Node, source: bytes, language: Language, depth: int = 0
) -> list[BooleanOption] | None:
    node = _unwrap(node)
    if (
        language == Language.GO
        and node.type == "unary_expression"
        and _text(node, source).startswith("&")
    ):
        operand = node.child_by_field_name("operand")
        if operand is not None:
            node = operand
    if node.type == "composite_literal":
        body = node.child_by_field_name("body")
        if body is None:
            return None
        node = body
    if node.type not in {"object", "dictionary", "literal_value"}:
        return None
    if depth >= MAX_DEPTH or node.has_error:
        return [BooleanOption()]
    options: list[BooleanOption] = []
    for child in node.named_children:
        if child.type == "comment":
            continue
        if len(options) >= MAX_ITEMS:
            options.append(BooleanOption())
            break
        if child.type in {"pair", "keyed_element"}:
            key = _key(child.child_by_field_name("key"), source, language)
            options.append(
                BooleanOption(name=key, state=_boolean(child.child_by_field_name("value")))
            )
        elif child.type in {"spread_element", "dictionary_splat"}:
            nested = (
                _options(child.named_children[0], source, language, depth + 1)
                if child.named_children
                else None
            )
            options.extend(nested if nested is not None else [BooleanOption()])
        elif child.type == "shorthand_property_identifier":
            options.append(BooleanOption(name=_text(child, source)))
        elif child.type in {"method_definition", "method_declaration"}:
            options.append(
                BooleanOption(name=_key(child.child_by_field_name("name"), source, language))
            )
        else:
            options.append(BooleanOption())
    if len(options) > MAX_ITEMS:
        options = [*options[:MAX_ITEMS], BooleanOption()]
    return options


def annotate_call_arguments(ast: FileAST, root: Node, source: bytes) -> None:
    if ast.language not in SUPPORTED:
        return
    calls = {(call.line, call.column): call for call in ast.calls}
    pending = [root]
    while pending:
        node = pending.pop()
        pending.extend(reversed(node.named_children))
        call = calls.get((node.start_point[0] + 1, node.start_point[1]))
        if call is None or node.type not in {"call", "call_expression"}:
            continue
        args = node.child_by_field_name("arguments")
        if args is None or args.has_error:
            continue
        facts: list[CallArgument] = []
        for child in args.named_children:
            if child.type == "comment":
                continue
            if len(facts) >= MAX_ITEMS:
                facts.append(CallArgument(kind="unknown"))
                break
            if child.type == "keyword_argument":
                name = child.child_by_field_name("name")
                facts.append(
                    CallArgument(
                        kind="keyword",
                        name=_text(name, source) if name else "",
                        state=_boolean(child.child_by_field_name("value")),
                    )
                )
            elif child.type in {
                "dictionary_splat",
                "list_splat",
                "spread_element",
                "variadic_argument",
            }:
                kind: Literal["keyword_spread", "spread"] = (
                    "keyword_spread" if child.type == "dictionary_splat" else "spread"
                )
                value = child.named_children[0] if child.named_children else None
                facts.append(
                    CallArgument(
                        kind=kind, options=_options(value, source, ast.language) if value else None
                    )
                )
            else:
                facts.append(
                    CallArgument(
                        kind="positional",
                        state=_boolean(child),
                        options=_options(child, source, ast.language),
                    )
                )
        call.structured_arguments = facts
