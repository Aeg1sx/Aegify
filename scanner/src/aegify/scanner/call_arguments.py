"""Bounded call argument facts from parser nodes, without executing application code."""

from __future__ import annotations

import ast as python_ast
import re
from typing import Literal
from urllib.parse import unquote_plus

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


def _first_argument(args: Node | None) -> Node | None:
    if args is None:
        return None
    return next((child for child in args.named_children if child.type != "comment"), None)


def _fetch_url_text(node: Node | None, source: bytes, depth: int = 0) -> str:
    # An opaque expression can supply a query value but never a literal key or delimiter.
    unknown = "\x00"
    if node is None or depth >= 24 or node.end_byte - node.start_byte > 32_768:
        return unknown
    node = _unwrap(node)
    if node.type in {"string", "template_string"}:
        return "".join(
            _text(child, source) if child.type == "string_fragment" else unknown
            for child in node.named_children
        )
    if node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        if operator is not None and operator.type == "+":
            left = _fetch_url_text(node.child_by_field_name("left"), source, depth + 1)
            right = _fetch_url_text(node.child_by_field_name("right"), source, depth + 1)
            return left + right
    if node.type == "member_expression":
        field = node.child_by_field_name("property")
        obj = node.child_by_field_name("object")
        if obj is None or field is None:
            return unknown
        obj = _unwrap(obj)
        constructor = obj.child_by_field_name("constructor")
        if obj.type != "new_expression" or constructor is None:
            return unknown
        kind = _text(constructor, source).split(".")[-1]
        if (kind, _text(field, source)) not in {("URL", "href"), ("Request", "url")}:
            return unknown
        return _fetch_url_text(obj, source, depth + 1)
    if node.type == "new_expression":
        constructor = node.child_by_field_name("constructor")
        if constructor is not None and _text(constructor, source) in {
            "Request", "URL", "globalThis.Request", "globalThis.URL",
            "window.Request", "window.URL", "self.Request", "self.URL",
        }:
            first = _first_argument(node.child_by_field_name("arguments"))
            return _fetch_url_text(first, source, depth + 1)
    return unknown


def _fetch_query_keys(args: Node, source: bytes) -> list[str]:
    url = _fetch_url_text(_first_argument(args), source)
    query = url.partition("#")[0].partition("?")[2]
    keys = set()
    for field in query.split("&"):
        name, _, value = field.partition("=")
        if value and len(name) <= 192:
            decoded = unquote_plus(name)
            if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", decoded):
                keys.add(decoded.lower())
    return sorted(keys)


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
        if (
            ast.language in {Language.JAVASCRIPT, Language.TYPESCRIPT}
            and call.callee == "fetch"
            and call.receiver in {None, "globalThis", "window", "self"}
        ):
            call.fetch_query_keys = _fetch_query_keys(args, source)
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
