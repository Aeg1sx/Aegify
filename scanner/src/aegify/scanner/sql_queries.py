"""Bounded SQL-text expression facts. Parse source only; never execute it.

This analysis distinguishes query text from bound values and propagates immutable
local string values. Unknown receivers and inputs remain static review candidates,
not proof of injection, sanitization, or runtime reachability.
"""

from __future__ import annotations

import ast as python_ast
import re
import string
from dataclasses import dataclass, field, replace

from tree_sitter import Node

from aegify.models import CallSite, FileAST, Language, QueryExpression

SUPPORTED = {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT}
QUERY_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "execute_async",
        "executesql",
        "query",
        "raw",
        "exec",
        "prepare",
        "$queryrawunsafe",
        "$executerawunsafe",
    }
)
MAX_TEXT = 4096
MAX_DEPTH = 48
MAX_STEPS = 100_000
MAX_FIELDS = 64
MAX_ORIGINS = 16
MAX_MERGE_STEPS = 1024
_SQL = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|WITH|REPLACE|PRAGMA)\b", re.I
)
_FUNCTIONS = {
    "function_definition",
    "function_declaration",
    "function_expression",
    "generator_function",
    "generator_function_declaration",
    "arrow_function",
    "lambda",
    "method_definition",
}
_BLOCKS = {"module", "program", "block", "statement_block"}
_WRAPPERS = {
    "parenthesized_expression",
    "as_expression",
    "satisfies_expression",
    "non_null_expression",
    "await_expression",
}


@dataclass(frozen=True)
class _Value:
    text: str = "\0"
    constant: bool = False
    constructed: bool = False
    sql_constructed: bool = False
    constructions: frozenset[str] = frozenset()
    origins: frozenset[int] = frozenset()
    uncertainties: frozenset[str] = frozenset()
    fields: dict[str, _Value] | None = field(default=None, compare=True)
    object_ids: frozenset[int] = frozenset()


_Env = dict[str, _Value]


def _merge(left: _Value, right: _Value, depth: int = 0, budget: list[int] | None = None) -> _Value:
    if left is right or (left.fields is None and right.fields is None and left == right):
        return left
    if budget is None:
        budget = [MAX_MERGE_STEPS]
    budget[0] -= 1
    if depth >= MAX_DEPTH or budget[0] < 0:
        return _Value(uncertainties=frozenset({"expression_limit"}))
    fields = None
    limited = False
    if left.fields is not None and right.fields is not None:
        names = sorted(left.fields.keys() | right.fields.keys())
        limited = len(names) > MAX_FIELDS
        fields = {
            name: _merge(
                left.fields.get(name, _Value()), right.fields.get(name, _Value()), depth + 1, budget
            )
            for name in names[:MAX_FIELDS]
        }
        limited |= any("expression_limit" in value.uncertainties for value in fields.values())
    text = left.text + "\0" + right.text
    object_ids = left.object_ids | right.object_ids
    limited |= len(text) > MAX_TEXT or len(object_ids) > MAX_FIELDS
    return _Value(
        text=text[:MAX_TEXT],
        constant=left.constant and right.constant and not limited,
        constructed=left.constructed or right.constructed,
        sql_constructed=left.sql_constructed or right.sql_constructed,
        constructions=left.constructions | right.constructions,
        origins=frozenset(sorted(left.origins | right.origins)[:MAX_ORIGINS]),
        uncertainties=left.uncertainties
        | right.uncertainties
        | ({"expression_limit"} if limited else set()),
        fields=fields,
        object_ids=frozenset(sorted(object_ids)[:MAX_FIELDS]),
    )


def _join_env(left: _Env, right: _Env) -> _Env:
    return {
        name: _merge(left.get(name, _Value()), right.get(name, _Value()))
        for name in left.keys() | right.keys()
    }


def _combine(left: _Value, right: _Value, operation: str) -> _Value:
    constant = left.constant and right.constant
    text = left.text + right.text
    limited = len(text) > MAX_TEXT
    return _Value(
        text=text[:MAX_TEXT],
        constant=constant and not limited,
        constructed=left.constructed or right.constructed or not constant,
        sql_constructed=left.sql_constructed
        or right.sql_constructed
        or (not constant and bool(_SQL.search(text))),
        constructions=left.constructions
        | right.constructions
        | ({operation} if not constant else set()),
        origins=frozenset(sorted(left.origins | right.origins)[:MAX_ORIGINS]),
        uncertainties=left.uncertainties
        | right.uncertainties
        | ({"expression_limit"} if limited else set()),
    )


def _decode_js(text: str) -> str | None:
    """Decode string/template escapes without eval or a JavaScript runtime."""
    output: list[str] = []
    index = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            output.append(char)
            continue
        if index >= len(text):
            return None
        char = text[index]
        index += 1
        if char in "\r\n":
            if char == "\r" and index < len(text) and text[index] == "\n":
                index += 1
            continue
        if char in {"u", "x"}:
            if char == "u" and index < len(text) and text[index] == "{":
                end = text.find("}", index + 1, index + 9)
                if end == -1:
                    return None
                digits = text[index + 1 : end]
                index = end + 1
            else:
                length = 4 if char == "u" else 2
                digits = text[index : index + length]
                index += length
                if len(digits) != length:
                    return None
            if not re.fullmatch(r"[0-9a-fA-F]{1,6}", digits):
                return None
            number = int(digits, 16)
            if number > 0x10FFFF:
                return None
            output.append(chr(number))
        elif char.isdigit() and (char != "0" or (index < len(text) and text[index].isdigit())):
            return None  # Legacy octal escapes are outside this contract.
        else:
            output.append(escapes.get(char, char))
    return "".join(output)


class _Analyzer:
    def __init__(self, ast: FileAST, source: bytes) -> None:
        self.ast = ast
        self.source = source
        self.steps = 0
        self.limited = False
        self.calls: dict[tuple[int, int], list[CallSite]] = {}
        for call in ast.calls:
            self.calls.setdefault((call.line, call.column), []).append(call)

    def text(self, node: Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def guard(self, node: Node, depth: int) -> bool:
        self.steps += 1
        if depth > MAX_DEPTH or self.steps > MAX_STEPS:
            self.limited = True
            return False
        return not node.is_error and not node.is_missing

    def key(self, node: Node | None, *, identifier: bool = True) -> str | None:
        if node is None or node.end_byte - node.start_byte > 256:
            return None
        if node.type == "computed_property_name" and len(node.named_children) == 1:
            node = node.named_children[0]
            identifier = False
        if identifier and node.type in {"identifier", "property_identifier"}:
            return self.text(node)
        if node.type not in {"string", "template_string"}:
            return None
        value = self.literal(node)
        return value.text if value.constant else None

    def literal(self, node: Node) -> _Value:
        if node.end_byte - node.start_byte > MAX_TEXT:
            return _Value(uncertainties=frozenset({"expression_limit"}))
        text = self.text(node)
        try:
            value = (
                python_ast.literal_eval(text)
                if self.ast.language == Language.PYTHON
                else _decode_js(text[1:-1])
            )
        except ValueError, SyntaxError, TypeError, MemoryError, RecursionError:
            if self.ast.language == Language.PYTHON:
                try:
                    expression = python_ast.parse(text, mode="eval").body
                    if isinstance(expression, python_ast.JoinedStr) and all(
                        isinstance(item, python_ast.Constant) and isinstance(item.value, str)
                        for item in expression.values
                    ):
                        fixed = "".join(
                            str(item.value)
                            for item in expression.values
                            if isinstance(item, python_ast.Constant)
                        )
                        return _Value(text=fixed, constant=True)
                except ValueError, SyntaxError, TypeError, MemoryError, RecursionError:
                    pass
            return _Value(uncertainties=frozenset({"unsupported_literal"}))
        return _Value(text=value, constant=True) if isinstance(value, str) else _Value()

    def truth(self, node: Node | None) -> bool | None:
        for _ in range(8):
            if node is not None and node.type in _WRAPPERS and node.named_children:
                node = node.named_children[0]
            else:
                break
        if node is not None and node.type in {"true", "false"}:
            return node.type == "true"
        return None

    def assign(self, target: Node | None, value: _Value, env: _Env) -> None:
        if target is None:
            return
        value = replace(
            value,
            origins=frozenset(sorted(value.origins | {target.start_point[0] + 1})[:MAX_ORIGINS]),
        )
        if target.type == "identifier":
            env[self.text(target)] = value
        elif target.type in {"member_expression", "attribute", "subscript_expression", "subscript"}:
            owner = target.child_by_field_name("object") or target.child_by_field_name("value")
            prop = (
                target.child_by_field_name("property")
                or target.child_by_field_name("attribute")
                or target.child_by_field_name("index")
                or target.child_by_field_name("subscript")
            )
            if owner is not None and owner.type == "identifier":
                old = env.get(self.text(owner), _Value())
                name = self.key(prop, identifier=target.type in {"member_expression", "attribute"})
                if old.fields is not None:
                    fields = dict(old.fields)
                    if name is None:
                        fields = {
                            key: _merge(
                                item, _Value(uncertainties=frozenset({"computed_property"}))
                            )
                            for key, item in fields.items()
                        }
                    else:
                        fields[name] = value
                    updated = replace(
                        old,
                        fields=dict(list(fields.items())[:MAX_FIELDS]),
                        constant=False,
                        uncertainties=old.uncertainties
                        | ({"expression_limit"} if len(fields) > MAX_FIELDS else set()),
                    )
                    for alias, item in list(env.items()):
                        if item.object_ids & old.object_ids:
                            env[alias] = (
                                updated
                                if item.object_ids == old.object_ids
                                else _merge(item, updated)
                            )
        else:
            # Destructuring may shadow an earlier known local value.
            pending = [target]
            while pending:
                child = pending.pop()
                if child.type in {"identifier", "shorthand_property_identifier_pattern"}:
                    env[self.text(child)] = _Value(uncertainties=frozenset({"destructuring"}))
                else:
                    pending.extend(child.named_children)

    def walk(self, node: Node, env: _Env, depth: int = 0) -> None:
        if not self.guard(node, depth):
            return
        kind = node.type
        if kind in _FUNCTIONS:
            local: _Env = {}
            for child in node.named_children:
                if child.type not in {"identifier", "type_identifier", "type_annotation"}:
                    self.walk(child, local, depth + 1)
            return
        if kind in {"class_definition", "class_declaration", "class_body"}:
            for child in node.named_children:
                self.walk(child, {}, depth + 1)
            return
        if kind in _BLOCKS:
            shadowed: dict[str, _Value | None] = {}
            if self.ast.language != Language.PYTHON:
                for child in node.named_children:
                    if child.type == "lexical_declaration":
                        for declaration in child.named_children:
                            binding_node = declaration.child_by_field_name("name")
                            if binding_node is not None and binding_node.type == "identifier":
                                shadowed[self.text(binding_node)] = env.get(self.text(binding_node))
                                env[self.text(binding_node)] = _Value()
            for child in node.named_children:
                self.walk(child, env, depth + 1)
            for scope_name, old_value in shadowed.items():
                if old_value is None:
                    env.pop(scope_name, None)
                else:
                    env[scope_name] = old_value
            return
        if kind == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition is not None:
                self.expr(condition, env, depth + 1)
            outcomes: list[_Env] = []
            consequence = node.child_by_field_name("consequence")
            truth = self.truth(condition)
            if consequence is not None and truth is not False:
                branch = dict(env)
                self.walk(consequence, branch, depth + 1)
                outcomes.append(branch)
            fallthrough = truth is not True
            alternatives = [
                child
                for child in node.named_children
                if child.type in {"elif_clause", "else_clause"}
            ]
            if not alternatives:
                alternative = node.child_by_field_name("alternative")
                alternatives = [alternative] if alternative is not None else []
            for alternative in alternatives:
                if not fallthrough:
                    break
                branch = dict(env)
                if alternative.type == "elif_clause":
                    condition = alternative.child_by_field_name("condition")
                    if condition is not None:
                        self.expr(condition, branch, depth + 1)
                    truth = self.truth(condition)
                    consequence = alternative.child_by_field_name("consequence")
                    if consequence is not None and truth is not False:
                        self.walk(consequence, branch, depth + 1)
                        outcomes.append(branch)
                    fallthrough = truth is not True
                else:
                    self.walk(alternative, branch, depth + 1)
                    outcomes.append(branch)
                    fallthrough = False
            if fallthrough or not outcomes:
                outcomes.append(dict(env))
            joined = outcomes[0]
            for branch in outcomes[1:]:
                joined = _join_env(joined, branch)
            env.clear()
            env.update(joined)
            return
        if kind == "try_statement":
            before_try = dict(env)
            success = dict(env)
            body = node.child_by_field_name("body")
            if body is not None:
                self.walk(body, success, depth + 1)
            exceptional = _join_env(before_try, success)
            successful_else = dict(success)
            handlers: list[_Env] = []
            finalizer: Node | None = None
            for child in node.named_children:
                if child.type in {"except_clause", "catch_clause"}:
                    handled = dict(exceptional)
                    self.walk(child, handled, depth + 1)
                    handlers.append(handled)
                elif child.type == "else_clause":
                    self.walk(child, successful_else, depth + 1)
                elif child.type == "finally_clause":
                    finalizer = child
            merged_try = successful_else
            for handled in handlers:
                merged_try = _join_env(merged_try, handled)
            if finalizer is not None:
                self.walk(finalizer, merged_try, depth + 1)
            env.clear()
            env.update(merged_try)
            return
        if kind in {"switch_statement", "match_statement"}:
            subject = node.child_by_field_name("value") or node.child_by_field_name("subject")
            if subject is not None:
                self.expr(subject, env, depth + 1)
            before = dict(env)
            joined = dict(env)
            carried = dict(env)
            body = node.child_by_field_name("body")
            for case in body.named_children if body is not None else []:
                if case.type not in {"switch_case", "switch_default", "case_clause"}:
                    continue
                # Include direct entry and possible JS fallthrough. Do not infer
                # that the final case overwrites every earlier branch.
                branch = _join_env(before, carried) if kind == "switch_statement" else dict(before)
                if kind == "match_statement":
                    for pattern in case.named_children:
                        if pattern.type == "case_pattern":
                            self.assign(pattern, _Value(), branch)
                for child in case.named_children:
                    self.walk(child, branch, depth + 1)
                joined = _join_env(joined, branch)
                carried = (
                    dict(before)
                    if any(child.type == "break_statement" for child in case.named_children)
                    else branch
                )
            env.clear()
            env.update(joined)
            return
        if kind in {
            "for_statement",
            "for_in_statement",
            "while_statement",
            "do_statement",
        }:
            before = dict(env)
            changed = dict(env)
            target = node.child_by_field_name("left")
            lexical_target = (
                self.text(target)
                if target is not None
                and target.type == "identifier"
                and self.ast.language != Language.PYTHON
                and any(child.type in {"let", "const"} for child in node.children)
                else None
            )
            if target is not None:
                self.assign(target, _Value(), changed)
            for child in node.named_children:
                self.walk(child, changed, depth + 1)
            joined = _join_env(before, changed)
            if kind in {"for_statement", "for_in_statement", "while_statement", "do_statement"}:
                # One bounded loop-carried pass; never assume a loop executes.
                repeated = dict(joined)
                body = node.child_by_field_name("body")
                if body is not None:
                    self.walk(body, repeated, depth + 1)
                joined = _join_env(joined, repeated)
            env.clear()
            env.update(joined)
            if lexical_target is not None:
                if lexical_target in before:
                    env[lexical_target] = before[lexical_target]
                else:
                    env.pop(lexical_target, None)
            return
        if kind in {
            "lexical_declaration",
            "variable_declaration",
            "expression_statement",
            "else_clause",
            "elif_clause",
            "except_clause",
            "finally_clause",
            "return_statement",
        }:
            for child in node.named_children:
                self.walk(child, env, depth + 1)
            return
        self.expr(node, env, depth + 1)

    def expr(self, node: Node, env: _Env, depth: int = 0) -> _Value:
        if not self.guard(node, depth):
            return _Value(
                uncertainties=frozenset({"expression_limit" if self.limited else "parse_recovery"})
            )
        kind = node.type
        if kind in _FUNCTIONS:
            self.walk(node, {}, depth + 1)
            return _Value()
        if kind in _WRAPPERS and node.named_children:
            return self.expr(node.named_children[0], env, depth + 1)
        if kind in {
            "assignment",
            "assignment_expression",
            "variable_declarator",
            "named_expression",
        }:
            target = node.child_by_field_name("left") or node.child_by_field_name("name")
            right = node.child_by_field_name("right") or node.child_by_field_name("value")
            value = self.expr(right, env, depth + 1) if right is not None else _Value()
            self.assign(target, value, env)
            return value
        if kind in {"augmented_assignment", "augmented_assignment_expression"}:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            operator = node.child_by_field_name("operator")
            first = self.expr(left, env, depth + 1) if left is not None else _Value()
            second = self.expr(right, env, depth + 1) if right is not None else _Value()
            value = (
                _combine(first, second, "concatenation")
                if operator is not None and self.text(operator) == "+="
                else _Value()
            )
            self.assign(left, value, env)
            return value
        if kind == "identifier":
            return env.get(self.text(node), _Value())
        if kind in {"integer", "float", "number", "true", "false", "none", "null"}:
            return _Value(text="", constant=True)
        if kind in {"string", "template_string"}:
            interpolations = [
                child
                for child in node.named_children
                if child.type in {"interpolation", "template_substitution"}
            ]
            if not interpolations:
                return self.literal(node)
            result = _Value(text="", constant=True)
            for child in node.named_children:
                if child.type in {"string_start", "string_end"}:
                    continue
                if child.type in {"interpolation", "template_substitution"}:
                    expression = child.child_by_field_name("expression") or next(
                        iter(child.named_children), None
                    )
                    value = (
                        self.expr(expression, env, depth + 1)
                        if expression is not None
                        else _Value()
                    )
                    for part in child.named_children:
                        if part.type == "format_specifier":
                            for nested in part.named_children:
                                value = _combine(
                                    value, self.expr(nested, env, depth + 1), "interpolation"
                                )
                    result = _combine(result, value, "interpolation")
                else:
                    text = self.text(child)
                    decoded = _decode_js(text) if self.ast.language != Language.PYTHON else text
                    result = _combine(
                        result,
                        _Value(text=decoded or "", constant=decoded is not None),
                        "interpolation",
                    )
            return result
        if kind == "concatenated_string":
            result = _Value(text="", constant=True)
            for child in node.named_children:
                result = _combine(result, self.expr(child, env, depth + 1), "concatenation")
            return result
        if kind in {"binary_operator", "binary_expression"}:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            operator = node.child_by_field_name("operator")
            first = self.expr(left, env, depth + 1) if left is not None else _Value()
            second = self.expr(right, env, depth + 1) if right is not None else _Value()
            operation = self.text(operator) if operator is not None else ""
            if operation == "+":
                return _combine(first, second, "concatenation")
            if operation == "%" and self.ast.language == Language.PYTHON:
                holes = re.search(
                    r"%(?:\([^)]{1,128}\))?[#0 +\-]*(?:[0-9]+|\*)?(?:\.[0-9]+)?[diouxXeEfFgGcrsa]",
                    first.text.replace("%%", ""),
                )
                return _combine(first, second, "percent_format") if holes else first
            return _Value(text="", constant=first.constant and second.constant)
        if kind in {"conditional_expression", "ternary_expression"}:
            parts = [child for child in node.named_children if child.type != "comment"]
            if len(parts) != 3:
                return _Value(uncertainties=frozenset({"conditional_shape"}))
            yes, condition, no = (
                parts if kind == "conditional_expression" else [parts[1], parts[0], parts[2]]
            )
            self.expr(condition, env, depth + 1)
            truth = self.truth(condition)
            if truth is not None:
                return self.expr(yes if truth else no, env, depth + 1)
            positive, negative = dict(env), dict(env)
            first = self.expr(yes, positive, depth + 1)
            second = self.expr(no, negative, depth + 1)
            env.clear()
            env.update(_join_env(positive, negative))
            return _merge(first, second)
        if kind in {"object", "dictionary"}:
            fields: dict[str, _Value] = {}
            uncertain: set[str] = set()
            for index, child in enumerate(node.named_children):
                if index >= MAX_FIELDS:
                    uncertain.add("expression_limit")
                    break
                if child.type == "comment":
                    continue
                if child.type in {"pair", "key_value_pair"}:
                    name = self.key(
                        child.child_by_field_name("key"),
                        identifier=self.ast.language != Language.PYTHON,
                    )
                    property_value = child.child_by_field_name("value")
                    value = (
                        self.expr(property_value, env, depth + 1)
                        if property_value is not None
                        else _Value()
                    )
                    if name is not None:
                        fields[name] = value
                        continue
                elif child.type == "shorthand_property_identifier":
                    name = self.text(child)
                    fields[name] = env.get(name, _Value())
                    continue
                elif child.type in {"spread_element", "dictionary_splat"} and child.named_children:
                    value = self.expr(child.named_children[0], env, depth + 1)
                    if value.fields is not None:
                        fields.update(value.fields)
                        uncertain.update(value.uncertainties)
                        if len(fields) > MAX_FIELDS:
                            fields = dict(list(fields.items())[:MAX_FIELDS])
                            uncertain.add("expression_limit")
                        continue
                uncertain.add("unknown_property_effect")
                fields = {
                    key: _merge(value, _Value(uncertainties=frozenset({"unknown_property_effect"})))
                    for key, value in fields.items()
                }
            return _Value(
                text="",
                constant=not uncertain and all(value.constant for value in fields.values()),
                fields=fields,
                uncertainties=frozenset(uncertain),
                object_ids=frozenset({node.start_byte}),
            )
        if kind in {"member_expression", "attribute", "subscript_expression", "subscript"}:
            owner = node.child_by_field_name("object") or node.child_by_field_name("value")
            prop = (
                node.child_by_field_name("property")
                or node.child_by_field_name("attribute")
                or node.child_by_field_name("index")
                or node.child_by_field_name("subscript")
            )
            value = self.expr(owner, env, depth + 1) if owner is not None else _Value()
            name = self.key(prop, identifier=kind in {"member_expression", "attribute"})
            return (
                value.fields.get(name, _Value())
                if value.fields is not None and name is not None
                else _Value()
            )
        if kind in {"call", "call_expression"}:
            return self.call(node, env, depth + 1)
        if kind in {"array", "tuple", "list", "set"}:
            values = [self.expr(child, env, depth + 1) for child in node.named_children]
            return _Value(text="", constant=all(value.constant for value in values))
        for child in node.named_children:
            self.walk(child, env, depth + 1)
        return _Value()

    def call(self, node: Node, env: _Env, depth: int) -> _Value:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None:
            return _Value()
        name = self.text(function)
        receiver: Node | None = None
        if function.type in {"member_expression", "attribute"}:
            receiver = function.child_by_field_name("object")
            prop = function.child_by_field_name("property") or function.child_by_field_name(
                "attribute"
            )
            name = self.text(prop) if prop is not None else name
        receiver_value = self.expr(receiver, env, depth + 1) if receiver is not None else _Value()
        positional: list[_Value] = []
        keywords: dict[str, _Value] = {}
        unknown_keywords = False
        children = arguments.named_children if arguments is not None else []
        for child in children:
            if child.type == "comment":
                continue
            if child.type == "keyword_argument":
                keyword_node = child.child_by_field_name("name")
                part = child.child_by_field_name("value")
                if keyword_node is not None and part is not None:
                    keywords[self.text(keyword_node)] = self.expr(part, env, depth + 1)
            elif child.type == "dictionary_splat" and child.named_children:
                expanded = self.expr(child.named_children[0], env, depth + 1)
                if expanded.fields is not None and not expanded.uncertainties:
                    keywords.update(expanded.fields)
                else:
                    unknown_keywords = True
            elif child.type in {"list_splat", "spread_element"} and child.named_children:
                sequence = child.named_children[0]
                if sequence.type in {"array", "list", "tuple"} and all(
                    part.type not in {"list_splat", "spread_element"}
                    for part in sequence.named_children
                ):
                    positional.extend(
                        self.expr(part, env, depth + 1)
                        for part in sequence.named_children
                        if part.type != "comment"
                    )
                else:
                    self.expr(sequence, env, depth + 1)
                    positional.append(_Value(uncertainties=frozenset({"argument_spread"})))
            else:
                positional.append(self.expr(child, env, depth + 1))
        if name.casefold() in QUERY_METHODS:
            selection = "positional:0"
            selected = positional[0] if positional else _Value()
            if not positional:
                for key in ("sql", "query", "operation", "statement"):
                    if key in keywords:
                        selected, selection = keywords[key], "keyword:" + key
                        break
                if unknown_keywords:
                    selected = _merge(
                        selected, _Value(uncertainties=frozenset({"argument_spread"}))
                    )
            if selected.fields is not None:
                keys = [key for key in ("sql", "text") if key in selected.fields]
                if len(keys) == 1:
                    selection += "." + keys[0]
                    selected = replace(
                        selected.fields[keys[0]],
                        uncertainties=selected.fields[keys[0]].uncertainties
                        | selected.uncertainties,
                    )
                else:
                    selected = _Value(
                        uncertainties=selected.uncertainties | {"ambiguous_query_object"}
                    )
            self.record(node, name, selected, selection)
        if name in {"format", "format_map"} and receiver is not None:
            try:
                holes = any(
                    part[1] is not None for part in string.Formatter().parse(receiver_value.text)
                )
            except ValueError:
                holes = False
            if not holes:
                return receiver_value
            value = receiver_value
            for item in [*positional, *keywords.values()]:
                value = _combine(value, item, "format_call")
            return value
        if name in {"str", "String", "text"} and positional:
            return replace(
                positional[0], uncertainties=positional[0].uncertainties | {"call_result_unmodeled"}
            )
        for value in [receiver_value, *positional, *keywords.values()]:
            if value.fields is not None:
                changed = replace(
                    value,
                    constant=False,
                    fields={
                        key: _merge(item, _Value(uncertainties=frozenset({"call_side_effect"})))
                        for key, item in value.fields.items()
                    },
                )
                for alias, item in list(env.items()):
                    if item.object_ids & value.object_ids:
                        env[alias] = (
                            changed
                            if item.object_ids == value.object_ids
                            else _merge(item, changed)
                        )
        return _Value()

    def record(self, node: Node, name: str, value: _Value, selection: str) -> None:
        if self.limited:
            value = replace(value, uncertainties=value.uncertainties | {"expression_limit"})
        facts = QueryExpression(
            state="constructed"
            if value.sql_constructed and "expression_limit" not in value.uncertainties
            else "constant"
            if value.constant and "expression_limit" not in value.uncertainties
            else "unknown",
            has_sql=bool(_SQL.search(value.text)),
            selection=selection,
            constructions=sorted(value.constructions),
            origin_lines=sorted(value.origins),
            uncertainties=sorted(value.uncertainties),
        )
        for call in self.calls.get((node.start_point[0] + 1, node.start_point[1]), []):
            if call.callee != name:
                continue
            previous = call.query_expression
            if previous is not None:
                uncertainties = sorted(set(previous.uncertainties) | set(facts.uncertainties))
                facts = facts.model_copy(
                    update={
                        "state": "unknown"
                        if "expression_limit" in uncertainties
                        else "constructed"
                        if "constructed" in {previous.state, facts.state}
                        else "constant"
                        if previous.state == facts.state == "constant"
                        else "unknown",
                        "has_sql": previous.has_sql or facts.has_sql,
                        "constructions": sorted(
                            set(previous.constructions) | set(facts.constructions)
                        ),
                        "origin_lines": sorted(
                            set(previous.origin_lines) | set(facts.origin_lines)
                        )[:MAX_ORIGINS],
                        "uncertainties": uncertainties,
                    }
                )
            call.query_expression = facts


def annotate_sql_queries(ast: FileAST, root: Node, source: bytes) -> None:
    if ast.language not in SUPPORTED:
        return
    analyzer = _Analyzer(ast, source)
    analyzer.walk(root, {})
    for call in ast.calls:
        if call.callee.casefold() not in QUERY_METHODS:
            continue
        if call.query_expression is None:
            call.query_expression = QueryExpression(
                uncertainties=["expression_limit" if analyzer.limited else "unmodeled_context"]
            )
        if "expression_limit" in call.query_expression.uncertainties:
            ast.query_expression_limit_count += 1
