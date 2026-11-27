"""Recognize a database read whose result controls a write to the same store."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from tree_sitter import Node

from aegify.models import ConditionalWrite

_BLOCK = {"block", "statement_block", "statement_list", "module", "program"}
_COMMENT = {"comment", "line_comment", "block_comment"}
_CALL = {"call", "call_expression", "method_invocation"}
_RETURN = {"return_statement", "raise_statement", "throw_statement"}
_STORE = re.compile(
    r"(?:^|[._])(?:repo(?:sitory)?|dao|db|database|store|model|entitymanager|jdbc|jooq|collection|table|session|objects)(?:$|\.)",
    re.I,
)
_PRISMA = re.compile(r"(?:^|\.)(?:prisma|db)\.\w+$", re.I)
_READ = {
    "findbyid",
    "findone",
    "find",
    "get",
    "load",
    "read",
    "query",
    "fetch",
    "select",
    "findunique",
    "findfirst",
    "finduniqueorthrow",
    "findfirstorthrow",
}
_WRITE = {"save", "update", "put", "write", "store", "create", "delete", "destroy", "insert"}
_SQL_API = {
    "execute",
    "executemany",
    "executequery",
    "executeupdate",
    "query",
    "queryrow",
    "queryrowcontext",
    "querycontext",
    "exec",
    "execcontext",
}
_NAME = r"[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)?"
_SELECT = re.compile(rf"SELECT\s+[^;]+?\s+FROM\s+({_NAME})(?=\s|$)", re.I | re.S)
_DML = re.compile(
    rf"(?:UPDATE\s+({_NAME})\s+SET\b|INSERT\s+INTO\s+({_NAME})(?=[\s(]|$)|DELETE\s+FROM\s+({_NAME})(?=\s|$))",
    re.I,
)


def _walk(root: Node) -> Iterator[Node]:
    pending = [root]
    while pending:
        n = pending.pop()
        yield n
        pending.extend(reversed(n.named_children))


def _text(node: Node | None) -> str:
    return (node.text or b"").decode(errors="replace") if node is not None else ""


def _sibling(node: Node, *, previous: bool) -> Node | None:
    other = node.prev_named_sibling if previous else node.next_named_sibling
    while other is not None and other.type in _COMMENT:
        other = other.prev_named_sibling if previous else other.next_named_sibling
    return other


def _first(node: Node | None) -> Node | None:
    while node is not None and node.type in _BLOCK:
        node = next((c for c in node.named_children if c.type not in _COMMENT), None)
    return node


@dataclass(frozen=True)
class _Operation:
    owner: str
    table: str
    line: int
    saved_value: str = ""
    literal_id: str = ""


def _operation(call: Node, *, read: bool) -> _Operation | None:
    if call.type == "method_invocation":
        receiver, method = (call.child_by_field_name(key) for key in ("object", "name"))
    else:
        func = call.child_by_field_name("function")
        if func is None or func.type not in {
            "attribute",
            "member_expression",
            "selector_expression",
        }:
            return None
        receiver = func.child_by_field_name("object") or func.child_by_field_name("operand")
        method = (
            func.child_by_field_name("attribute")
            or func.child_by_field_name("property")
            or func.child_by_field_name("field")
        )
    owner, verb = _text(receiver), _text(method).lower()
    if not re.fullmatch(r"[\w$]+(?:\.[\w$]+)*", owner):
        return None
    args = call.child_by_field_name("arguments")
    operands = [n for n in args.named_children if n.type not in _COMMENT] if args else []
    index = int(verb.endswith("context"))
    if verb in _SQL_API and len(operands) > index:
        arg = operands[index]
        value = _text(arg)
        if (
            arg.type
            in {
                "string",
                "string_literal",
                "template_string",
                "interpreted_string_literal",
                "raw_string_literal",
            }
            and 2 <= len(value) <= 8192
            and value[0] in "'\"`"
            and value[-1] == value[0]
        ):
            query = value[1:-1].strip().removesuffix(";").strip()
            if not any(x in query for x in (";", "${", "\\", "/*", "--")):
                match = (_SELECT if read else _DML).match(query)
                if match and not re.search(
                    r"\b(?:FOR\s+(?:NO\s+KEY\s+)?UPDATE|FOR\s+SHARE|UPDLOCK|HOLDLOCK)\b",
                    query,
                    re.I,
                ):
                    table = next(v for v in match.groups() if v is not None)
                    # A conditional write already checking additional predicates
                    # can implement optimistic concurrency. Its semantics need wider review.
                    where = re.search(r"\bWHERE\s+(.+)$", query, re.I | re.S)
                    if not read and (
                        re.search(r"\bON\s+(?:CONFLICT|DUPLICATE)\b", query, re.I)
                        or (where and re.search(r"\b(?:AND|OR|version)\b", where[1], re.I))
                    ):
                        return None
                    key = (
                        re.fullmatch(r"(?:\w+\.)?id\s*=\s*(\d+|'[^']*')", where[1], re.I)
                        if where
                        else None
                    )
                    return _Operation(
                        owner,
                        table.lower(),
                        call.start_point[0] + 1,
                        literal_id=key[1] if key else "",
                    )
        # A query execution API must actually receive SQL of the requested kind.
        if verb != "query" or (value and value[0] in "'\"`"):
            return None
    if verb not in (_READ if read else _WRITE) or not (
        _STORE.search(owner) or _PRISMA.search(owner)
    ):
        return None
    saved = (
        _text(operands[0])
        if verb == "save" and len(operands) == 1 and operands[0].type == "identifier"
        else ""
    )
    return _Operation(owner, "", call.start_point[0] + 1, saved)


def _single_operation(root: Node, *, read: bool) -> _Operation | None:
    node = root
    while node.type in {
        "await",
        "await_expression",
        "parenthesized_expression",
        "expression_list",
        "expression_statement",
        "return_statement",
        "not_operator",
        "unary_expression",
    }:
        children = [n for n in node.named_children if n.type not in _COMMENT]
        if len(children) != 1:
            return None
        node = children[0]
    if node.type not in _CALL:
        return None
    if read and node.type == "call":
        fn = node.child_by_field_name("function")
        if (
            fn is not None
            and fn.type == "attribute"
            and _text(fn.child_by_field_name("attribute")) in {"fetchone", "fetchall"}
        ):
            inner = fn.child_by_field_name("object")
            args = node.child_by_field_name("arguments")
            if inner is None or inner.type != "call" or args is None or args.named_child_count:
                return None
            node = inner
    return _operation(node, read=read)


def _read_assignment(statement: Node) -> tuple[str, _Operation] | None:
    item = statement
    while item.type in {"expression_statement", "lexical_declaration", "variable_declaration"}:
        children = [c for c in item.named_children if c.type not in _COMMENT]
        if len(children) != 1:
            return None
        item = children[0]
    if item.type == "local_variable_declaration":
        decls = item.children_by_field_name("declarator")
        if len(decls) != 1:
            return None
        item = decls[0]
    if item.type not in {
        "assignment",
        "variable_declarator",
        "short_var_declaration",
        "assignment_expression",
    }:
        return None
    target = item.child_by_field_name("name") or item.child_by_field_name("left")
    value = item.child_by_field_name("value") or item.child_by_field_name("right")
    name = _text(target)
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name) or value is None:
        return None
    op = _single_operation(value, read=True)
    return (name, op) if op is not None else None


def _transaction_scope(branch: Node, owner: str) -> bool:
    node = branch.parent
    while node is not None:
        if node.type == "synchronized_statement":
            return True
        if node.type == "with_statement":
            clause = next((c for c in node.named_children if c.type == "with_clause"), None)
            if clause and (
                re.search(r"\b(?:atomic|transaction|begin|lock)\b", _text(clause), re.I)
                or _text(clause).strip() in {owner, owner.split(".")[0]}
            ):
                return True
        if node.type in _CALL:
            callee = node.child_by_field_name("function") or node.child_by_field_name("name")
            if re.search(r"(?:transaction|atomic|withlock)$", _text(callee), re.I):
                return True
        if node.type == "decorated_definition" and any(
            c.type == "decorator" and re.search(r"\batomic\b|transaction", _text(c), re.I)
            for c in node.named_children
        ):
            return True
        if node.type in {"method_declaration", "function_definition"} and any(
            c.type == "modifiers" and re.search(r"\b(?:Transactional|synchronized)\b", _text(c))
            for c in node.named_children
        ):
            return True
        node = node.parent
    return False


def _reads_name(condition: Node, name: str) -> bool:
    pending = [condition]
    while pending:
        node = pending.pop()
        if node.type in {
            "lambda",
            "lambda_expression",
            "arrow_function",
            "function_expression",
            "generator_expression",
            "list_comprehension",
            "set_comprehension",
            "dictionary_comprehension",
        }:
            continue
        if (
            node.type == "identifier"
            and _text(node) == name
            and node.parent is not None
            and node.parent.child_by_field_name("attribute") != node
            and node.parent.child_by_field_name("field") != node
        ):
            return True
        pending.extend(node.named_children)
    return False


def _guarded_write(branch: Node) -> ConditionalWrite | None:
    condition = branch.child_by_field_name("condition")
    if condition is None:
        return None
    before = _sibling(branch, previous=True)
    bound = _read_assignment(before) if before is not None else None
    if bound and _reads_name(condition, bound[0]):
        name, read = bound
    else:
        direct = _single_operation(condition, read=True)
        if direct is None:
            return None
        name, read = "", direct
    body = _first(branch.child_by_field_name("consequence") or branch.child_by_field_name("body"))
    if (
        body is not None
        and body.type in _RETURN
        and branch.child_by_field_name("alternative") is None
    ):
        body = _sibling(branch, previous=False)
    # A common ORM path changes fields on the selected object before saving it.
    # Stop at calls, reassignment of the receiver, or any other statement.
    for _ in range(8):
        if not name or body is None or body.type != "expression_statement":
            break
        expr = body.named_child(0)
        if expr is None or expr.type not in {"assignment", "assignment_expression"}:
            break
        left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
        if (
            left is None
            or left.type not in {"attribute", "member_expression", "field_access"}
            or right is None
        ):
            break
        if _text(left.child_by_field_name("object")) != name or any(
            n.type in _CALL for n in _walk(right)
        ):
            break
        body = _sibling(body, previous=False)
    if body is None or body.type not in {
        "expression_statement",
        "return_statement",
        "assignment_statement",
        "short_var_declaration",
    }:
        return None
    write = _single_operation(body, read=False)
    if (
        write is None
        or (read.owner, read.table) != (write.owner, write.table)
        or (read.literal_id and write.literal_id and read.literal_id != write.literal_id)
        or _transaction_scope(branch, read.owner)
    ):
        return None
    return ConditionalWrite(
        read_line=read.line,
        condition_line=branch.start_point[0] + 1,
        line=write.line,
        sql=bool(read.table),
        saves_read_value=bool(name and write.saved_value == name),
    )


def guarded_writes(root: Node, source: bytes) -> list[ConditionalWrite]:
    if b"if" not in source or root.has_error:
        return []
    return [
        fact
        for node in _walk(root)
        if node.type == "if_statement" and (fact := _guarded_write(node))
    ]
