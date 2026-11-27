"""Track literal servlet cookie flags from fresh allocation to addCookie."""

from __future__ import annotations

from tree_sitter import Node

from aegify.models import BooleanOption, CallArgument, ImportInfo

_PACKAGES = ("javax.servlet.http", "jakarta.servlet.http")
_FLAGS = {b"setSecure": "secure", b"setHttpOnly": "httpOnly"}
_OTHER_SETTERS = {b"setPath", b"setDomain", b"setValue", b"setMaxAge", b"setComment", b"setVersion"}
_COMMENTS = {"line_comment", "block_comment"}


def servlet_types(root: Node, imports: list[ImportInfo]) -> dict[str, str]:
    if root.has_error:
        return {}
    types = {
        f"{package}.{name}": f"{package}.{name}"
        for package in _PACKAGES
        for name in ("Cookie", "HttpServletResponse")
    }
    # An explicit import can be shadowed by a nested or generic type.
    short: dict[str, set[str]] = {}
    for item in imports:
        if item.module in types:
            short.setdefault(item.module.rsplit(".", 1)[1], set()).add(item.module)
    if short:
        pending = [root]
        while pending:
            node = pending.pop()
            if node.type in {
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
                "annotation_type_declaration",
                "type_parameter",
            }:
                name = node.child_by_field_name("name")
                if node.type == "type_parameter":
                    name = next(
                        (c for c in node.named_children if c.type == "type_identifier"), None
                    )
                if name is not None:
                    short.pop((name.text or b"").decode(errors="replace"), None)
            pending.extend(node.named_children)
    types.update({name: next(iter(values)) for name, values in short.items() if len(values) == 1})
    return types


def _field_text(node: Node, field: str) -> bytes:
    child = node.child_by_field_name(field)
    return (child.text or b"") if child is not None else b""


def _single_child(node: Node | None) -> Node | None:
    if node is None:
        return None
    children = [c for c in node.named_children if c.type not in _COMMENTS]
    return children[0] if len(children) == 1 else None


def _may_reference(node: Node, name: bytes) -> bool:
    # Unknown large expressions cannot establish that the local stayed private.
    if node.end_byte - node.start_byte > 4096:
        return True
    pending = [node]
    while pending:
        current = pending.pop()
        if current.type == "identifier" and current.text == name:
            return True
        pending.extend(current.named_children)
    return False


def cookie_arguments(
    sink: Node, method: Node | None, types: dict[str, str]
) -> list[CallArgument] | None:
    argument = _single_child(sink.child_by_field_name("arguments"))
    statement = sink.parent
    if (
        method is None
        or method.has_error
        or statement is None
        or statement.type != "expression_statement"
        or statement.parent != method.child_by_field_name("body")
        or argument is None
        or argument.type != "identifier"
    ):
        return None
    cookie = argument.text
    parameters = method.child_by_field_name("parameters")
    if parameters is None or cookie is None:
        return None
    receiver = _field_text(sink, "object")
    response_type = next(
        (
            types.get(_field_text(param, "type").decode(errors="replace"), "")
            for param in parameters.named_children
            if param.type == "formal_parameter" and _field_text(param, "name") == receiver
        ),
        "",
    )
    if response_type not in {f"{package}.HttpServletResponse" for package in _PACKAGES}:
        return None
    cookie_type = response_type.rsplit(".", 1)[0] + ".Cookie"
    flags: dict[str, BooleanOption] = {}
    # Only consecutive calls on this fresh local can prove its state. Any escape,
    # assignment, conditional or unfamiliar mutation ends the proof.
    for _ in range(64):
        previous = statement.prev_named_sibling
        if previous is None:
            return None
        statement = previous
        if statement.type in _COMMENTS:
            continue
        if statement.type == "local_variable_declaration":
            declarations = statement.children_by_field_name("declarator")
            if len(declarations) != 1 or _field_text(declarations[0], "name") != cookie:
                return None
            value = declarations[0].child_by_field_name("value")
            if (
                value is None
                or value.type != "object_creation_expression"
                or value.children[0].type != "new"
                or types.get(_field_text(value, "type").decode(errors="replace")) != cookie_type
                or any(c.type == "class_body" for c in value.named_children)
            ):
                return None
            return [CallArgument(kind="positional", options=list(flags.values()))]
        call = _single_child(statement)
        if (
            statement.type != "expression_statement"
            or call is None
            or call.type != "method_invocation"
            or _field_text(call, "object") != cookie
        ):
            return None
        setter = _field_text(call, "name")
        operand = _single_child(call.child_by_field_name("arguments"))
        if operand is None or _may_reference(operand, cookie):
            return None
        if setter in _FLAGS:
            flag = _FLAGS[setter]
            if flag not in flags:
                option = BooleanOption(name=flag)
                if operand.type == "true":
                    option.state = "true"
                elif operand.type == "false":
                    option.state = "false"
                flags[flag] = option
        elif setter not in _OTHER_SETTERS:
            return None
    return None
