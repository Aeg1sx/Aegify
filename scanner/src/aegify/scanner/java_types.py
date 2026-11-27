"""Resolve the explicitly supported JDK and servlet names in a Java source file."""

from tree_sitter import Node

from aegify.models import ImportInfo


def known_types(root: Node, imports: list[ImportInfo]) -> dict[str, str]:
    if root.has_error:
        return {}
    types = {
        f"{package}.{name}": f"{package}.{name}"
        for package in ("javax.servlet.http", "jakarta.servlet.http")
        for name in ("Cookie", "HttpServletResponse", "HttpServletRequest", "HttpSession")
    }
    java_lang = ("Integer", "Long", "Float", "Double", "String", "Math")
    types.update({f"java.lang.{name}": f"java.lang.{name}" for name in java_lang})
    for name in ("Connection", "Statement"):
        types[f"java.sql.{name}"] = f"java.sql.{name}"
    types["javax.sql.DataSource"] = "javax.sql.DataSource"
    types["java.util.Random"] = "java.util.Random"
    # An explicit import can be shadowed by a nested or generic type.
    short = {name: {f"java.lang.{name}"} for name in java_lang}
    for item in imports:
        name = item.module.rsplit(".", 1)[-1]
        if name in java_lang and item.module != f"java.lang.{name}":
            short.pop(name, None)
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
                declared = node.child_by_field_name("name")
                if node.type == "type_parameter":
                    declared = next(
                        (c for c in node.named_children if c.type == "type_identifier"), None
                    )
                if declared is not None:
                    short.pop((declared.text or b"").decode(errors="replace"), None)
            elif node.type == "field_declaration":
                for field in node.named_children:
                    if field.type == "variable_declarator":
                        field_name = field.child_by_field_name("name")
                        if field_name is not None:
                            short.pop((field_name.text or b"").decode(errors="replace"), None)
            pending.extend(node.named_children)
    types.update({name: next(iter(values)) for name, values in short.items() if len(values) == 1})
    return types
