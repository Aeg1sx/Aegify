"""Recognize local append-only in-memory streams without running project code."""

from __future__ import annotations

import ast
from collections import defaultdict

from aegify.scanner.python_scope import function_scopes


def buffer_writes(source: bytes) -> set[tuple[int, int]]:
    if b"StringIO" not in source and b"BytesIO" not in source:
        return set()
    writes: set[tuple[int, int]] = set()
    for scope in function_scopes(source):
        reads: dict[str, list[ast.Name]] = defaultdict(list)
        constructors: dict[str, ast.Assign] = {}
        for node in scope.nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                reads[node.id].append(node)
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(target := node.targets[0], ast.Name)
                and scope.definitions.get(target.id) == 1
                and isinstance(node.value, ast.Call)
                and scope.resolve(node.value.func) in {"io.StringIO", "io.BytesIO"}
                and not node.value.args
                and not node.value.keywords
            ):
                constructors[target.id] = node
        if not constructors:
            continue
        opaque_names = {
            node.id
            for node in ast.walk(scope.owner)
            if isinstance(node, ast.Name) and node not in scope.parents
        }
        for name, constructor in constructors.items():
            if name in opaque_names:
                continue
            local_writes = set()
            for read in reads[name]:
                method = scope.parents[read]
                if not isinstance(method, ast.Attribute) or not scope.precedes(constructor, read):
                    break
                call = scope.parents[method]
                if not isinstance(call, ast.Call) or call.func is not method or call.keywords:
                    break
                if method.attr == "getvalue" and not call.args:
                    continue
                if (
                    method.attr != "write"
                    or len(call.args) != 1
                    or isinstance(call.args[0], ast.Starred)
                    or not isinstance(scope.parents[call], ast.Expr)
                ):
                    break
                local_writes.add((call.lineno, call.col_offset))
            else:
                writes.update(local_writes)
    return writes
