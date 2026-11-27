"""Recognize request-sensitive Flask session destinations without loading Flask."""

from __future__ import annotations

import ast
from typing import Literal

from aegify.models import SessionWrite
from aegify.scanner.python_scope import function_scopes

_IDENTITY_KEYS = {"_user_id", "user_id", "userid", "role", "roles", "is_admin", "permissions"}


def session_writes(source: bytes) -> list[SessionWrite]:
    if b"flask" not in source or b"session" not in source:
        return []
    writes: list[SessionWrite] = []
    for scope in function_scopes(source):
        assert isinstance(scope.owner, ast.FunctionDef | ast.AsyncFunctionDef)
        for node in scope.nodes:
            if not isinstance(node, ast.Assign | ast.AnnAssign) or node.value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (
                    not isinstance(target, ast.Subscript)
                    or scope.resolve(target.value) != "flask.session"
                ):
                    continue
                key = target.slice
                field: Literal["key", "identity"]
                if isinstance(key, ast.Constant):
                    if key.value not in _IDENTITY_KEYS:
                        continue
                    expression = node.value
                    field = "identity"
                else:
                    expression = key
                    field = "key"
                writes.append(
                    SessionWrite(
                        function_line=scope.owner.lineno,
                        line=node.lineno,
                        expression=ast.unparse(expression),
                        field=field,
                    )
                )
    return sorted(writes, key=lambda write: write.line)
