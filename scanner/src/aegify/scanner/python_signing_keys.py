"""Identify string literals used as HMAC JWT signing keys without retaining their values."""

import ast
import io
import tokenize

from aegify.models import PythonSigningKey
from aegify.scanner.python_scope import PythonScope, python_scopes

_SIGNERS = {"jwt.encode", "jose.jwt.encode"}
_ALGORITHMS = {"HS256", "HS384", "HS512"}
REDACTED_SIGNING_KEY = "[REDACTED_SIGNING_KEY]"


def _literal(
    node: ast.expr,
    scope: PythonScope,
    owners: dict[ast.AST, PythonScope],
    declarations: dict[ast.AST, dict[str, ast.Assign | ast.AnnAssign]],
) -> ast.Constant | None:
    # Resolve simple assignments and aliases. Stop at the first lexical definition.
    current: PythonScope | None = scope
    for _ in range(12):
        if isinstance(node, ast.Constant):
            return node
        if not isinstance(node, ast.Name) or current is None:
            return None
        if node.id not in current.definitions:
            current = owners.get(current.owner)
            # A method does not capture class attributes as local names.
            while current is not None and isinstance(current.owner, ast.ClassDef):
                current = owners.get(current.owner)
            continue
        stmt = declarations[current.owner].get(node.id)
        if stmt is None or stmt.value is None or stmt.lineno >= node.lineno:
            return None
        node = stmt.value
    return None


def _signing_args(call: ast.Call, api: str) -> dict[str, ast.expr] | None:
    payload = "claims" if api == "jose.jwt.encode" else "payload"
    parameters = [payload, "key", "algorithm", "headers"]
    parameters.extend(
        ["access_token"] if api == "jose.jwt.encode" else ["json_encoder", "sort_headers"]
    )
    if len(call.args) > len(parameters) or any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    bound = dict(zip(parameters, call.args, strict=False))
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in parameters or kw.arg in bound:
            return None
        bound[kw.arg] = kw.value
    if not {payload, "key"} <= bound.keys():
        return None
    return bound


def signing_keys(source: bytes) -> list[PythonSigningKey]:
    if b"jwt" not in source or b"encode" not in source:
        return []
    scopes = list(python_scopes(source))
    if not scopes:
        return []
    # Assignments through a global or closure can invalidate a seemingly unique declaration.
    rebound = {
        name
        for scope in scopes
        for stmt in scope.nodes
        if isinstance(stmt, ast.Global | ast.Nonlocal)
        for name in stmt.names
    }
    owners: dict[ast.AST, PythonScope] = {
        child: scope
        for scope in scopes
        for child in scope.parents
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
    }
    declarations: dict[ast.AST, dict[str, ast.Assign | ast.AnnAssign]] = {}
    found = []
    for scope in scopes:
        bindings = {}
        for stmt in scope.owner.body:
            if not isinstance(stmt, ast.Assign | ast.AnnAssign):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                name = targets[0].id
                if scope.definitions.get(name) == 1 and name not in rebound:
                    bindings[name] = stmt
        declarations[scope.owner] = bindings

        for node in scope.nodes:
            if not isinstance(node, ast.Call) or (api := scope.resolve(node.func)) not in _SIGNERS:
                continue
            bound = _signing_args(node, api)
            if bound is None:
                continue
            algorithm = "HS256"
            if "algorithm" in bound:
                mode = _literal(bound["algorithm"], scope, owners, declarations)
                if mode is None or not isinstance(mode.value, str) or mode.value not in _ALGORITHMS:
                    continue
                algorithm = mode.value
            headers = bound.get("headers")
            if headers is not None and not (
                isinstance(headers, ast.Constant)
                and headers.value is None
                or isinstance(headers, ast.Dict)
                and all(
                    isinstance(k, ast.Constant)
                    and isinstance(k.value, str)
                    and (k.value != "alg" or isinstance(v, ast.Constant) and v.value == algorithm)
                    for k, v in zip(headers.keys, headers.values, strict=True)
                )
            ):
                continue
            material = _literal(bound["key"], scope, owners, declarations)
            if (
                material is None
                or not isinstance(material.value, str | bytes)
                or not material.value
                or material.end_col_offset is None
            ):
                continue
            # A recognizable asymmetric key is not an HMAC secret.
            value = (
                material.value.encode("utf-8", errors="replace")
                if isinstance(material.value, str)
                else material.value
            )
            if value.lstrip().startswith(
                (b"-----BEGIN ", b"ssh-", b"ecdsa-sha2-", b"sk-ssh-", b"sk-ecdsa-")
            ):
                continue
            found.append(
                PythonSigningKey(
                    api=api,
                    algorithm=algorithm,
                    line=material.lineno,
                    end_line=material.end_lineno or material.lineno,
                    column=material.col_offset,
                    end_column=material.end_col_offset,
                    use_line=node.lineno,
                )
            )
    return sorted(found, key=lambda fact: (fact.line, fact.use_line, fact.api))


def protected_lines(facts: list[PythonSigningKey]) -> set[int]:
    return {
        line
        for start, end in {(f.line, f.end_line) for f in facts}
        for line in range(start, end + 1)
    }


def redact_signing_source(raw: bytes, facts: list[PythonSigningKey]) -> str:
    """Replace literal ranges while preserving line numbers and surrounding source."""
    raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = raw.removeprefix(b"\xef\xbb\xbf").split(b"\n")
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError:
        encoding = ""
    marker = REDACTED_SIGNING_KEY.encode()
    spans = {(f.line, f.column, f.end_line, f.end_column) for f in facts}
    for start, col, end, end_col in sorted(spans, reverse=True):
        if not 1 <= start <= end <= len(lines):
            # Coordinates must come from these same source bytes.
            return "\n".join(REDACTED_SIGNING_KEY for _ in lines)
        if encoding not in {"utf-8", "utf-8-sig"}:
            # CPython AST columns count UTF-8 bytes after decoding. Columns in
            # another source encoding need not identify the same bytes.
            lines[start - 1 : end] = [marker] * (end - start + 1)
            continue
        prefix, suffix = lines[start - 1][:col], lines[end - 1][end_col:]
        lines[start - 1 : end] = [marker] * (end - start + 1)
        lines[start - 1] = prefix + lines[start - 1]
        lines[end - 1] += suffix
    return b"\n".join(lines).decode("utf-8", errors="replace")
