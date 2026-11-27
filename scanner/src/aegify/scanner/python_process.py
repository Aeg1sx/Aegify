"""Resolve subprocess arguments and snapshot text supplied to a shell interpreter."""

from __future__ import annotations

import ast
from collections import Counter
from itertools import islice

from aegify.models import CallSite, FileAST, PythonProcessInput, PythonProcessPart
from aegify.scanner.python_scope import PythonModules, call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

_APIS = {f"subprocess.{name}" for name in ("run", "Popen", "call", "check_call", "check_output")}
_SHELLS = {
    directory + shell
    for directory in ("", "/bin/", "/usr/bin/")
    for shell in ("sh", "bash", "dash", "ksh", "zsh")
}
type _Entry = tuple[ast.expr, int]
type _Vector = tuple[_Entry, ...]


def _entries(items: list[ast.expr], line: int) -> _Vector | None:
    if len(items) > 64 or any(isinstance(item, ast.Starred) for item in items):
        return None
    return tuple((item, line) for item in items)


def _mutations(
    statements: list[ast.stmt],
    name: str,
    vectors: set[_Vector],
    references: set[ast.stmt],
    depth: int = 0,
) -> set[_Vector] | None:
    """Follow only proven writes to the local list, keeping conditional arms separate."""
    if depth > 4:
        return None
    for stmt in statements:
        if isinstance(stmt, ast.Return | ast.Raise):
            return set()
        if stmt not in references:
            continue
        if isinstance(stmt, ast.If):
            if any(isinstance(part, ast.Name) and part.id == name for part in ast.walk(stmt.test)):
                return None
            if isinstance(stmt.test, ast.Constant) and type(stmt.test.value) is bool:
                branch = stmt.body if stmt.test.value else stmt.orelse
                choice = _mutations(branch, name, vectors, references, depth + 1)
                if choice is None:
                    return None
                vectors = choice
                continue
            left = _mutations(stmt.body, name, vectors, references, depth + 1)
            right = _mutations(stmt.orelse, name, vectors, references, depth + 1)
            if left is None or right is None or len(left | right) > 16:
                return None
            vectors = left | right
            continue
        if not (
            isinstance(stmt, ast.Expr)
            and isinstance(call := stmt.value, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == name
            and len(call.args) == 1
            and not call.keywords
        ):
            return None
        value = call.args[0]
        if any(isinstance(part, ast.Name) and part.id == name for part in ast.walk(value)):
            return None
        if call.func.attr == "append":
            extra = _entries([value], stmt.lineno)
        elif call.func.attr == "extend" and isinstance(value, ast.List | ast.Tuple):
            extra = _entries(value.elts, stmt.lineno)
        else:
            return None
        if extra is None or any(len(vector) + len(extra) > 64 for vector in vectors):
            return None
        vectors = {vector + extra for vector in vectors}
    return vectors


def _vectors(local: LocalValues, value: ast.expr, use: ast.Call) -> set[_Vector] | None:
    parents = local.scope.parents
    end: ast.AST = use
    while end in parents and not isinstance(end, ast.stmt):
        end = parents[end]
    if not isinstance(end, ast.stmt) or local.in_loop(use):
        return None
    if isinstance(value, ast.List | ast.Tuple):
        initial = _entries(value.elts, end.lineno)
        return {initial} if initial is not None else None
    if not isinstance(value, ast.Name) or local.scope.definitions.get(value.id) != 1:
        return None
    seed = local.assigned(value)
    if not isinstance(seed, ast.List | ast.Tuple):
        return None
    start = parents[seed]
    if not isinstance(start, ast.AnnAssign) and not (
        isinstance(start, ast.Assign) and len(start.targets) == 1
    ):
        return None
    initial = _entries(seed.elts, start.lineno)
    if (
        initial is None
        or parents.get(start) is not parents.get(end)
        or len(local.loads[value.id]) > 128
    ):
        return None
    block = next(
        (
            body
            for _, body in ast.iter_fields(parents[start])
            if isinstance(body, list) and start in body and end in body
        ),
        None,
    )
    if block is None or len(block) > 512:
        return None
    references: set[ast.stmt] = set()
    for read in local.loads[value.id]:
        if read is value or not start.lineno <= read.lineno <= (use.end_lineno or use.lineno):
            continue
        cursor: ast.AST = read
        while cursor in parents and cursor is not parents[start]:
            if isinstance(cursor, ast.stmt):
                references.add(cursor)
            cursor = parents[cursor]
    if start in references or end in references:
        return None
    middle = block[block.index(start) + 1 : block.index(end)]
    return _mutations(middle, value.id, {initial}, references)


def _text(node: ast.expr) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _command_parts(
    local: LocalValues, value: ast.expr, call: ast.Call, lines: Counter[int]
) -> list[PythonProcessPart]:
    selected: set[tuple[int, str]] = set()
    for vector in _vectors(local, value, call) or ():
        if len(vector) < 3:
            continue
        executable = _text(vector[0][0])
        option = _text(vector[1][0])
        if executable in _SHELLS and option in {"-c", "-ec", "-lc"}:
            parts = vector[2:3]
        elif executable.lower() in {"cmd", "cmd.exe"} and option.lower() in {"/c", "/k"}:
            parts = vector[2:]
        else:
            continue
        for expr, line in parts:
            if (
                not isinstance(expr, ast.Constant)
                and lines[line] == 1
                and len(list(islice(ast.walk(expr), 129))) <= 128
            ):
                text = ast.unparse(expr)
                if len(text) <= 4096:
                    selected.add((line, text))
    return [PythonProcessPart(line=line, expression=expr) for line, expr in sorted(selected)]


def _parameter(call: ast.Call, index: int, name: str) -> tuple[int, ast.expr] | None:
    bound = call_argument(call, index, name)
    if bound or (
        not any(isinstance(arg, ast.Starred) for arg in call.args)
        and all(kw.arg is not None for kw in call.keywords)
    ):
        return bound
    # An explicit binding still supplies the value on every successful invocation
    # when a later unpack is present. Duplicate bindings raise before execution.
    for offset, kw in enumerate(call.keywords):
        if kw.arg == name:
            return len(call.args) + offset, kw.value
    if index < len(call.args) and not any(
        isinstance(arg, ast.Starred) for arg in call.args[: index + 1]
    ):
        return index, call.args[index]
    return None


def process_calls(source: bytes) -> dict[tuple[int, int, int, int], PythonProcessInput]:
    if b"subprocess" not in source:
        return {}
    facts = {}
    for scope in python_scopes(source):
        local = None
        lines: Counter[int] = Counter()
        for call in scope.nodes:
            if not isinstance(call, ast.Call):
                continue
            api = scope.resolve(call.func)
            if (
                api not in _APIS
                and isinstance(call.func, ast.Name)
                and call.func.id in scope.definitions
            ):
                if local is None:
                    local = LocalValues(scope)
                target = local.assigned(call.func)
                api = scope.resolve(target) if target is not None else ""
            if api not in _APIS:
                continue
            if call.end_lineno is None or call.end_col_offset is None:
                continue
            if local is None:
                local = LocalValues(scope)
            operand = _parameter(call, 0, "args")
            option = _parameter(call, 8, "shell")
            override = _parameter(call, 2, "executable")
            shell: bool | None = False
            if option:
                flag = local.assigned(option[1]) or option[1]
                shell = (
                    flag.value
                    if isinstance(flag, ast.Constant) and type(flag.value) is bool
                    else None
                )
            unpacked = any(isinstance(arg, ast.Starred) for arg in call.args) or any(
                kw.arg is None for kw in call.keywords
            )
            if not option and unpacked:
                shell = None
            parts = []
            if (
                operand
                and shell is False
                and not unpacked
                and (
                    not override
                    or isinstance(override[1], ast.Constant)
                    and override[1].value is None
                )
            ):
                if not lines:
                    lines.update(node.lineno for node in scope.nodes if isinstance(node, ast.stmt))
                parts = _command_parts(local, operand[1], call, lines)
            argument_index = operand[0] if operand else None
            if argument_index is None and call.args and isinstance(call.args[0], ast.Starred):
                argument_index = 0
            facts[call.lineno, call.col_offset, call.end_lineno, call.end_col_offset] = (
                PythonProcessInput(
                    api=api, argument_index=argument_index, shell=shell, command_parts=parts
                )
            )
    return facts


def process_input(
    call: CallSite, file: FileAST, modules: PythonModules
) -> PythonProcessInput | None:
    if not modules.external(file, "subprocess"):
        return None
    if call.python_process_input:
        return call.python_process_input if call.python_process_input.api in _APIS else None
    if file.python_process_resolved:
        return None
    # Import identity is unavailable on previously serialized call sites.
    api = f"{call.receiver}.{call.callee}"
    if api not in _APIS or not call.arguments:
        return None
    expression = ", ".join(call.arguments)
    if len(expression) > 8192:
        return PythonProcessInput(api=api, argument_index=0)
    try:
        parsed = ast.parse(f"f({expression})", mode="eval").body
    except SyntaxError, RecursionError, ValueError:
        return PythonProcessInput(api=api, argument_index=0)
    if not isinstance(parsed, ast.Call):
        return None
    operand = _parameter(parsed, 0, "args")
    flag = _parameter(parsed, 8, "shell")
    shell: bool | None = None
    if flag:
        if isinstance(flag[1], ast.Constant) and type(flag[1].value) is bool:
            shell = flag[1].value
    elif not any(isinstance(arg, ast.Starred) for arg in parsed.args) and all(
        kw.arg is not None for kw in parsed.keywords
    ):
        shell = False
    return PythonProcessInput(
        api=api,
        argument_index=operand[0] if operand else 0,
        shell=shell,
    )
