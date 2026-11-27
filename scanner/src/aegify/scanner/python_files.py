"""Resolve path operands of Python filesystem operations without loading the program."""

from __future__ import annotations

import ast
from itertools import pairwise

from aegify.models import PythonDirectoryCheck, PythonFileAccess, PythonReadLimit
from aegify.scanner.python_scope import PythonScope, call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

_FILE_PARAMS = {
    "open": ("file",),
    "builtins.open": ("file",),
    "io.open": ("file",),
    "codecs.open": ("filename",),
    "os.open": ("path",),
    "os.remove": ("path",),
    "os.unlink": ("path",),
    "os.rmdir": ("path",),
    "os.mkdir": ("path",),
    "os.makedirs": ("name",),
    "os.listdir": ("path",),
    "os.scandir": ("path",),
    "os.rename": ("src", "dst"),
    "os.replace": ("src", "dst"),
    "shutil.copy": ("src", "dst"),
    "shutil.copy2": ("src", "dst"),
    "shutil.copyfile": ("src", "dst"),
    "shutil.copytree": ("src", "dst"),
    "shutil.move": ("src", "dst"),
    "shutil.rmtree": ("path",),
    "flask.send_file": ("path_or_file",),
}
_METADATA = {"exists", "isfile", "isdir", "islink", "lexists"}
_PATH_CLASSES = {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}
_PATH_DERIVATIONS = {"joinpath", "with_name", "with_stem", "with_suffix", "absolute", "resolve"}
_PATH_IO = {
    "open",
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "touch",
    "unlink",
    "mkdir",
    "rmdir",
    "iterdir",
    "rename",
    "replace",
}
_PATH_METADATA = {"exists", "is_file", "is_dir", "is_symlink", "stat", "lstat"}


def _path_receiver(node: ast.expr, local: LocalValues, depth: int = 0) -> bool:
    if depth >= 12:
        return False
    if isinstance(node, ast.Name):
        value = local.assigned(node)
        return value is not None and _path_receiver(value, local, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _path_receiver(node.left, local, depth + 1)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        return _path_receiver(node.value, local, depth + 1)
    if isinstance(node, ast.Call):
        return local.scope.resolve(node.func) in _PATH_CLASSES or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _PATH_DERIVATIONS
            and _path_receiver(node.func.value, local, depth + 1)
        )
    return False


def _api(function: ast.expr, local: LocalValues) -> str:
    scope = local.scope
    if isinstance(function, ast.Name) and function.id == "open" and "open" not in scope.hidden:
        return "" if "builtins.open" in scope.modified else "open"
    return scope.resolve(function)


def _file_stream(node: ast.expr, local: LocalValues, depth: int = 0) -> bool:
    if depth >= 12:
        return False
    if isinstance(node, ast.Name):
        value = local.assigned(node)
        if (
            value is None
            and node.id not in local.closed_over
            and local.scope.definitions.get(node.id) == 1
        ):
            stores = local.stores.get(node.id, [])
            parent = local.scope.parents.get(stores[0]) if len(stores) == 1 else None
            if isinstance(parent, ast.withitem) and parent.optional_vars is stores[0]:
                owner = local.scope.parents.get(parent)
                cursor: ast.AST = node
                while cursor in local.scope.parents and local.scope.parents[cursor] is not owner:
                    cursor = local.scope.parents[cursor]
                if isinstance(owner, ast.With) and cursor in owner.body:
                    value = parent.context_expr
        return value is not None and _file_stream(value, local, depth + 1)
    return local.scope.resolve(node) == "flask.request.stream" or (
        isinstance(node, ast.Call)
        and (
            _api(node.func, local)
            in {
                "open",
                "builtins.open",
                "io.open",
                "io.BytesIO",
                "io.BufferedReader",
                "io.FileIO",
                "codecs.open",
                "tempfile.TemporaryFile",
                "tempfile.SpooledTemporaryFile",
            }
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "open"
                and _path_receiver(node.func.value, local)
            )
        )
    )


def _operation(call: ast.Call, local: LocalValues) -> PythonFileAccess | None:
    api = _api(call.func, local)
    params = _FILE_PARAMS.get(api, ())
    metadata = api.removeprefix("os.path.") in _METADATA and api.startswith("os.path.")
    if metadata:
        params = ("path",)
    indices: list[int] = []
    if not params:
        if not isinstance(call.func, ast.Attribute):
            return None
        name = call.func.attr
        if name not in _PATH_IO and name not in _PATH_METADATA:
            return None
        if not _path_receiver(call.func.value, local):
            return None
        api = "pathlib.Path." + name
        indices.append(-1)
        metadata = name in _PATH_METADATA
        params = ("target",) if name in {"rename", "replace"} else ()
    for index, keyword in enumerate(params):
        selected = call_argument(call, index, keyword)
        if selected and not (api == "flask.send_file" and _file_stream(selected[1], local)):
            indices.append(selected[0])
    if not indices:
        return None
    return PythonFileAccess(
        api=api, path_indices=indices, sink_type="file_metadata" if metadata else "file_access"
    )


def _rejects_oversize(guard: ast.stmt, name: str) -> bool:
    if not isinstance(guard, ast.If) or not isinstance(guard.body[-1], ast.Raise | ast.Return):
        return False
    test = guard.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    measured, limit = test.left, test.comparators[0]
    if isinstance(test.ops[0], ast.Lt | ast.LtE):
        measured, limit = limit, measured
    elif not isinstance(test.ops[0], ast.Gt | ast.GtE):
        return False
    return (
        isinstance(measured, ast.Call)
        and isinstance(measured.func, ast.Name)
        and measured.func.id == "len"
        and not measured.keywords
        and len(measured.args) == 1
        and isinstance(measured.args[0], ast.Name)
        and measured.args[0].id == name
        and (
            isinstance(limit, ast.Name | ast.Attribute)
            or (isinstance(limit, ast.Constant) and type(limit.value) is int)
        )
    )


def post_read_limits(source: bytes) -> list[PythonReadLimit]:
    """Find a rejecting size check on the result of the immediately preceding read."""
    if b"len" not in source or not any(m in source for m in (b"read_bytes", b"read_text")):
        return []
    observations = []
    for scope in python_scopes(source):
        if "len" in scope.hidden or "builtins.len" in scope.modified:
            continue
        for node in [scope.owner, *scope.nodes]:
            for _, block in ast.iter_fields(node):
                if (
                    not isinstance(block, list)
                    or len(block) < 2
                    or not isinstance(block[0], ast.stmt)
                ):
                    continue
                for assignment, guard in pairwise(block):
                    if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1:
                        target = assignment.targets[0]
                    elif isinstance(assignment, ast.AnnAssign):
                        target = assignment.target
                    else:
                        continue
                    call = assignment.value
                    if (
                        isinstance(target, ast.Name)
                        and isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr in {"read_bytes", "read_text"}
                        and not call.args
                        and not call.keywords
                        and _rejects_oversize(guard, target.id)
                    ):
                        observations.append(
                            PythonReadLimit(
                                method=call.func.attr,
                                line=call.lineno,
                                end_line=call.end_lineno or call.lineno,
                                guard_line=guard.lineno,
                            )
                        )
    return sorted(observations, key=lambda check: check.line)


def _module_entry_functions(scope: PythonScope) -> set[str]:
    """Zero-argument functions invoked directly by a Python script entry guard."""
    if not isinstance(scope.owner, ast.Module) or "__name__" in scope.hidden:
        return set()
    names = set()
    for node in scope.owner.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.comparators[0], ast.Constant)
            and test.comparators[0].value == "__main__"
        ):
            continue
        for statement in node.body:
            if isinstance(statement, ast.Raise):
                expr = statement.exc
            elif isinstance(statement, ast.Expr):
                expr = statement.value
            else:
                continue
            if isinstance(expr, ast.Call) and len(expr.args) == 1 and not expr.keywords:
                if scope.resolve(expr.func) == "sys.exit" or (
                    isinstance(statement, ast.Raise)
                    and isinstance(expr.func, ast.Name)
                    and expr.func.id == "SystemExit"
                    and "SystemExit" not in scope.hidden
                ):
                    expr = expr.args[0]
            if (
                isinstance(expr, ast.Call)
                and isinstance(expr.func, ast.Name)
                and not expr.args
                and not expr.keywords
                and scope.definitions.get(expr.func.id) == 1
            ):
                names.add(expr.func.id)
    return names


def _cli_path_line(node: ast.expr, local: LocalValues, depth: int = 0) -> int | None:
    if depth >= 12:
        return None
    if isinstance(node, ast.Name):
        value = local.assigned(node)
        return _cli_path_line(value, local, depth + 1) if value is not None else None
    if isinstance(node, ast.Subscript) and local.scope.resolve(node.value) == "sys.argv":
        index = node.slice
        if isinstance(index, ast.Constant) and type(index.value) is int and index.value > 0:
            return node.lineno
    if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords:
        if local.scope.resolve(node.func) in _PATH_CLASSES:
            return _cli_path_line(node.args[0], local, depth + 1)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "with_name":
            name = node.args[0]
            if (
                isinstance(name, ast.Constant)
                and isinstance(name.value, str)
                and name.value not in {"", ".", ".."}
                and "/" not in name.value
                and "\\" not in name.value
            ):
                return _cli_path_line(node.func.value, local, depth + 1)
    return None


def file_calls(source: bytes) -> dict[tuple[int, int, int, int], PythonFileAccess]:
    facts: dict[tuple[int, int, int, int], PythonFileAccess] = {}
    entries: set[ast.FunctionDef] = set()
    for scope in python_scopes(source):
        if isinstance(scope.owner, ast.Module):
            names = _module_entry_functions(scope)
            entries = {
                node
                for node in scope.owner.body
                if isinstance(node, ast.FunctionDef)
                and node.name in names
                and not node.decorator_list
                and not node.args.args
                and not node.args.posonlyargs
                and not node.args.kwonlyargs
                and node.args.vararg is None
                and node.args.kwarg is None
            }
        local = LocalValues(scope)
        for node in scope.nodes:
            if (
                isinstance(node, ast.Call)
                and node.end_lineno is not None
                and node.end_col_offset is not None
            ):
                fact = _operation(node, local)
                if fact:
                    if (
                        scope.owner in entries
                        and isinstance(node.func, ast.Attribute)
                        and fact.api
                        in {
                            "pathlib.Path.read_text",
                            "pathlib.Path.read_bytes",
                            "pathlib.Path.write_text",
                            "pathlib.Path.write_bytes",
                        }
                    ):
                        fact.cli_path_origin_line = _cli_path_line(node.func.value, local)
                    facts[(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)] = (
                        fact
                    )
    return facts


_PATH_MODULES = ("os.path", "posixpath", "ntpath")
_COMMON_PREFIX = {f"{module}.commonprefix" for module in _PATH_MODULES}
_PATH_BUILDERS = {
    f"{module}.{name}"
    for module in _PATH_MODULES
    for name in ("abspath", "realpath", "normpath", "join", "dirname", "expanduser")
} | _PATH_CLASSES


def _assigned_value(node: ast.expr, local: LocalValues, depth: int = 0) -> ast.expr:
    if depth < 6 and (value := local.assigned(node)) is not None:
        return _assigned_value(value, local, depth + 1)
    return node


def _uses_path(node: ast.expr, local: LocalValues) -> bool:
    value = _assigned_value(node, local)
    if isinstance(value, ast.Call) and local.scope.resolve(value.func) in _PATH_BUILDERS:
        return True
    return _path_receiver(value, local)


def _operand_matches(item: ast.expr, root: ast.expr, use: ast.Compare, local: LocalValues) -> bool:
    # Only stable local names and explicit path constructions can identify the compared operand.
    if not isinstance(item, ast.Name):
        if not _uses_path(item, local):
            return False
        if any(
            isinstance(part, ast.Call) and not _uses_path(part, local) for part in ast.walk(item)
        ):
            return False
    if ast.dump(item) != ast.dump(root):
        return False
    start = (item.lineno, item.col_offset)
    end = (use.end_lineno or use.lineno, use.end_col_offset or use.col_offset)
    return not any(
        start < (store.lineno, store.col_offset) < end
        for part in ast.walk(item)
        if isinstance(part, ast.Name)
        for store in local.stores.get(part.id, ())
    )


def directory_checks(source: bytes) -> list[PythonDirectoryCheck]:
    """Record path-prefix comparisons used as a decision or a returned predicate."""
    if b"commonprefix" not in source:
        return []
    checks: dict[tuple[int, int], PythonDirectoryCheck] = {}
    for scope in python_scopes(source):
        prefixes = {
            call: scope.resolve(call.func)
            for call in scope.nodes
            if isinstance(call, ast.Call) and scope.resolve(call.func) in _COMMON_PREFIX
        }
        if not prefixes:
            continue
        local = LocalValues(scope)
        for test in scope.nodes:
            if not (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq | ast.NotEq)
            ):
                continue
            parent = scope.parents.get(test)
            condition: ast.AST = test
            while isinstance(parent, ast.BoolOp) or (
                isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not)
            ):
                condition, parent = parent, scope.parents.get(parent)
            if not (isinstance(parent, ast.Return) or getattr(parent, "test", None) is condition):
                continue
            right = test.comparators[0]
            for result, root in ((test.left, right), (right, test.left)):
                call = _assigned_value(result, local)
                if (
                    not isinstance(call, ast.Call)
                    or call not in prefixes
                    or len(call.args) != 1
                    or call.keywords
                ):
                    continue
                paths = call.args[0]
                # A local tuple has fixed membership. A mutable list must appear at the call.
                if isinstance(paths, ast.Name):
                    paths = _assigned_value(paths, local)
                    if not isinstance(paths, ast.Tuple):
                        continue
                if not isinstance(paths, ast.List | ast.Tuple) or len(paths.elts) != 2:
                    continue
                if not any(_uses_path(item, local) for item in paths.elts):
                    continue
                if any(_operand_matches(item, root, test, local) for item in paths.elts):
                    checks.setdefault(
                        (call.lineno, call.col_offset),
                        PythonDirectoryCheck(
                            api=prefixes[call],
                            line=call.lineno,
                            end_line=call.end_lineno or call.lineno,
                            comparison_line=test.lineno,
                        ),
                    )
    return [checks[key] for key in sorted(checks)]
