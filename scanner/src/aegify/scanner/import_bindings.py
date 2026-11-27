"""Source-declared import identities shared by graph and taint resolution."""

from aegify.models import CallSite, FileAST, FunctionDef, Language


def javascript_targets(call: CallSite, candidates: list[FunctionDef]) -> list[FunctionDef]:
    """A nested binding is visible only in its own source scope."""
    visible = []
    for function in candidates:
        scope = function.javascript_scope
        if scope is None:
            continue
        row, col, last, right = scope
        if (
            not call.receiver
            and function.file_path == call.file_path
            and ((row, col) <= (call.line, call.column) < (last, right))
        ):
            visible.append(function)
    if not visible:
        return [function for function in candidates if function.javascript_scope is None]
    inner = max(function.javascript_scope for function in visible if function.javascript_scope)
    return [function for function in visible if function.javascript_scope == inner]


def shares_call_runtime(caller: Language, target: Language) -> bool:
    """Languages where a source-level name can refer directly to the same callable."""
    if caller == target:
        return True
    return {caller, target} in (
        {Language.JAVASCRIPT, Language.TYPESCRIPT},
        {Language.JAVA, Language.KOTLIN},
    )


def declared_import_names(ast: FileAST) -> set[str]:
    names: set[str] = set()
    for imported in ast.imports:
        names.update(name for name in imported.names if name not in imported.bindings.values())
        names.update(imported.bindings)
        if not imported.names and imported.module:
            module = imported.module.rstrip("/.").replace("::", "/").replace(".", "/")
            names.add(imported.alias or module.rsplit("/", 1)[-1])
    return names
