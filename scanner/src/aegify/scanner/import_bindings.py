"""Source-declared import identities shared by graph and taint resolution."""

from aegify.models import FileAST, Language


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
