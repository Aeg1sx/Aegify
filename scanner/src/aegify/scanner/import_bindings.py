"""Source-declared import identities shared by graph and taint resolution."""

from aegify.models import FileAST


def declared_import_names(ast: FileAST) -> set[str]:
    names: set[str] = set()
    for imported in ast.imports:
        names.update(name for name in imported.names if name not in imported.bindings.values())
        names.update(imported.bindings)
        if not imported.names and imported.module:
            module = imported.module.rstrip("/.").replace("::", "/").replace(".", "/")
            names.add(imported.alias or module.rsplit("/", 1)[-1])
    return names
