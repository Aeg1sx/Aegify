"""Classify Python object readers from source, without loading the scanned data."""

from __future__ import annotations

import ast
import pickletools
from collections import defaultdict
from typing import Literal

from aegify.models import CallSite, FileAST, PythonDeserialization
from aegify.scanner.python_literals import LiteralInputs
from aegify.scanner.python_scope import PythonScope, call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

type _Position = tuple[int, int, int, int]

_PICKLE_MODULES = {"pickle", "_pickle", "cPickle"}
_YAML_READERS = {
    "yaml.load",
    "yaml.load_all",
    "yaml.unsafe_load",
    "yaml.unsafe_load_all",
    "yaml.full_load",
    "yaml.full_load_all",
    "yaml.safe_load",
    "yaml.safe_load_all",
}
_LOADERS: dict[str, Literal["object", "restricted", "full"]] = {
    "Loader": "object",
    "UnsafeLoader": "object",
    "CLoader": "object",
    "CUnsafeLoader": "object",
    "BaseLoader": "restricted",
    "SafeLoader": "restricted",
    "CBaseLoader": "restricted",
    "CSafeLoader": "restricted",
    "FullLoader": "full",
    "CFullLoader": "full",
}
_EXTENSION_METHODS = {
    "add_constructor",
    "add_multi_constructor",
    "add_implicit_resolver",
    "add_path_resolver",
}
_TABLES = {
    "yaml_constructors",
    "yaml_multi_constructors",
    "yaml_implicit_resolvers",
    "yaml_path_resolvers",
}
# These opcodes can build only plain data from a fresh standard unpickler stack.
# Unknown instructions and extension, object, buffer and persistent callbacks stay reviewable.
_DATA_OPCODES = frozenset(
    """
    PROTO FRAME STOP MARK NONE NEWTRUE NEWFALSE INT BININT BININT1 BININT2 LONG LONG1 LONG4
    FLOAT BINFLOAT STRING BINSTRING SHORT_BINSTRING UNICODE BINUNICODE SHORT_BINUNICODE BINUNICODE8
    BINBYTES SHORT_BINBYTES BINBYTES8 BYTEARRAY8 EMPTY_LIST LIST APPEND APPENDS EMPTY_TUPLE
    TUPLE TUPLE1 TUPLE2 TUPLE3 EMPTY_DICT DICT SETITEM SETITEMS EMPTY_SET ADDITEMS FROZENSET
    PUT BINPUT LONG_BINPUT MEMOIZE GET BINGET LONG_BINGET POP POP_MARK DUP
""".split()
)
_OPCODE_BYTES = frozenset(ord(op.code) for op in pickletools.opcodes)


def _passive_pickle(value: bytes | str) -> bool:
    if isinstance(value, str) or not value:
        return True  # loads requires a nonempty bytes-like object.
    if value[0] not in _OPCODE_BYTES:
        return True  # The default reader fails before its first instruction.
    fixed_prefix = True
    try:
        for i, (op, _argument, offset) in enumerate(pickletools.genops(value)):
            if i >= 256 or op.name not in _DATA_OPCODES:
                return False
            if op.name == "STOP":
                return True
            # Fixed-width instructions establish an exact next opcode boundary,
            # even when there is no complete record for genops to disassemble.
            fixed_prefix = fixed_prefix and op.name != "FRAME" and (op.arg is None or op.arg.n >= 0)
            if fixed_prefix and offset is not None:
                following = offset + 1 + (op.arg.n if op.arg else 0)
                if following >= len(value) or value[following] not in _OPCODE_BYTES:
                    return True
    except ValueError, OverflowError, UnicodeError:
        pass
    return False


def _passive_yaml(value: bytes | str) -> bool:
    # Object constructors in the stock unsafe loader require an explicit tag.
    # Limit the proof to ordinary ASCII text without tags, directives or control bytes.
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeError:
            return False
    return value.isascii() and not any(
        c in "!%" or not (c.isprintable() or c in "\t\n\r") for c in value
    )


def _loader(scope: PythonScope, node: ast.expr, local: LocalValues) -> str:
    for _ in range(12):
        path = scope.resolve(node)
        parts = path.split(".")
        if parts[-1] in _LOADERS and ".".join(parts[:-1]) in {"yaml", "yaml.loader", "yaml.cyaml"}:
            return parts[-1]
        assigned = local.assigned(node)
        if assigned is None:
            break
        node = assigned
    return ""


def _extensions(scope: PythonScope, local: LocalValues) -> set[str]:
    defaults = {"Loader", "FullLoader", "UnsafeLoader"}
    affected: set[str] = set()
    if isinstance(scope.owner, ast.ClassDef) and any(
        scope.resolve(base) == "yaml.YAMLObject" for base in scope.owner.bases
    ):
        fields = {
            target.id: stmt.value
            for stmt in scope.owner.body
            if isinstance(stmt, ast.Assign)
            for target in stmt.targets
            if isinstance(target, ast.Name)
        }
        tag = fields.get("yaml_tag")
        if tag is not None and not (isinstance(tag, ast.Constant) and tag.value is None):
            selected = fields.get("yaml_loader")
            if selected is None:
                affected.update(defaults)
            else:
                registered = selected.elts if isinstance(selected, ast.List) else [selected]
                affected.update(_loader(scope, item, local) or "*" for item in registered)
    for node in scope.nodes:
        if isinstance(node, ast.Call):
            module, _, method = scope.resolve(node.func).rpartition(".")
            if module == "yaml" and method in _EXTENSION_METHODS:
                index = 2 if method in {"add_constructor", "add_multi_constructor"} else 3
                selected_arg = call_argument(node, index, "Loader")
                if selected_arg and not (
                    isinstance(selected_arg[1], ast.Constant) and selected_arg[1].value is None
                ):
                    affected.add(_loader(scope, selected_arg[1], local) or "*")
                elif any(isinstance(arg, ast.Starred) for arg in node.args) or any(
                    k.arg is None for k in node.keywords
                ):
                    affected.add("*")
                else:
                    affected.update(defaults)
            elif isinstance(node.func, ast.Attribute):
                owner = node.func.value
                if node.func.attr in _EXTENSION_METHODS:
                    if loader := _loader(scope, owner, local):
                        affected.add(loader)
                elif isinstance(owner, ast.Attribute) and owner.attr in _TABLES:
                    if loader := _loader(scope, owner.value, local):
                        affected.add(loader)
        elif isinstance(node, ast.Attribute) and node.attr in _TABLES:
            parent = scope.parents.get(node)
            if isinstance(node.ctx, ast.Store | ast.Del) or (
                isinstance(parent, ast.Subscript) and isinstance(parent.ctx, ast.Store | ast.Del)
            ):
                if receiver := _loader(scope, node.value, local):
                    affected.add(receiver)
    return affected


def decode_calls(source: bytes) -> tuple[dict[_Position, PythonDeserialization], list[str]]:
    if b"pickle" not in source and b"yaml" not in source and b"cPickle" not in source:
        return {}, []
    result = {}
    extensions: set[str] = set()
    for scope in python_scopes(source):
        local = LocalValues(scope)
        if b"yaml" in source:
            extensions.update(_extensions(scope, local))
        for node in scope.nodes:
            if (
                not isinstance(node, ast.Call)
                or node.end_lineno is None
                or node.end_col_offset is None
            ):
                continue
            api = scope.resolve(node.func)
            prefix, _, name = api.rpartition(".")
            if prefix in _PICKLE_MODULES and name in {"load", "loads"}:
                selected = call_argument(node, 0, "file" if name == "load" else "data")
                fact = PythonDeserialization(api=api, mode="pickle")
            elif api in _YAML_READERS:
                selected = call_argument(node, 0, "stream")
                if name.startswith("safe_"):
                    loader = "SafeLoader"
                elif name.startswith("unsafe_"):
                    loader = "UnsafeLoader"
                elif name.startswith("full_"):
                    loader = "FullLoader"
                elif selection := call_argument(node, 1, "Loader"):
                    loader = _loader(scope, selection[1], local)
                else:
                    loader = ""
                parent = scope.parents.get(node)
                lazy = name.endswith("_all")
                if lazy and isinstance(parent, ast.Expr):
                    continue  # An immediately discarded generator never reads its stream.
                consumes = (
                    isinstance(parent, ast.For)
                    and parent.iter is node
                    or isinstance(parent, ast.YieldFrom)
                    or isinstance(parent, ast.Call)
                    and parent.args == [node]
                    and not parent.keywords
                    and isinstance(parent.func, ast.Name)
                    and parent.func.id in {"list", "tuple", "next"}
                    and parent.func.id not in scope.hidden
                )
                fact = PythonDeserialization(
                    api=api,
                    mode=_LOADERS.get(loader, "unknown"),
                    loader=loader,
                    deferred=lazy and not consumes,
                )
            else:
                continue
            if selected is not None:
                fact.argument_index, operand = selected
                # A stream stored in a variable could have been changed since construction.
                if (
                    isinstance(operand, ast.Call)
                    and scope.resolve(operand.func) in {"io.BytesIO", "io.StringIO"}
                    and len(operand.args) == 1
                    and not operand.keywords
                ):
                    operand = operand.args[0]
                values = LiteralInputs(local, codecs=True).values(operand)
                if fact.mode == "pickle" and len(node.args) + len(node.keywords) > 1:
                    values = None
                if values is not None:
                    check = _passive_pickle if fact.mode == "pickle" else _passive_yaml
                    fact.passive_input = all(check(value) for value in values)
            result[(node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)] = fact
    return result, sorted(extensions)


def extended_loaders(files: list[FileAST]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for file in files:
        result[file.repository_id].update(file.python_yaml_extensions)
    return result


def reader(call: CallSite, file: FileAST) -> PythonDeserialization | None:
    if file.python_deserialization_resolved or call.python_deserialization:
        return call.python_deserialization
    # Legacy serialized ASTs have no import or loader information.
    api = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
    if api in {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"}:
        return PythonDeserialization(api=api, argument_index=0, mode="pickle")
    if api == "yaml.load":
        return PythonDeserialization(api=api, argument_index=0, mode="unknown")
    return None


def sink_operand(call: CallSite, file: FileAST) -> tuple[str, int] | None:
    fact = reader(call, file)
    if (
        fact
        and fact.mode in {"object", "pickle"}
        and not fact.passive_input
        and not fact.deferred
        and fact.argument_index is not None
    ):
        return fact.api, fact.argument_index
    return None
