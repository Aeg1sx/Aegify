"""Resolve selected values from local dictionaries, sequences and ConfigParsers."""

from __future__ import annotations

import ast
from collections import Counter, defaultdict

from aegify.models import PythonStoredRead
from aegify.scanner.python_scope import PythonScope, function_scopes, python_scopes


class LocalValues:
    def __init__(self, scope: PythonScope) -> None:
        self.scope = scope
        self.stores: dict[str, list[ast.Name]] = defaultdict(list)
        self.loads: dict[str, list[ast.Name]] = defaultdict(list)
        self.closed_over = {
            node.id
            for node in ast.walk(scope.owner)
            if isinstance(node, ast.Name) and node not in scope.parents
        }
        for node in scope.nodes:
            if isinstance(node, ast.Name):
                (self.loads if isinstance(node.ctx, ast.Load) else self.stores)[node.id].append(
                    node
                )
        for stores in self.stores.values():
            stores.sort(key=lambda node: (node.lineno, node.col_offset), reverse=True)

    def assigned(self, node: ast.expr) -> ast.expr | None:
        if not isinstance(node, ast.Name) or node.id in self.closed_over:
            return None
        stores = self.stores.get(node.id, [])
        if len(stores) != self.scope.definitions.get(node.id, 0):
            return None
        # A later conditional or compound write prevents using an earlier value.
        for name in stores:
            if name.lineno > node.lineno:
                if self.in_loop(node):
                    return None
                continue
            assignment = self.scope.parents[name]
            if isinstance(assignment, ast.Assign | ast.AnnAssign) and self.scope.precedes(
                assignment, node
            ):
                return assignment.value
            return None
        return None

    def unchanged(self, name: str, origin: ast.expr, use: ast.Call) -> bool:
        """Whether a tested local name retains its binding between the check and use."""
        if not isinstance(origin, ast.Name) or origin.id != name or name in self.closed_over:
            return False
        stores = self.stores.get(name, [])
        args = sum(isinstance(node, ast.arg) and node.arg == name for node in self.scope.nodes)
        if len(stores) + args != self.scope.definitions.get(name, 0):
            return False
        end = use.end_lineno or use.lineno
        return not any(origin.lineno <= store.lineno <= end for store in stores)

    def in_loop(self, node: ast.AST) -> bool:
        while node in self.scope.parents:
            node = self.scope.parents[node]
            if isinstance(node, ast.For | ast.AsyncFor | ast.While):
                return True
        return False

    def _sole_target(self, value: ast.expr) -> bool:
        statement = self.scope.parents.get(value)
        return isinstance(statement, ast.AnnAssign) or (
            isinstance(statement, ast.Assign) and len(statement.targets) == 1
        )

    def stored_source(self, use: ast.expr) -> tuple[ast.expr, int] | None:
        """Resolve the selected value of a local mapping, sequence or ConfigParser."""
        config = isinstance(use, ast.Call)
        if isinstance(use, ast.Call) and isinstance(use.func, ast.Attribute):
            if use.func.attr != "get" or len(use.args) != 2 or use.keywords:
                return None
            receiver = use.func.value
            section, option = use.args
            if not (
                isinstance(section, ast.Constant)
                and isinstance(section.value, str)
                and isinstance(option, ast.Constant)
                and isinstance(option.value, str)
            ):
                return None
            key = (section.value, option.value.lower())
        elif isinstance(use, ast.Subscript) and isinstance(use.ctx, ast.Load):
            receiver = use.value
            if _index(use.slice) is not None:
                return self._sequence_item(use)
            if not isinstance(use.slice, ast.Constant) or not isinstance(use.slice.value, str):
                return None
            key = ("", use.slice.value)
        else:
            return None
        return self._selected_entry(receiver, key, use, config=config)

    def _sequence_item(self, use: ast.Subscript) -> tuple[ast.expr, int] | None:
        receiver = use.value
        index = _index(use.slice)
        if (
            not isinstance(receiver, ast.Name)
            or index is None
            or receiver.id in self.closed_over
            or self.scope.definitions.get(receiver.id) != 1
            or self.in_loop(use)
            or len(self.loads[receiver.id]) > 256
        ):
            return None
        initial = self.assigned(receiver)
        if (
            not isinstance(initial, ast.List | ast.Tuple)
            or not self._sole_target(initial)
            or len(initial.elts) > 128
            or any(isinstance(i, ast.Starred) for i in initial.elts)
        ):
            return None
        elements = [(item, initial.lineno) for item in initial.elts]
        for read in sorted(self.loads[receiver.id], key=lambda n: (n.lineno, n.col_offset)):
            if read is receiver or not initial.lineno <= read.lineno <= use.lineno:
                continue
            parent = self.scope.parents[read]
            if isinstance(parent, ast.Subscript) and isinstance(parent.ctx, ast.Load):
                continue
            if isinstance(initial, ast.Tuple):
                return None
            if isinstance(parent, ast.Subscript) and isinstance(parent.ctx, ast.Store):
                slot = _index(parent.slice)
                assignment = self.scope.parents[parent]
                if (
                    slot is None
                    or not -len(elements) <= slot < len(elements)
                    or not isinstance(assignment, ast.Assign)
                    or len(assignment.targets) != 1
                    or not self.scope.precedes(assignment, use)
                ):
                    return None
                elements[slot] = (assignment.value, assignment.lineno)
                continue
            if not isinstance(parent, ast.Attribute):
                return None
            call = self.scope.parents[parent]
            if (
                not isinstance(call, ast.Call)
                or call.func is not parent
                or call.keywords
                or any(isinstance(i, ast.Starred) for i in call.args)
            ):
                return None
            stmt = self.scope.parents[call]
            if (
                not isinstance(stmt, ast.Expr | ast.Assign)
                or stmt.value is not call
                or not self.scope.precedes(stmt, use)
            ):
                return None
            if parent.attr == "append" and len(call.args) == 1:
                elements.append((call.args[0], stmt.lineno))
            elif parent.attr == "pop" and len(call.args) <= 1:
                slot = _index(call.args[0]) if call.args else -1
                if slot is None or not -len(elements) <= slot < len(elements):
                    return None
                elements.pop(slot)
            elif parent.attr == "insert" and len(call.args) == 2:
                slot = _index(call.args[0])
                if slot is None:
                    return None
                elements.insert(slot, (call.args[1], stmt.lineno))
            else:
                return None
            if len(elements) > 128:
                return None
        return elements[index] if -len(elements) <= index < len(elements) else None

    def mapping_item(self, receiver: ast.expr, key: str) -> tuple[ast.expr, int] | None:
        """Select the key read by a format field from its actual dictionary operand."""
        return self._selected_entry(receiver, ("", key), receiver, config=False)

    def _selected_entry(
        self, receiver: ast.expr, key: tuple[str, str], use: ast.expr, *, config: bool
    ) -> tuple[ast.expr, int] | None:
        if (
            not isinstance(receiver, ast.Name)
            or receiver.id in self.closed_over
            or self.scope.definitions.get(receiver.id) != 1
            or self.in_loop(use)
            or len(self.loads[receiver.id]) > 256
        ):
            return None
        initial = self.assigned(receiver)
        if initial is None or not self._sole_target(initial):
            return None
        selected: tuple[ast.expr, int] | None = None
        if config:
            if (
                not isinstance(initial, ast.Call)
                or initial.args
                or initial.keywords
                or self.scope.resolve(initial.func)
                not in {"configparser.ConfigParser", "configparser.RawConfigParser"}
            ):
                return None
        elif isinstance(initial, ast.Dict):
            for entry, value in zip(initial.keys, initial.values, strict=True):
                if not isinstance(entry, ast.Constant) or not isinstance(entry.value, str):
                    return None
                if entry.value == key[1]:
                    selected = (value, initial.lineno)
        else:
            return None
        for read in sorted(
            self.loads[receiver.id], key=lambda item: (item.lineno, item.col_offset)
        ):
            if read is receiver or read.lineno < initial.lineno or read.lineno > use.lineno:
                continue
            parent = self.scope.parents[read]
            if config and isinstance(parent, ast.Attribute):
                call = self.scope.parents[parent]
                if not isinstance(call, ast.Call) or call.func is not parent or call.keywords:
                    return None
                if parent.attr in {"get", "add_section"}:
                    continue
                if parent.attr != "set" or len(call.args) != 3:
                    return None
                sec, opt, value = call.args
                if not (
                    isinstance(sec, ast.Constant)
                    and isinstance(sec.value, str)
                    and isinstance(opt, ast.Constant)
                    and isinstance(opt.value, str)
                ):
                    return None
                if (sec.value, opt.value.lower()) != key:
                    continue
                statement = self.scope.parents[call]
            elif not config and isinstance(parent, ast.Subscript):
                if isinstance(parent.ctx, ast.Load):
                    continue
                if not isinstance(parent.slice, ast.Constant) or not isinstance(
                    parent.slice.value, str
                ):
                    return None
                if parent.slice.value != key[1]:
                    continue
                statement = self.scope.parents[parent]
                if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                    return None
                value = statement.value
            else:
                return None
            selected = (
                (value, statement.lineno)
                if isinstance(statement, ast.stmt) and self.scope.precedes(statement, use)
                else None
            )
        if selected and config:
            value = selected[0]
            if (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and "%" in value.value
            ):
                return None
        return selected

    def stored_literal(self, node: ast.expr) -> ast.Constant | None:
        source = self.stored_source(node)
        if source and isinstance(source[0], ast.Constant) and isinstance(source[0].value, str):
            return source[0]
        return None


def _file_config_reads(local: LocalValues) -> set[tuple[int, int]]:
    loads: dict[ast.Call, list[tuple[int, int]]] = defaultdict(list)
    reads = []
    for node in local.scope.nodes:
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        if method not in {
            "read",
            "read_file",
            "readfp",
            "get",
            "getint",
            "getfloat",
            "getboolean",
            "items",
        }:
            continue
        receiver: ast.expr | None = node.func.value
        for _ in range(12):
            if not isinstance(receiver, ast.Name):
                break
            receiver = local.assigned(receiver)
        if not isinstance(receiver, ast.Call) or local.scope.resolve(receiver.func) not in {
            "configparser.ConfigParser",
            "configparser.RawConfigParser",
        }:
            continue
        position = (node.lineno, node.col_offset)
        if method in {"read", "read_file", "readfp"}:
            loads[receiver].append(position)
        else:
            reads.append((receiver, position))
    return {
        position for receiver, position in reads if any(site < position for site in loads[receiver])
    }


def _index(node: ast.expr) -> int | None:
    sign = 1
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        node, sign = node.operand, -1
    if isinstance(node, ast.Constant) and type(node.value) is int and node.value.bit_length() <= 31:
        return sign * int(node.value)
    return None


def dict_get_calls(source: bytes) -> set[tuple[int, int, int, int]]:
    """Identify exact dict receivers without inferring their type from a method name."""
    if b"get" not in source or (b"{" not in source and b"dict" not in source):
        return set()
    positions = set()
    module_dicts: dict[str, int] = {}
    direct_functions: set[ast.stmt] = set()
    for scope in python_scopes(source):
        if isinstance(scope.owner, ast.Module):
            direct_functions = set(scope.owner.body)
            global_writes = {
                name
                for node in ast.walk(scope.owner)
                if isinstance(node, ast.Global)
                for name in node.names
            }
            for stmt in scope.owner.body:
                target: ast.expr
                if isinstance(stmt, ast.AnnAssign):
                    target = stmt.target
                elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                    target = stmt.targets[0]
                else:
                    continue
                if (
                    isinstance(target, ast.Name)
                    and isinstance(stmt.value, ast.Dict | ast.DictComp)
                    and scope.definitions.get(target.id) == 1
                    and target.id not in global_writes
                ):
                    module_dicts[target.id] = stmt.lineno
        local = None
        for node in scope.nodes:
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and node.end_lineno is not None
                and node.end_col_offset is not None
            ):
                continue
            location = node.lineno, node.col_offset, node.end_lineno, node.end_col_offset
            receiver = node.func.value
            if isinstance(receiver, ast.Name):
                if (
                    scope.owner in direct_functions
                    and receiver.id not in scope.definitions
                    and module_dicts.get(receiver.id, node.lineno) < node.lineno
                ):
                    positions.add(location)
                    continue
                local = local or LocalValues(scope)
                value = local.assigned(receiver)
            else:
                value = receiver
            if isinstance(value, ast.Dict | ast.DictComp) or (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "dict"
                and "dict" not in scope.hidden
                and "builtins.dict" not in scope.modified
            ):
                positions.add(location)
    return positions


def storage_facts(source: bytes) -> tuple[list[PythonStoredRead], set[tuple[int, int]]]:
    if b"{" not in source and b"[" not in source and b"ConfigParser" not in source:
        return [], set()
    facts = []
    external = set()
    for scope in function_scopes(source):
        if not isinstance(scope.owner, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        local = LocalValues(scope)
        if b"ConfigParser" in source:
            external.update(_file_config_reads(local))
        line_counts = Counter(n.lineno for n in scope.nodes if isinstance(n, ast.stmt))
        for node in scope.nodes:
            if (
                not isinstance(node, ast.Assign)
                or len(node.targets) != 1
                or not isinstance(target := node.targets[0], ast.Name)
                or line_counts[node.lineno] != 1
            ):
                continue
            stored = local.stored_source(node.value)
            if (
                not stored
                or line_counts[stored[1]] != 1
                or not isinstance(stored[0], ast.Name | ast.Constant)
            ):
                continue
            facts.append(
                PythonStoredRead(
                    function_line=scope.owner.lineno,
                    read_line=node.lineno,
                    target=target.id,
                    write_line=stored[1],
                    value_name=stored[0].id if isinstance(stored[0], ast.Name) else "",
                )
            )
    facts.sort(key=lambda fact: (fact.function_line, fact.read_line, fact.target))
    return facts, external
