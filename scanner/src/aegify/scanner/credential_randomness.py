"""Bind Python PRNG output to its credential use. Never execute the scanned source."""

from __future__ import annotations

import ast
from collections import Counter, defaultdict
from collections.abc import Iterator

from aegify.models import CredentialRandomness
from aegify.scanner.python_scope import PythonScope, function_scopes

_GENERATORS = {
    "randbytes",
    "getrandbits",
    "random",
    "randint",
    "randrange",
    "choice",
    "choices",
    "sample",
    "uniform",
    "triangular",
    "betavariate",
    "expovariate",
    "gammavariate",
    "gauss",
    "lognormvariate",
    "normalvariate",
    "vonmisesvariate",
    "paretovariate",
    "weibullvariate",
    "binomialvariate",
}
_ENCODERS = {"base64.b64encode", "base64.urlsafe_b64encode", "binascii.hexlify"}
_CREDENTIAL_FIELDS = {
    "sessionid",
    "session_id",
    "session_token",
    "auth_token",
    "csrf",
    "csrf_token",
    "access_token",
    "refresh_token",
    "reset_token",
    "remember_token",
    "api_key",
}
_CREDENTIAL_HEADERS = {"authorization", "x-csrf-token", "x-xsrf-token", "x-api-key"}
type Assignment = ast.Assign | ast.AnnAssign
type Slot = tuple[str, str, str]


def _literal(node: ast.expr) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


class _CredentialUses:
    def __init__(self, scope: PythonScope) -> None:
        self.scope = scope
        self.assignments: dict[str, Assignment] = {}
        self.writes: Counter[Slot] = Counter()
        self.mutated_maps: set[str] = set()
        for node in scope.nodes:
            if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
                for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                    if isinstance(target, ast.Name) and scope.definitions[target.id] == 1:
                        self.assignments[target.id] = node
            if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store | ast.Del):
                if slot := self.slot(node):
                    self.writes[slot] += 1
                elif isinstance(node.value, ast.Name):
                    self.mutated_maps.add(node.value.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and node.func.attr in {
                    "update",
                    "clear",
                    "pop",
                    "popitem",
                    "__setitem__",
                    "__delitem__",
                }:
                    self.mutated_maps.add(receiver.id)

    def slot(self, node: ast.expr) -> Slot | None:
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name):
            return None
        mapping, key = node.value.id, node.slice
        if self.scope.definitions.get(mapping, 0) > 1:
            return None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return mapping, "literal", key.value
        if isinstance(key, ast.Name) and self.scope.definitions.get(key.id, 0) <= 1:
            return mapping, "variable", key.id
        return None

    def assigned(self, node: ast.expr) -> ast.expr | None:
        if isinstance(node, ast.Name) and (assignment := self.assignments.get(node.id)):
            if self.scope.precedes(assignment, node):
                return assignment.value
        return None

    def generator(self, node: ast.expr, depth: int = 0) -> tuple[str, int] | None:
        if depth >= 16:
            return None
        if (value := self.assigned(node)) is not None:
            return self.generator(value, depth + 1)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            bounds = (node.slice.lower, node.slice.upper, node.slice.step)
            if all(
                v is None or isinstance(v, ast.Constant) and type(v.value) is int for v in bounds
            ):
                return self.generator(node.value, depth + 1)
        if not isinstance(node, ast.Call):
            return None
        callee = self.scope.resolve(node.func)
        owner, _, method = callee.rpartition(".")
        if owner == "random" and method in _GENERATORS:
            return callee, node.lineno
        if isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            instance = self.assigned(receiver) or receiver
            if (
                node.func.attr in _GENERATORS
                and isinstance(instance, ast.Call)
                and self.scope.resolve(instance.func) == "random.Random"
            ):
                return f"random.Random.{node.func.attr}", node.lineno
            if node.func.attr == "hex" and not node.args and not node.keywords:
                return self.generator(receiver, depth + 1)
        if len(node.args) == 1 and not node.keywords:
            builtin = (
                isinstance(node.func, ast.Name)
                and node.func.id in {"str", "repr", "hex"}
                and node.func.id not in self.scope.hidden
            )
            if builtin or callee in _ENCODERS | {"builtins.str", "builtins.repr", "builtins.hex"}:
                return self.generator(node.args[0], depth + 1)
        return None

    def incoming(self, node: ast.expr, depth: int = 0) -> bool:
        if depth >= 12:
            return False
        if (assigned := self.assigned(node)) is not None:
            return self.incoming(assigned, depth + 1)
        if isinstance(node, ast.Subscript):
            container, key = self.scope.resolve(node.value), node.slice
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
        ):
            container, key = self.scope.resolve(node.func.value), node.args[0]
        else:
            return False
        return container == "flask.request.cookies" or (
            container == "flask.request.headers" and _literal(key).lower() in _CREDENTIAL_HEADERS
        )

    def comparisons(self) -> Iterator[tuple[ast.expr, int]]:
        for node in self.scope.nodes:
            if (
                isinstance(node, ast.Compare)
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Eq | ast.NotEq)
            ):
                left, right = node.left, node.comparators[0]
            elif (
                isinstance(node, ast.Call)
                and self.scope.resolve(node.func)
                in {"hmac.compare_digest", "secrets.compare_digest"}
                and len(node.args) == 2
            ):
                left, right = node.args
            else:
                continue
            if self.incoming(left):
                yield right, node.lineno
            elif self.incoming(right):
                yield left, node.lineno

    def facts(self) -> Iterator[CredentialRandomness]:
        checked_slots: dict[Slot, list[tuple[ast.expr, int]]] = defaultdict(list)
        for operand, line in self.comparisons():
            read = self.assigned(operand) or operand
            if (slot := self.slot(read)) is not None:
                checked_slots[slot].append((read, line))
            if origin := self.generator(operand):
                yield CredentialRandomness(
                    generator=origin[0],
                    generator_line=origin[1],
                    use="request credential comparison",
                    use_line=line,
                )
        for node in self.scope.nodes:
            if not isinstance(node, ast.Assign | ast.AnnAssign) or node.value is None:
                continue
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                if not isinstance(target, ast.Subscript):
                    continue
                compare_line = None
                if (
                    self.scope.resolve(target.value) == "flask.session"
                    and _literal(target.slice).lower() in _CREDENTIAL_FIELDS
                ):
                    use = f"Flask session field {_literal(target.slice)!r}"
                elif (
                    (slot := self.slot(target)) in checked_slots
                    and slot is not None
                    and self.writes[slot] == 1
                    and slot[0] not in self.mutated_maps
                ):
                    # A freshly assigned local mapping cannot supply an earlier comparison.
                    compare_line = min(
                        (
                            line
                            for read, line in checked_slots[slot]
                            if slot[0] not in self.assignments or self.scope.precedes(node, read)
                        ),
                        default=None,
                    )
                    if compare_line is None:
                        continue
                    use = "stored value compared with a request credential"
                else:
                    continue
                if origin := self.generator(node.value):
                    yield CredentialRandomness(
                        generator=origin[0],
                        generator_line=origin[1],
                        use=use,
                        use_line=node.lineno,
                        comparison_line=compare_line,
                    )


def credential_uses(source: bytes) -> list[CredentialRandomness]:
    if b"random" not in source or b"flask" not in source:
        return []
    facts = [fact for scope in function_scopes(source) for fact in _CredentialUses(scope).facts()]
    return sorted(facts, key=lambda f: (f.use_line, f.generator_line, f.use))
