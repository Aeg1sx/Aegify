"""Call Graph builder using networkx for cross-file analysis."""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from aegify.graph_types import CodeGraph
from aegify.models import CallSite, FileAST, FunctionDef, Language
from aegify.semantic.signatures import (
    jvm_overload_score,
    normalize_jvm_type,
    type_compatibility,
)

logger = logging.getLogger(__name__)


# This is an executable support contract, not a marketing-only matrix.  The
# regression suite builds and resolves at least one real parser-produced call
# edge for every language in this set.
HEURISTIC_CALL_GRAPH_LANGUAGES: frozenset[Language] = frozenset(Language)


@dataclass
class CallGraphNode:
    """A node in the call graph representing a function/method."""

    qualified_name: str
    file_path: str
    line_start: int
    line_end: int
    is_entry_point: bool = False
    is_sink: bool = False
    decorators: list[str] = field(default_factory=list)
    symbol_id: str = ""
    repository_id: str = ""


class CallGraphBuilder:
    """Builds a cross-file call graph from parsed ASTs."""

    # Common entry point patterns
    ENTRY_POINT_PATTERNS: list[str] = [
        # Python web frameworks
        "@app.route",
        "@app.get",
        "@app.post",
        "@app.put",
        "@app.delete",
        "@router.get",
        "@router.post",
        "@router.put",
        "@router.delete",
        "@api_view",
        "@Controller",
        "@Get",
        "@Post",
        # Java Spring
        "@GetMapping",
        "@PostMapping",
        "@RequestMapping",
        # Express.js
        "app.get",
        "app.post",
        "router.get",
        "router.post",
        # Rust web frameworks
        "#[get",
        "#[post",
        "#[put",
        "#[delete",
        "#[patch",
        # Go net/http
        "HandleFunc",
        "Handle",
    ]

    # Common sink patterns
    SINK_PATTERNS: list[str] = [
        "execute",
        "raw",
        "query",
        "system",
        "popen",
        "exec",
        "eval",
        "run",
        "open",
        "write",
        "render_template_string",
        "innerHTML",
        "dangerouslySetInnerHTML",
    ]

    def __init__(self) -> None:
        self.graph: CodeGraph = nx.MultiDiGraph()
        self._function_index: dict[str, FunctionDef] = {}
        # Precise indexes used before any fuzzy/global fallback. They are
        # essential in multi-repo workspaces where short names collide.
        self._file_function_index: dict[tuple[str, str], list[str]] = {}
        self._name_index: dict[str, list[str]] = {}
        self._call_sites: list[CallSite] = []
        # Import resolution: maps (file_path, imported_name) -> qualified_name
        self._import_map: dict[tuple[str, str], list[str]] = {}
        # Suffix index: maps short_name -> [qualified_name, ...]
        self._suffix_index: dict[str, list[str]] = {}
        # Reachability cache: maps node -> set of reachable descendants
        self._reachability: dict[str, set[str]] = {}
        self.descriptor_callables = 0
        self._overload_resolved_sites: set[tuple[str, int, int, str]] = set()
        self._overload_ambiguous_sites: set[tuple[str, int, int, str]] = set()
        self._node_id_by_function: dict[int, str] = {}

    def build(self, file_asts: list[FileAST]) -> CodeGraph:
        """Build call graph from a list of parsed file ASTs."""
        self.graph = nx.MultiDiGraph()
        self._function_index = {}
        self._file_function_index = {}
        self._name_index = {}
        self._call_sites = []
        self._import_map = {}
        self._suffix_index = {}
        self._reachability = {}
        self.descriptor_callables = 0
        self._overload_resolved_sites = set()
        self._overload_ambiguous_sites = set()
        self._node_id_by_function = {}

        # Phase 1: Index all function definitions
        functions = self._unique_functions(file_asts)
        base_ids = [function.symbol_id or function.qualified_name for function in functions]
        duplicate_ids = {symbol_id for symbol_id, count in Counter(base_ids).items() if count > 1}
        for function in functions:
            base_id = function.symbol_id or function.qualified_name
            node_id = (
                f"file:{function.file_path}::{base_id}" if base_id in duplicate_ids else base_id
            )
            self._node_id_by_function[id(function)] = node_id
            self._register_function(function)
        self.descriptor_callables = len(self._function_index)

        # Phase 2: Build import resolution map
        self._build_import_map(file_asts)

        # Phase 3: Collect all call sites
        for ast in file_asts:
            self._call_sites.extend(ast.calls)

        # Phase 4: Resolve calls and build edges
        self._resolve_calls()

        # Phase 5: Build reachability cache for frequently-used queries
        self._build_reachability_cache()

        logger.info(
            "Call graph built: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )
        return self.graph

    @staticmethod
    def _unique_functions(file_asts: list[FileAST]) -> list[FunctionDef]:
        functions: list[FunctionDef] = []
        seen: set[int] = set()
        for ast in file_asts:
            for function in ast.functions:
                if id(function) not in seen:
                    seen.add(id(function))
                    functions.append(function)
            for cls in ast.classes:
                for method in cls.methods:
                    if id(method) not in seen:
                        seen.add(id(method))
                        functions.append(method)
        return functions

    def _node_id(self, function: FunctionDef) -> str:
        return self._node_id_by_function.get(
            id(function), function.symbol_id or function.qualified_name
        )

    def _register_function(self, func: FunctionDef) -> None:
        """Register a function in the index and add as a graph node."""
        node_id = self._node_id(func)
        node = CallGraphNode(
            qualified_name=func.qualified_name,
            file_path=func.file_path,
            line_start=func.line_start,
            line_end=func.line_end,
            is_entry_point=self._is_entry_point(func),
            is_sink=self._is_sink(func),
            decorators=func.decorators,
            symbol_id=node_id,
            repository_id=func.repository_id,
        )
        self.graph.add_node(node_id, data=node)
        self._function_index[node_id] = func
        for key in {
            (func.file_path, func.name),
            (func.file_path, func.qualified_name),
            (func.file_path, func.symbol_id),
        }:
            if not key[1]:
                continue
            self._file_function_index.setdefault(key, [])
            if node_id not in self._file_function_index[key]:
                self._file_function_index[key].append(node_id)
        self._name_index.setdefault(func.name, [])
        if node_id not in self._name_index[func.name]:
            self._name_index[func.name].append(node_id)

        # Preserve legacy single-repo lookup aliases without overwriting an
        # existing definition. Ambiguous resolution is handled by _name_index.
        if not func.symbol_id and func.name not in self._function_index:
            self._function_index[func.name] = func

        # Build suffix index: index all suffixes of the qualified name
        # e.g., "module.Class.method" -> index under "method", "Class.method"
        parts = func.qualified_name.split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix not in self._suffix_index:
                self._suffix_index[suffix] = []
            if node_id not in self._suffix_index[suffix]:
                self._suffix_index[suffix].append(node_id)

    def _build_import_map(self, file_asts: list[FileAST]) -> None:
        """Build a mapping from imported names to their qualified function names.

        For example, if routes.py has `from db import query_user`, and db.py defines
        `query_user`, this maps ("routes.py", "query_user") -> "query_user" (the one in db.py).
        """
        # Build a repository-scoped module-name -> file_path index.  Each file
        # receives language-native aliases (``pkg.mod``, ``pkg/mod``, and
        # ``pkg::mod``) so Python, JS/TS, JVM, Go, and Rust imports share one
        # deterministic resolver without falling back across repositories.
        module_to_files: dict[tuple[str, str], list[str]] = {}
        for ast in file_asts:
            for alias in self._module_aliases(ast):
                key = (ast.repository_id, alias)
                module_to_files.setdefault(key, [])
                if ast.file_path not in module_to_files[key]:
                    module_to_files[key].append(ast.file_path)

        # Build function-per-file index: file_path -> {func_name: qualified_name}
        file_functions: dict[str, dict[str, list[str]]] = {}
        for ast in file_asts:
            funcs: dict[str, list[str]] = {}
            for func in ast.functions:
                funcs.setdefault(func.name, []).append(self._node_id(func))
            for cls in ast.classes:
                for method in cls.methods:
                    funcs.setdefault(method.name, [])
                    method_id = self._node_id(method)
                    if method_id not in funcs[method.name]:
                        funcs[method.name].append(method_id)
            file_functions[ast.file_path] = funcs

        # Resolve imports
        for ast in file_asts:
            for imp in ast.imports:
                target_files = self._resolve_import_files(ast, imp.module, module_to_files)
                if not target_files:
                    continue
                # "from db import query_user, query_products"
                if imp.names:
                    for target_file in target_files:
                        imported_names = {
                            name: name for name in imp.names if name not in imp.bindings.values()
                        }
                        imported_names.update(imp.bindings)
                        for local_name, exported_name in imported_names.items():
                            if exported_name in file_functions[target_file]:
                                self._add_import_binding(
                                    ast.file_path,
                                    local_name,
                                    file_functions[target_file][exported_name],
                                )
                # "import db" -> later calls like db.query_user()
                elif imp.module:
                    alias = imp.alias or self._import_leaf(imp.module)
                    for target_file in target_files:
                        for func_name, qualified in file_functions[target_file].items():
                            self._add_import_binding(
                                ast.file_path,
                                f"{alias}.{func_name}",
                                qualified,
                            )
                        if alias in file_functions[target_file]:
                            self._add_import_binding(
                                ast.file_path,
                                alias,
                                file_functions[target_file][alias],
                            )
                        elif imp.alias and len(file_functions[target_file]) == 1:
                            only_targets = next(iter(file_functions[target_file].values()))
                            self._add_import_binding(ast.file_path, alias, only_targets)
                        # Java/Kotlin static imports and Rust ``use`` commonly
                        # encode the imported callable as the final path part.
                        imported_name = self._import_leaf(imp.module)
                        if imported_name in file_functions[target_file]:
                            self._add_import_binding(
                                ast.file_path,
                                imported_name,
                                file_functions[target_file][imported_name],
                            )

        if self._import_map:
            logger.info("Resolved %d cross-file import bindings", len(self._import_map))

    @staticmethod
    def _import_leaf(module: str) -> str:
        normalized = module.rstrip("/.").replace("::", "/").replace(".", "/")
        return normalized.rsplit("/", 1)[-1]

    @staticmethod
    def _module_aliases(ast: FileAST) -> set[str]:
        raw = (ast.module_path or ast.file_path).replace("\\", "/").lstrip("/")
        without_ext = os.path.splitext(raw)[0]
        parts = [part for part in without_ext.split("/") if part]
        aliases: set[str] = set()
        for index in range(len(parts)):
            suffix = parts[index:]
            if suffix and suffix[-1] == "index":
                suffix = suffix[:-1]
            if not suffix:
                continue
            aliases.update(
                {
                    suffix[-1],
                    "/".join(suffix),
                    ".".join(suffix),
                    "::".join(suffix),
                }
            )
        directories = parts[:-1]
        for index in range(len(directories)):
            suffix = directories[index:]
            aliases.update(
                {
                    suffix[-1],
                    "/".join(suffix),
                    ".".join(suffix),
                    "::".join(suffix),
                }
            )
        return aliases

    def _resolve_import_files(
        self,
        ast: FileAST,
        module: str,
        module_to_files: dict[tuple[str, str], list[str]],
    ) -> list[str]:
        normalized = module.strip().strip("'\"").replace("\\", "/")
        candidates = {
            normalized,
            normalized.removeprefix("./"),
            normalized.replace("::", "/"),
            normalized.replace("/", "."),
            normalized.replace("::", "."),
        }
        path_parts = [
            part
            for part in normalized.replace("::", "/").replace(".", "/").split("/")
            if part and part not in {"crate", "self", "super"}
        ]
        # A direct symbol/static import ends in a callable; try the containing
        # module/type as well (Rust ``crate::svc::run``, JVM ``Type.run``).
        for parts in (path_parts, path_parts[:-1]):
            if not parts:
                continue
            candidates.update(
                {
                    parts[-1],
                    "/".join(parts),
                    ".".join(parts),
                    "::".join(parts),
                }
            )
        results: list[str] = []
        for candidate in candidates:
            for value in module_to_files.get((ast.repository_id, candidate), []):
                if value not in results:
                    results.append(value)

        # Relative JS/TS and Python imports are resolved from the importing
        # file, including extensionless and directory-index forms.
        if normalized.startswith("."):
            base = (Path(ast.file_path).parent / normalized).resolve()
            for other_path in {path for paths in module_to_files.values() for path in paths}:
                other = Path(other_path).resolve()
                if other == base or other.with_suffix("") == base:
                    if other_path not in results:
                        results.append(other_path)
                elif other.stem == "index" and other.parent == base:
                    if other_path not in results:
                        results.append(other_path)
        return results

    def _add_import_binding(
        self,
        file_path: str,
        imported_name: str,
        targets: list[str],
    ) -> None:
        key = (file_path, imported_name)
        self._import_map.setdefault(key, [])
        for target in targets:
            if target not in self._import_map[key]:
                self._import_map[key].append(target)

    def _resolve_calls(self) -> None:
        """Resolve call sites to function definitions and create edges."""
        for call in self._call_sites:
            caller = call.caller_symbol_id or call.in_function
            # Resolve legacy caller names in their own file. Descriptor-bound
            # callers are assigned by the parser from the exact source range.
            if caller and (
                caller not in self._function_index
                or self._function_index[caller].file_path != call.file_path
            ):
                caller_candidates = self._file_function_index.get((call.file_path, caller), [])
                caller = caller_candidates[0] if len(caller_candidates) == 1 else caller
            if caller and caller in self._function_index:
                func = self._function_index[caller]
                caller = self._node_id(func)
            if caller is None:
                caller = f"<module:{call.file_path}>"
                if caller not in self.graph:
                    self.graph.add_node(
                        caller,
                        data=CallGraphNode(
                            qualified_name=caller,
                            file_path=call.file_path,
                            line_start=0,
                            line_end=0,
                        ),
                    )

            # Try to resolve the callee
            callee = self._resolve_callee(call)
            if callee is None:
                continue

            # Ensure caller node exists
            if caller not in self.graph:
                caller_func = self._function_index.get(caller)
                if caller_func:
                    self._register_function(caller_func)
                else:
                    self.graph.add_node(
                        caller,
                        data=CallGraphNode(
                            qualified_name=caller,
                            file_path=call.file_path,
                            line_start=0,
                            line_end=0,
                        ),
                    )

            self.graph.add_edge(
                caller,
                callee,
                call_site=call,
                line=call.line,
                file_path=call.file_path,
            )

    def _build_reachability_cache(self) -> None:
        """Pre-compute reachability for entry points to speed up path queries."""
        self._reachability = {}
        entry_points = self.get_entry_points()
        for ep in entry_points:
            try:
                self._reachability[ep] = set(nx.descendants(self.graph, ep))
            except nx.NetworkXError:
                self._reachability[ep] = set()

    def can_reach(self, source: str, target: str) -> bool:
        """Check if source can reach target using cached reachability data."""
        source_node = self._resolve_query_node(source)
        target_node = self._resolve_query_node(target)
        if source_node is None or target_node is None:
            return False
        if source_node in self._reachability:
            return target_node in self._reachability[source_node]
        # Fallback to nx.has_path for non-cached nodes
        try:
            return nx.has_path(self.graph, source_node, target_node)
        except nx.NodeNotFound, nx.NetworkXError:
            return False

    def _resolve_callee(self, call: CallSite) -> str | None:
        """Resolve one overload using locality, arity, and source type evidence."""
        callee_full = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        candidate_tiers: list[list[str]] = []
        for import_name in (callee_full, call.callee):
            imported = self._import_map.get((call.file_path, import_name), [])
            if imported:
                candidate_tiers.append(imported)
        if call.receiver:
            qualified = f"{call.receiver}.{call.callee}"
            local_qualified = self._file_function_index.get((call.file_path, qualified), [])
            if local_qualified:
                candidate_tiers.append(local_qualified)
        local = self._file_function_index.get((call.file_path, call.callee), [])
        if local:
            candidate_tiers.append(local)
        name_matches = self._name_index.get(call.callee, [])
        if name_matches:
            candidate_tiers.append(name_matches)
        suffix_matches = self._suffix_index.get(call.callee, [])
        if suffix_matches:
            candidate_tiers.append(suffix_matches)

        for candidates in candidate_tiers:
            resolved = self._select_overload(call, candidates)
            if resolved is not None:
                return resolved
            # A local/import tier with candidates but no unique compatible
            # descriptor is authoritative ambiguity; do not choose a global
            # same-named method from another repository.
            if candidates:
                return None
        return None

    def _select_overload(self, call: CallSite, candidates: list[str]) -> str | None:
        unique = list(dict.fromkeys(candidates))
        repository_id = call.repository_id
        caller_function = self._caller_function(call)
        if not repository_id and caller_function:
            repository_id = caller_function.repository_id
        if repository_id:
            unique = [
                candidate
                for candidate in unique
                if candidate in self._function_index
                and self._function_index[candidate].repository_id == repository_id
            ]
        functions = [
            self._function_index[candidate]
            for candidate in unique
            if candidate in self._function_index
        ]
        if not functions:
            return None
        overload_site = (call.file_path, call.line, call.column, call.callee)
        is_overloaded = len(functions) > 1

        if call.receiver_type:
            receiver = self._normalize_match_type(call.receiver_type)
            typed = [
                function
                for function in functions
                if function.class_name
                and self._normalize_match_type(function.class_name) == receiver
            ]
            if typed:
                functions = typed
        elif caller_function:
            caller_class = caller_function.class_name
            same_class = [
                function
                for function in functions
                if caller_class and function.class_name == caller_class
            ]
            if same_class:
                functions = same_class

        scored: list[tuple[int, FunctionDef]] = []
        for function in functions:
            score = self._overload_score(call, function)
            if score is not None:
                scored.append((score, function))
        if not scored:
            if is_overloaded:
                self._overload_ambiguous_sites.add(overload_site)
            return None
        best = max(score for score, _ in scored)
        winners = [function for score, function in scored if score == best]
        if len(winners) != 1:
            if is_overloaded:
                self._overload_ambiguous_sites.add(overload_site)
            return None
        if is_overloaded:
            self._overload_resolved_sites.add(overload_site)
            self._overload_ambiguous_sites.discard(overload_site)
        return self._node_id(winners[0])

    def _caller_function(self, call: CallSite) -> FunctionDef | None:
        if call.caller_symbol_id in self._function_index:
            function = self._function_index[call.caller_symbol_id]
            if function.file_path == call.file_path:
                return function
        for caller_name in (call.caller_symbol_id, call.in_function or ""):
            candidates = self._file_function_index.get((call.file_path, caller_name), [])
            if len(candidates) == 1:
                return self._function_index.get(candidates[0])
        return None

    @property
    def overload_calls_resolved(self) -> int:
        return len(self._overload_resolved_sites)

    @property
    def overload_calls_ambiguous(self) -> int:
        return len(self._overload_ambiguous_sites)

    def _overload_score(self, call: CallSite, function: FunctionDef) -> int | None:
        if function.language not in {Language.JAVA, Language.KOTLIN}:
            # The caller has already selected an authoritative locality/import
            # tier.  A single candidate in that tier is safe even if another
            # file or repository defines the same short name.
            return 0
        return jvm_overload_score(call, function)

    @classmethod
    def _type_compatibility(cls, actual: str, expected: str) -> int:
        return type_compatibility(actual, expected)

    @staticmethod
    def _normalize_match_type(value: str) -> str:
        return normalize_jvm_type(value)

    def _is_entry_point(self, func: FunctionDef) -> bool:
        """Check if a function is an entry point (route handler, etc.)."""
        for decorator in func.decorators:
            for pattern in self.ENTRY_POINT_PATTERNS:
                if pattern in decorator:
                    return True
        return False

    def _is_sink(self, func: FunctionDef) -> bool:
        """Check if a function is a potential security sink."""
        name_lower = func.name.lower()
        return any(sink in name_lower for sink in self.SINK_PATTERNS)

    def get_entry_points(self) -> list[str]:
        """Get all entry point nodes."""
        return [
            n
            for n, data in self.graph.nodes(data=True)
            if data and data.get("data") and data["data"].is_entry_point
        ]

    def get_sinks(self) -> list[str]:
        """Get all sink nodes."""
        return [
            n
            for n, data in self.graph.nodes(data=True)
            if data and data.get("data") and data["data"].is_sink
        ]

    def find_paths(self, source: str, target: str, max_depth: int = 10) -> list[list[str]]:
        """Find all simple paths from source to target."""
        source_node = self._resolve_query_node(source)
        target_node = self._resolve_query_node(target)
        if source_node is None or target_node is None:
            return []
        try:
            return list(nx.all_simple_paths(self.graph, source_node, target_node, cutoff=max_depth))
        except nx.NodeNotFound, nx.NetworkXError:
            return []

    def find_paths_to_sinks(self, entry_point: str) -> dict[str, list[list[str]]]:
        """Find all paths from an entry point to any sink."""
        sinks = self.get_sinks()
        result: dict[str, list[list[str]]] = {}
        for sink in sinks:
            paths = self.find_paths(entry_point, sink)
            if paths:
                result[sink] = paths
        return result

    def get_callers(self, func_name: str) -> list[str]:
        """Get all direct callers of a function."""
        node = self._resolve_query_node(func_name)
        if node is None:
            return []
        return [self._display_node(value) for value in self.graph.predecessors(node)]

    def get_callees(self, func_name: str) -> list[str]:
        """Get all functions called by the given function."""
        node = self._resolve_query_node(func_name)
        if node is None:
            return []
        return [self._display_node(value) for value in self.graph.successors(node)]

    def _resolve_query_node(self, value: str) -> str | None:
        if value in self.graph:
            return value
        candidates = self._suffix_index.get(value, [])
        if not candidates:
            candidates = self._name_index.get(value, [])
        return candidates[0] if len(candidates) == 1 else None

    def _display_node(self, node_id: str) -> str:
        function = self._function_index.get(node_id)
        if function is None:
            return node_id
        same_qualified = self._suffix_index.get(function.qualified_name, [])
        if len(same_qualified) == 1:
            return function.qualified_name
        return function.callable_name

    def get_call_chain(self, source: str, target: str) -> list[str] | None:
        """Get the shortest call chain between two functions."""
        source_node = self._resolve_query_node(source)
        target_node = self._resolve_query_node(target)
        if source_node is None or target_node is None:
            return None
        try:
            path = nx.shortest_path(self.graph, source_node, target_node)
            return [self._display_node(node) for node in path]
        except nx.NodeNotFound, nx.NetworkXNoPath:
            return None
