"""Call Graph builder using networkx for cross-file analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import networkx as nx

from aegify.graph_types import CodeGraph
from aegify.models import CallSite, FileAST, FunctionDef, Language
from aegify.semantic.signatures import (
    jvm_overload_score,
    normalize_jvm_type,
    type_compatibility,
)

logger = logging.getLogger(__name__)


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
        # Java Spring
        "@GetMapping",
        "@PostMapping",
        "@RequestMapping",
        # Express.js
        "app.get",
        "app.post",
        "router.get",
        "router.post",
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

        # Phase 1: Index all function definitions
        for ast in file_asts:
            for func in ast.functions:
                self._register_function(func)
            for cls in ast.classes:
                for method in cls.methods:
                    self._register_function(method)
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

    def _register_function(self, func: FunctionDef) -> None:
        """Register a function in the index and add as a graph node."""
        node_id = func.symbol_id or func.qualified_name
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
        }:
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
        # Build a module-name -> file_path index
        # e.g., "db" -> "/path/to/db.py", "utils" -> "/path/to/utils.py"
        import os

        module_to_file: dict[tuple[str, str], str] = {}
        for ast in file_asts:
            # Module name = filename without extension
            basename = os.path.splitext(os.path.basename(ast.file_path))[0]
            module_to_file[(ast.repository_id, basename)] = ast.file_path

            # Also store relative module paths for deeper imports
            # e.g., "pkg.db" for pkg/db.py
            parts = ast.file_path.replace("\\", "/").split("/")
            for i in range(len(parts) - 1, 0, -1):
                mod_parts = parts[i:]
                mod_parts[-1] = os.path.splitext(mod_parts[-1])[0]
                dotted = ".".join(mod_parts)
                module_to_file[(ast.repository_id, dotted)] = ast.file_path

        # Build function-per-file index: file_path -> {func_name: qualified_name}
        file_functions: dict[str, dict[str, list[str]]] = {}
        for ast in file_asts:
            funcs: dict[str, list[str]] = {}
            for func in ast.functions:
                funcs.setdefault(func.name, []).append(func.symbol_id or func.qualified_name)
            for cls in ast.classes:
                for method in cls.methods:
                    funcs.setdefault(method.name, [])
                    method_id = method.symbol_id or method.qualified_name
                    if method_id not in funcs[method.name]:
                        funcs[method.name].append(method_id)
            file_functions[ast.file_path] = funcs

        # Resolve imports
        for ast in file_asts:
            for imp in ast.imports:
                # "from db import query_user, query_products"
                if imp.names:
                    target_file = module_to_file.get((ast.repository_id, imp.module))
                    if target_file and target_file in file_functions:
                        for name in imp.names:
                            if name in file_functions[target_file]:
                                self._import_map[(ast.file_path, name)] = list(
                                    file_functions[target_file][name]
                                )
                # "import db" -> later calls like db.query_user()
                elif imp.module:
                    target_file = module_to_file.get((ast.repository_id, imp.module))
                    if target_file and target_file in file_functions:
                        alias = imp.alias or imp.module
                        for func_name, qualified in file_functions[target_file].items():
                            self._import_map[(ast.file_path, f"{alias}.{func_name}")] = list(
                                qualified
                            )

        if self._import_map:
            logger.info("Resolved %d cross-file import bindings", len(self._import_map))

    def _resolve_calls(self) -> None:
        """Resolve call sites to function definitions and create edges."""
        for call in self._call_sites:
            caller = call.caller_symbol_id or call.in_function
            # Resolve legacy caller names in their own file. Descriptor-bound
            # callers are assigned by the parser from the exact source range.
            if caller and caller not in self._function_index:
                caller_candidates = self._file_function_index.get((call.file_path, caller), [])
                caller = caller_candidates[0] if len(caller_candidates) == 1 else caller
            if caller and caller in self._function_index:
                func = self._function_index[caller]
                caller = func.symbol_id or func.qualified_name
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
        elif call.caller_symbol_id in self._function_index:
            caller_class = self._function_index[call.caller_symbol_id].class_name
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
        return winners[0].symbol_id or winners[0].qualified_name

    @property
    def overload_calls_resolved(self) -> int:
        return len(self._overload_resolved_sites)

    @property
    def overload_calls_ambiguous(self) -> int:
        return len(self._overload_ambiguous_sites)

    def _overload_score(self, call: CallSite, function: FunctionDef) -> int | None:
        if function.language not in {Language.JAVA, Language.KOTLIN}:
            return 0 if len(self._name_index.get(call.callee, [])) == 1 else None
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
