"""Bounded queries over the normalized program graph."""

from __future__ import annotations

from collections import deque

import networkx as nx

from aegify.graph_types import ProgramGraph

_ContextState = tuple[str, tuple[str, ...]]


class ContextQueryLimitError(RuntimeError):
    """A bounded context query exhausted a declared safety limit."""


class ProgramGraphQuery:
    """Security-oriented reachability with explicit overlay selection."""

    _INTERPROCEDURAL_CALL_KINDS = {
        "interprocedural-call",
        "interprocedural-bytecode-call",
    }
    _INTERPROCEDURAL_RETURN_KINDS = {
        "interprocedural-return",
        "interprocedural-bytecode-return",
        "interprocedural-bytecode-throw",
    }

    _STRUCTURAL_KINDS = {
        "contains-file",
        "contains-function",
        "declared-in",
        "declares",
        "defined-in",
        "definition",
        "member-of-module",
        "member-of-repository",
        "reference",
        "defines-package",
        "depends-on-package",
        "package-version-conflict",
        "publishes-jvm-artifact",
        "repository-publishes-jvm-artifact",
        "depends-on-jvm-artifact",
        "repository-depends-on-jvm-artifact",
        "resolved-jvm-provider",
        "resolved-jvm-provider-repository",
        "jvm-version-conflict",
    }

    def __init__(self, graph: ProgramGraph) -> None:
        self.graph = graph

    def reachable(
        self,
        source: str,
        target: str,
        overlays: set[str] | None = None,
    ) -> bool:
        projected = self._project(overlays)
        return (
            source in projected and target in projected and nx.has_path(projected, source, target)
        )

    def shortest_path(
        self,
        source: str,
        target: str,
        overlays: set[str] | None = None,
    ) -> list[str]:
        projected = self._project(overlays)
        if source not in projected or target not in projected:
            return []
        try:
            return nx.shortest_path(projected, source, target)
        except nx.NetworkXNoPath:
            return []

    def source_to_sink_paths(
        self,
        sources: set[str],
        sinks: set[str],
        max_paths: int = 100,
    ) -> list[list[str]]:
        projected = self._project(
            {
                "call",
                "dfg",
                "dtg",
                "framework",
                "icfg",
                "points-to",
                "semantic",
                "ssa",
                "taint",
            },
            excluded_kinds=self._STRUCTURAL_KINDS | {"module-dependency", "depends-on"},
        )
        paths: list[list[str]] = []
        for source in sorted(sources):
            for sink in sorted(sinks):
                if source not in projected or sink not in projected:
                    continue
                try:
                    paths.append(nx.shortest_path(projected, source, sink))
                except nx.NetworkXNoPath:
                    continue
                if len(paths) >= max_paths:
                    return paths
        return paths

    def context_balanced_reachable(
        self,
        source: str,
        target: str,
        overlays: set[str] | None = None,
        *,
        max_call_depth: int = 32,
        max_states: int = 100_000,
        require_empty_stack: bool = True,
    ) -> bool:
        """Return whether a bounded callsite-balanced path exists."""

        return bool(
            self.context_balanced_path(
                source,
                target,
                overlays,
                max_call_depth=max_call_depth,
                max_states=max_states,
                require_empty_stack=require_empty_stack,
            )
        )

    def context_balanced_path(
        self,
        source: str,
        target: str,
        overlays: set[str] | None = None,
        *,
        max_call_depth: int = 32,
        max_states: int = 100_000,
        require_empty_stack: bool = True,
    ) -> list[str]:
        """Find a bounded pushdown path with matched call/return identities.

        `interprocedural-call` and `interprocedural-bytecode-call` push their
        `callsite_id`. Normal, bytecode, and declared-exception return edges can
        only pop the same top identity. This prevents a shortest-path query
        from returning through another invocation of the same callee.
        """

        if max_call_depth < 0:
            raise ValueError("max_call_depth must be non-negative")
        if max_states <= 0:
            raise ValueError("max_states must be positive")
        if source not in self.graph or target not in self.graph:
            return []
        selected_overlays = overlays if overlays is not None else {"cfg", "icfg"}
        start: _ContextState = (source, ())
        pending: deque[_ContextState] = deque([start])
        predecessor: dict[_ContextState, _ContextState | None] = {start: None}
        explored = 0
        depth_truncated = False
        while pending and explored < max_states:
            state = pending.popleft()
            explored += 1
            node, stack = state
            if node == target and (not require_empty_stack or not stack):
                return self._reconstruct_context_path(state, predecessor)
            edges = sorted(
                self.graph.out_edges(node, keys=True, data=True),
                key=lambda edge: (
                    str(edge[1]),
                    str(edge[3].get("kind", "")),
                    str(edge[2]),
                ),
            )
            for _, next_node, _, data in edges:
                if selected_overlays and data.get("overlay") not in selected_overlays:
                    continue
                kind = str(data.get("kind", ""))
                next_stack = stack
                if kind in self._INTERPROCEDURAL_CALL_KINDS:
                    callsite_id = str(data.get("callsite_id", ""))
                    if not callsite_id:
                        continue
                    if len(stack) >= max_call_depth:
                        depth_truncated = True
                        continue
                    next_stack = (*stack, callsite_id)
                elif kind in self._INTERPROCEDURAL_RETURN_KINDS:
                    callsite_id = str(data.get("callsite_id", ""))
                    if not callsite_id or not stack or stack[-1] != callsite_id:
                        continue
                    next_stack = stack[:-1]
                next_state: _ContextState = (str(next_node), next_stack)
                if next_state in predecessor:
                    continue
                predecessor[next_state] = state
                pending.append(next_state)
        if pending:
            raise ContextQueryLimitError(f"context query exceeded max_states={max_states}")
        if depth_truncated:
            raise ContextQueryLimitError(f"context query exceeded max_call_depth={max_call_depth}")
        return []

    @staticmethod
    def _reconstruct_context_path(
        state: _ContextState,
        predecessor: dict[_ContextState, _ContextState | None],
    ) -> list[str]:
        path: list[str] = []
        current: _ContextState | None = state
        while current is not None:
            path.append(current[0])
            current = predecessor[current]
        path.reverse()
        return path

    def cross_repository_path(self, source: str, sink: str) -> list[str]:
        """Find a bounded path across call, data, API, semantic, or repo edges.

        Explicit repository dependency edges are deliberately last-resort,
        coarse evidence. Consumers should inspect each edge's ``fidelity``.
        """
        precise_overlays = {
            "attack-surface",
            "call",
            "dfg",
            "dtg",
            "framework",
            "icfg",
            "points-to",
            "semantic",
            "ssa",
            "taint",
        }
        precise = self._shortest_path(
            source,
            sink,
            precise_overlays,
            excluded_kinds=self._STRUCTURAL_KINDS | {"module-dependency", "depends-on"},
        )
        if precise:
            return precise

        source_repository = self._repository_id(source)
        sink_repository = self._repository_id(sink)
        if source_repository and source_repository != sink_repository:
            artifacts = self._typed_projection_kinds(
                {"depends-on-jvm-artifact", "resolved-jvm-provider"}
            )
            source_modules = self._modules_for_function(source)
            sink_modules = self._modules_for_function(sink)
            for source_module in sorted(source_modules):
                for sink_module in sorted(sink_modules):
                    artifact_path = self._nx_shortest_path(
                        artifacts,
                        source_module,
                        sink_module,
                    )
                    if artifact_path:
                        return [source, *artifact_path, sink]

            repository_artifacts = self._typed_projection_kinds(
                {
                    "repository-depends-on-jvm-artifact",
                    "resolved-jvm-provider-repository",
                }
            )
            source_node = f"repository:{source_repository}"
            sink_node = f"repository:{sink_repository}"
            artifact_path = self._nx_shortest_path(
                repository_artifacts,
                source_node,
                sink_node,
            )
            if artifact_path:
                return [source, *artifact_path, sink]

            repositories = self._typed_projection("depends-on")
            dependency_path = self._nx_shortest_path(repositories, source_node, sink_node)
            return [source, *dependency_path, sink] if dependency_path else []

        source_modules = self._modules_for_function(source)
        sink_modules = self._modules_for_function(sink)
        dependencies = self._typed_projection("module-dependency")
        best: list[str] = []
        for source_module in sorted(source_modules):
            for sink_module in sorted(sink_modules):
                if source_module == sink_module:
                    continue
                candidate = self._nx_shortest_path(dependencies, source_module, sink_module)
                if candidate and (not best or len(candidate) < len(best)):
                    best = candidate
        return [source, *best, sink] if best else []

    def _repository_id(self, node: str) -> str:
        value = self.graph.nodes.get(node, {}).get("repository_id")
        if value:
            return str(value)
        if node.startswith("repo:"):
            return node.split(":", 2)[1]
        if node.startswith("repository:"):
            return node.split(":", 1)[1]
        return ""

    def _modules_for_function(self, function: str) -> set[str]:
        files = {
            target
            for _, target, data in self.graph.out_edges(function, data=True)
            if data.get("kind") == "declared-in"
        }
        return {
            target
            for file_node in files
            for _, target, data in self.graph.out_edges(file_node, data=True)
            if data.get("kind") == "member-of-module"
        }

    def _typed_projection(self, kind: str) -> nx.DiGraph[str]:
        return self._typed_projection_kinds({kind})

    def _typed_projection_kinds(self, kinds: set[str]) -> nx.DiGraph[str]:
        graph: nx.DiGraph[str] = nx.DiGraph()
        for source, target, data in self.graph.edges(data=True):
            if data.get("kind") in kinds:
                graph.add_edge(source, target)
        return graph

    @staticmethod
    def _nx_shortest_path(graph: nx.DiGraph[str], source: str, target: str) -> list[str]:
        if source not in graph or target not in graph:
            return []
        try:
            return nx.shortest_path(graph, source, target)
        except nx.NetworkXNoPath:
            return []

    def _shortest_path(
        self,
        source: str,
        target: str,
        overlays: set[str] | None,
        *,
        excluded_kinds: set[str] | None = None,
    ) -> list[str]:
        projected = self._project(overlays, excluded_kinds=excluded_kinds)
        return self._nx_shortest_path(projected, source, target)

    def _project(
        self,
        overlays: set[str] | None,
        *,
        excluded_kinds: set[str] | None = None,
    ) -> nx.DiGraph[str]:
        graph: nx.DiGraph[str] = nx.DiGraph()
        graph.add_nodes_from(self.graph.nodes)
        for source, target, data in self.graph.edges(data=True):
            if excluded_kinds and data.get("kind") in excluded_kinds:
                continue
            if overlays is None or data.get("overlay") in overlays:
                graph.add_edge(source, target)
        return graph
