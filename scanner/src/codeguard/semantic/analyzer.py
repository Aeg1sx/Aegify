"""Compose SCIP and JVM fallback facts into a queryable graph."""

from __future__ import annotations

import json
from dataclasses import dataclass

import networkx as nx

from codeguard.graph_types import SemanticGraph
from codeguard.models import FileAST, SemanticAnalysisSummary, SemanticRelationship
from codeguard.scanner.workspace import WorkspaceManifest
from codeguard.semantic.jvm import (
    JvmBuildDiscoverer,
    JvmModuleGraphAnalyzer,
    JvmSemanticAnalyzer,
)
from codeguard.semantic.jvm_bytecode import JvmBytecodeImporter
from codeguard.semantic.jvm_dependencies import JvmDependencyAnalyzer
from codeguard.semantic.scip import ScipImport, ScipImporter, ScipImportError
from codeguard.semantic.scip_symbol import ScipPackageCoordinate, parse_scip_symbol


@dataclass
class SemanticGraphBundle:
    """The in-memory graph plus bounded result metadata."""

    graph: SemanticGraph
    summary: SemanticAnalysisSummary
    relationships: list[SemanticRelationship]


class SemanticAnalyzer:
    """Build a layered graph while preserving evidence provider and fidelity."""

    def __init__(self) -> None:
        self.scip = ScipImporter()
        self.jvm = JvmSemanticAnalyzer()
        self.jvm_modules = JvmModuleGraphAnalyzer()
        self.jvm_dependencies = JvmDependencyAnalyzer()
        self.jvm_bytecode = JvmBytecodeImporter()
        self.builds = JvmBuildDiscoverer()

    def analyze(
        self,
        manifest: WorkspaceManifest,
        file_asts: list[FileAST],
    ) -> SemanticGraphBundle:
        self.scip = ScipImporter(cache_dir=manifest.scip_cache_dir)
        graph: SemanticGraph = nx.MultiDiGraph()
        summary = SemanticAnalysisSummary(enabled=True)
        relationships: list[SemanticRelationship] = []
        providers: set[str] = set()
        scip_imports: list[ScipImport] = []
        bytecode_nodes: dict[str, dict[str, str | int | bool]] = {}

        for repository in manifest.repositories:
            projects = self.builds.discover(repository)
            summary.build_projects.extend(projects)
            module_graph = self.jvm_modules.analyze(
                repository,
                file_asts,
                projects,
            )
            summary.jvm_modules += len(module_graph.modules)
            summary.jvm_module_edges += module_graph.dependency_edges
            summary.warnings.extend(module_graph.warnings)
            if module_graph.modules:
                providers.add("codeguard-jvm-build")
            for module in module_graph.modules:
                graph.add_node(module, kind="jvm-module", provider="codeguard-jvm-build")
            relationships.extend(module_graph.relationships)
            indexes = list(repository.scip_indexes)
            if repository.scip_index is not None:
                indexes.insert(0, repository.scip_index)
            for index_path in dict.fromkeys(indexes):
                try:
                    imported = self.scip.load(index_path, repository.id)
                except ScipImportError as error:
                    summary.warnings.append(f"{repository.id}: {error}")
                    continue
                providers.add(imported.provider)
                scip_imports.append(imported)
                if imported.cache_hit:
                    summary.scip_cache_hits += 1
                else:
                    summary.scip_cache_misses += 1
                summary.scip_documents += imported.documents
                summary.scip_symbols += len(imported.symbols)
                summary.scip_occurrences += imported.occurrences
                for symbol in imported.symbols:
                    graph.add_node(symbol, kind="symbol", provider=imported.provider)
                relationships.extend(imported.relationships)
                relationships.extend(
                    self._function_scoped_scip_relationships(
                        imported.relationships,
                        file_asts,
                    )
                )

        package_relationships, packages = self._resolve_scip_packages(scip_imports, summary)
        if packages:
            providers.add("codeguard-scip-package-resolver")
        relationships.extend(package_relationships)
        for package in packages:
            graph.add_node(
                package.node_id,
                kind="scip-package",
                scheme=package.scheme,
                manager=package.manager,
                package_name=package.name,
                version=package.version,
                provider="codeguard-scip-package-resolver",
            )

        dependencies = self.jvm_dependencies.analyze(
            manifest.repositories,
            summary.build_projects,
        )
        summary.jvm_artifacts = len(dependencies.artifacts)
        summary.jvm_published_artifacts = dependencies.published_artifacts
        summary.jvm_declared_dependencies = dependencies.declared_dependencies
        summary.jvm_locked_dependencies = dependencies.locked_dependencies
        summary.jvm_dynamic_dependencies = dependencies.dynamic_dependencies
        summary.jvm_dependency_lockfiles = dependencies.lockfiles
        summary.jvm_version_catalogs = dependencies.version_catalogs
        summary.jvm_catalog_dependencies = dependencies.catalog_dependencies
        summary.jvm_exact_external_resolutions = dependencies.exact_external_resolutions
        summary.jvm_ambiguous_external_resolutions = dependencies.ambiguous_external_resolutions
        summary.jvm_unresolved_workspace_dependencies = (
            dependencies.unresolved_workspace_dependencies
        )
        summary.jvm_dependency_version_conflicts = dependencies.version_conflicts
        summary.warnings.extend(dependencies.warnings)
        if dependencies.artifacts:
            providers.add("codeguard-jvm-dependency")
        relationships.extend(dependencies.relationships)
        for artifact in dependencies.artifacts:
            graph.add_node(
                artifact.node_id,
                kind="jvm-artifact",
                manager=artifact.manager,
                group=artifact.group,
                artifact=artifact.artifact,
                version=artifact.version,
                provider="codeguard-jvm-dependency",
            )

        for repository in manifest.repositories:
            for classpath_artifact in repository.jvm_classpath_snapshots:
                try:
                    bytecode = self.jvm_bytecode.load(
                        classpath_artifact,
                        repository,
                    )
                except (
                    OSError,
                    UnicodeError,
                    ValueError,
                    json.JSONDecodeError,
                ) as error:
                    summary.jvm_classpath_snapshots += 1
                    summary.warnings.append(
                        f"{repository.id}: failed to import JVM classpath "
                        f"{classpath_artifact.path}: {error}"
                    )
                    continue
                providers.add("codeguard-jvm-bytecode")
                summary.jvm_classpath_snapshots += bytecode.summary.snapshots
                summary.jvm_classpath_entries += bytecode.summary.classpath_entries
                summary.jvm_classpath_entries_verified += bytecode.summary.entries_verified
                summary.jvm_classpath_entries_rejected += bytecode.summary.entries_rejected
                summary.jvm_bytecode_classes += bytecode.summary.bytecode_classes
                summary.jvm_bytecode_methods += bytecode.summary.bytecode_methods
                summary.jvm_bytecode_invokes += bytecode.summary.bytecode_invokes
                summary.jvm_bytecode_declared_exceptions += bytecode.summary.declared_exceptions
                summary.jvm_bytecode_unresolved_invokes += bytecode.summary.unresolved_invokes
                summary.jvm_bytecode_ambiguous_invokes += bytecode.summary.ambiguous_invokes
                summary.jvm_bytecode_virtual_invokes += bytecode.summary.virtual_invokes
                summary.jvm_bytecode_virtual_single_target += bytecode.summary.virtual_single_target
                summary.jvm_bytecode_virtual_ambiguous += bytecode.summary.virtual_ambiguous
                summary.jvm_bytecode_allocation_sites += bytecode.summary.allocation_sites
                summary.jvm_bytecode_rta_invokes += bytecode.summary.rta_invokes
                summary.jvm_bytecode_rta_targets += bytecode.summary.rta_targets
                summary.jvm_bytecode_invokedynamic_sites += bytecode.summary.invokedynamic_sites
                summary.jvm_bytecode_lambda_targets += bytecode.summary.lambda_targets
                summary.jvm_bytecode_unresolved_bootstraps += bytecode.summary.unresolved_bootstraps
                summary.warnings.extend(bytecode.summary.warnings)
                relationships.extend(bytecode.relationships)
                bytecode_nodes.update(bytecode.nodes)
                for node_id, attributes in bytecode.nodes.items():
                    graph.add_node(node_id, **attributes)

        source_bytecode_calls, resolved_calls, ambiguous_calls = (
            self.jvm_bytecode.link_source_calls(
                file_asts,
                bytecode_nodes,
                relationships,
            )
        )
        summary.jvm_bytecode_source_calls_resolved = resolved_calls
        summary.jvm_bytecode_source_calls_ambiguous = ambiguous_calls
        relationships.extend(source_bytecode_calls)

        jvm = self.jvm.analyze(file_asts)
        summary.jvm_types = len(jvm.types)
        summary.jvm_cha_edges = jvm.cha_edges
        summary.jvm_rta_edges = jvm.rta_edges
        summary.jvm_points_to_contexts = jvm.points_to_contexts
        summary.jvm_points_to_iterations = jvm.points_to_iterations
        summary.jvm_points_to_allocations = jvm.points_to_allocations
        summary.jvm_points_to_edges = jvm.points_to_edges
        summary.jvm_points_to_alias_edges = jvm.points_to_alias_edges
        summary.jvm_points_to_argument_edges = jvm.points_to_argument_edges
        summary.jvm_points_to_return_edges = jvm.points_to_return_edges
        summary.jvm_points_to_receiver_calls = jvm.points_to_receiver_calls
        summary.jvm_points_to_direct_calls = jvm.points_to_direct_calls
        summary.jvm_points_to_truncated = jvm.points_to_truncated
        summary.warnings.extend(jvm.warnings)
        if jvm.types:
            providers.add("codeguard-jvm-source")
        if (
            jvm.points_to_allocations
            or jvm.points_to_edges
            or jvm.points_to_receiver_calls
            or jvm.points_to_direct_calls
        ):
            providers.add("codeguard-jvm-points-to")
        for type_id in jvm.types:
            graph.add_node(type_id, kind="jvm-type", provider="codeguard-jvm-source")
        relationships.extend(jvm.relationships)

        for relationship in relationships:
            graph.add_node(relationship.source)
            graph.add_node(relationship.target)
            graph.add_edge(
                relationship.source,
                relationship.target,
                kind=relationship.kind,
                confidence=relationship.confidence,
                provider=relationship.provider,
                fidelity=relationship.fidelity,
                repository_id=relationship.repository_id,
                file_path=relationship.file_path,
                line=relationship.line,
                bytecode_offset=relationship.bytecode_offset,
                dispatch=relationship.dispatch,
                bootstrap_method=relationship.bootstrap_method,
                qualifier=relationship.qualifier,
                condition=relationship.condition,
            )

        summary.providers = sorted(providers)
        summary.node_count = graph.number_of_nodes()
        summary.edge_count = graph.number_of_edges()
        if any(provider.startswith("scip:") for provider in providers) and jvm.types:
            summary.fidelity = "hybrid"
        elif any(provider.startswith("scip:") for provider in providers):
            summary.fidelity = "compiler-index"
        elif jvm.types:
            summary.fidelity = "source-heuristic"
        else:
            summary.fidelity = "none"
        return SemanticGraphBundle(graph, summary, relationships)

    @staticmethod
    def _resolve_scip_packages(
        imports: list[ScipImport],
        summary: SemanticAnalysisSummary,
    ) -> tuple[list[SemanticRelationship], set[ScipPackageCoordinate]]:
        packages = {package for imported in imports for package in imported.packages}
        summary.scip_packages = len(packages)
        definitions: dict[str, set[str]] = {}
        references: set[tuple[str, str]] = set()
        package_definitions: dict[ScipPackageCoordinate, set[str]] = {}
        package_references: set[tuple[str, ScipPackageCoordinate]] = set()
        relationships: list[SemanticRelationship] = []
        seen: set[tuple[str, str, str]] = set()

        for imported in imports:
            for symbol in imported.defined_symbols:
                definitions.setdefault(symbol, set()).add(imported.repository_id)
                parsed = parse_scip_symbol(symbol)
                if parsed is not None and parsed.package is not None:
                    package_definitions.setdefault(parsed.package, set()).add(
                        imported.repository_id
                    )
            for symbol in imported.referenced_symbols:
                parsed = parse_scip_symbol(symbol)
                if parsed is None or parsed.package is None:
                    continue
                references.add((imported.repository_id, symbol))
                package_references.add((imported.repository_id, parsed.package))

        summary.scip_exact_external_resolutions = sum(
            1
            for repository_id, symbol in references
            if definitions.get(symbol, set()) - {repository_id}
        )
        summary.scip_unresolved_external_symbols = sum(
            1 for _, symbol in references if symbol not in definitions
        )

        for package, repositories in sorted(package_definitions.items()):
            for repository_id in sorted(repositories):
                SemanticAnalyzer._append_unique_relationship(
                    relationships,
                    seen,
                    source=f"repository:{repository_id}",
                    target=package.node_id,
                    kind="defines-package",
                    repository_id=repository_id,
                )
        for repository_id, package in sorted(package_references):
            SemanticAnalyzer._append_unique_relationship(
                relationships,
                seen,
                source=f"repository:{repository_id}",
                target=package.node_id,
                kind="depends-on-package",
                repository_id=repository_id,
            )

        families: dict[tuple[str, str, str], list[ScipPackageCoordinate]] = {}
        for package in packages:
            families.setdefault(package.family, []).append(package)
        conflicting = [
            sorted(versions)
            for versions in families.values()
            if len({item.version for item in versions}) > 1
        ]
        summary.scip_package_version_conflicts = len(conflicting)
        for versions in conflicting:
            for source in versions:
                for target in versions:
                    if source == target:
                        continue
                    SemanticAnalyzer._append_unique_relationship(
                        relationships,
                        seen,
                        source=source.node_id,
                        target=target.node_id,
                        kind="package-version-conflict",
                        repository_id="",
                    )
        return relationships, packages

    @staticmethod
    def _append_unique_relationship(
        relationships: list[SemanticRelationship],
        seen: set[tuple[str, str, str]],
        *,
        source: str,
        target: str,
        kind: str,
        repository_id: str,
    ) -> None:
        key = (source, target, kind)
        if key in seen:
            return
        seen.add(key)
        relationships.append(
            SemanticRelationship(
                source=source,
                target=target,
                kind=kind,
                repository_id=repository_id,
                confidence=1.0,
                provider="codeguard-scip-package-resolver",
                fidelity="compiler-index",
            )
        )

    @staticmethod
    def _function_scoped_scip_relationships(
        relationships: list[SemanticRelationship],
        file_asts: list[FileAST],
    ) -> list[SemanticRelationship]:
        """Lift occurrence lines from SCIP documents to enclosing functions.

        File-level navigation edges remain available, but security reachability
        must not imply that every function in a document references every SCIP
        symbol.  A compiler occurrence is therefore connected only to the
        narrowest source function containing its exact range line.
        """
        ast_by_document = {
            (ast.repository_id, ast.module_path): ast
            for ast in file_asts
            if ast.repository_id and ast.module_path
        }
        emitted: list[SemanticRelationship] = []
        seen: set[tuple[str, str, str, int]] = set()
        for relationship in relationships:
            if relationship.kind not in {"definition", "reference"}:
                continue
            ast = ast_by_document.get((relationship.repository_id, relationship.file_path))
            if ast is None or relationship.line <= 0:
                continue
            candidates = [
                function
                for function in ast.functions
                if function.line_start <= relationship.line <= function.line_end
            ]
            if not candidates:
                continue
            function = min(
                candidates,
                key=lambda item: (item.line_end - item.line_start, item.line_start),
            )
            function_id = function.symbol_id or function.qualified_name
            symbol = relationship.target
            kind = "symbol-definition" if relationship.kind == "definition" else "symbol-reference"
            key = (function_id, symbol, kind, relationship.line)
            if key not in seen:
                seen.add(key)
                emitted.append(
                    SemanticRelationship(
                        source=function_id,
                        target=symbol,
                        kind=kind,
                        repository_id=relationship.repository_id,
                        file_path=relationship.file_path,
                        line=relationship.line,
                        confidence=relationship.confidence,
                        provider=relationship.provider,
                        fidelity=relationship.fidelity,
                    )
                )
            if relationship.kind == "definition":
                reverse_key = (
                    symbol,
                    function_id,
                    "resolved-definition",
                    relationship.line,
                )
                if reverse_key not in seen:
                    seen.add(reverse_key)
                    emitted.append(
                        SemanticRelationship(
                            source=symbol,
                            target=function_id,
                            kind="resolved-definition",
                            repository_id=relationship.repository_id,
                            file_path=relationship.file_path,
                            line=relationship.line,
                            confidence=relationship.confidence,
                            provider=relationship.provider,
                            fidelity=relationship.fidelity,
                        )
                    )
        return emitted
