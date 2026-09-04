"""Main scanner engine orchestrating all analysis phases."""

from __future__ import annotations

import gc
import hashlib
import json
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegify.graph_types import CodeGraph

from collections.abc import Callable

from aegify.config import AegifyConfig
from aegify.models import (
    EvidenceProvenance,
    EvidenceState,
    FileAST,
    Finding,
    FindingDisposition,
    Language,
    RuntimeObservation,
    ScanProgress,
    ScanResult,
    ScanStatus,
    SemanticRelationship,
    Severity,
)
from aegify.rules.base import get_registry
from aegify.rules.registry import load_builtin_rules, load_custom_rules
from aegify.scanner.ast_parser import ASTParser
from aegify.scanner.attack_surface import AttackSurfaceAnalyzer
from aegify.scanner.call_graph import CallGraphBuilder
from aegify.scanner.context import ContextAnalyzer
from aegify.scanner.dataflow import DataflowAnalyzer
from aegify.scanner.endpoint_detector import EndpointDetector
from aegify.scanner.openapi_parser import find_openapi_files, parse_openapi_file
from aegify.storage import InMemoryBackend, StorageBackend
from aegify.storage.hasher import compute_file_hash

logger = logging.getLogger(__name__)


def _parse_file_worker(path_str: str) -> FileAST | None:
    """Top-level worker for parallel AST parsing (must be picklable)."""
    parser = ASTParser()
    return parser.parse_file(Path(path_str))


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class ScanEngine:
    """Orchestrates the full scan pipeline:
    AST parsing -> Call Graph -> Dataflow -> Rules -> Context -> (LLM) -> Report
    """

    # Phase weights for overall progress estimation (relative time proportions)
    _PHASE_WEIGHTS = [0.15, 0.10, 0.05, 0.10, 0.05, 0.40, 0.05, 0.10]
    _SEMANTIC_RESULT_LIMIT = 10_000

    def __init__(
        self,
        config: AegifyConfig | None = None,
        storage: StorageBackend | None = None,
        on_progress: Callable[[ScanProgress], None] | None = None,
    ) -> None:
        self.config = config or AegifyConfig()
        self.ast_parser = ASTParser()
        self.call_graph_builder = CallGraphBuilder()
        self.dataflow_analyzer = DataflowAnalyzer()
        self.endpoint_detector = EndpointDetector()
        self.attack_surface_analyzer = AttackSurfaceAnalyzer()
        self.context_analyzer = ContextAnalyzer(self.config.context)
        self.storage = storage or self._create_storage()
        self._on_progress = on_progress

        # Parallelization config
        workers = self.config.scan.max_workers
        self.max_workers = workers if workers > 0 else min(os.cpu_count() or 1, 8)

        # File hash cache for incremental builds
        self._file_hashes: dict[str, str] = {}
        # Last call graph (for external access after scan)
        self._last_call_graph: Any | None = None
        # Workspace semantic graph (SCIP + JVM fallback), kept out of the
        # default JSON payload so million-node indexes need not be duplicated.
        self._last_semantic_graph: Any | None = None
        self._last_program_graph: Any | None = None
        # Current scan progress (accessible externally for polling)
        self.current_progress: ScanProgress | None = None

        # Load rules
        load_builtin_rules()
        if self.config.rules.custom_rules:
            count = load_custom_rules(self.config.rules.custom_rules)
            logger.info("Loaded %d custom YAML rules", count)
        self.registry = get_registry()

    def _emit_progress(
        self,
        phase: int,
        phase_name: str,
        start_time: float,
        progress: float = 0.0,
        items_processed: int = 0,
        items_total: int = 0,
        message: str = "",
    ) -> None:
        """Emit a scan progress update."""
        elapsed = time.time() - start_time

        # Calculate overall progress from phase weights
        weight_before = sum(self._PHASE_WEIGHTS[: phase - 1])
        weight_current = self._PHASE_WEIGHTS[phase - 1] if phase <= len(self._PHASE_WEIGHTS) else 0
        overall = weight_before + weight_current * progress

        # Estimate ETA based on overall progress rate
        eta: float | None = None
        if overall > 0.01:
            eta = (elapsed / overall) * (1.0 - overall)

        prog = ScanProgress(
            phase=phase,
            phase_name=phase_name,
            phase_total=7,
            progress=progress,
            overall_progress=min(overall, 1.0),
            message=message or phase_name,
            items_processed=items_processed,
            items_total=items_total,
            elapsed_seconds=elapsed,
            eta_seconds=eta,
        )
        self.current_progress = prog
        if self._on_progress:
            try:
                self._on_progress(prog)
            except Exception:
                pass  # Don't let callback errors break the scan

    def scan(self, target: Path) -> ScanResult:
        """Run a full security scan on the target directory or file."""
        start_time = time.time()
        result = ScanResult(status=ScanStatus.RUNNING)

        try:
            # Phase 1: AST Parsing (with parallelization)
            logger.info("Phase 1: Parsing ASTs...")
            self._emit_progress(1, "Parsing ASTs", start_time)
            if target.is_file():
                ast = self.ast_parser.parse_file(target)
                file_asts = [ast] if ast else []
            else:
                file_asts = self._parse_directory_parallel(target)

            result.files_scanned = len(file_asts)
            self._emit_progress(
                1,
                "Parsing ASTs",
                start_time,
                1.0,
                len(file_asts),
                len(file_asts),
                f"Parsed {len(file_asts)} files",
            )
            if not file_asts:
                logger.warning("No files to scan")
                result.status = ScanStatus.COMPLETED
                return result

            self._run_pipeline(file_asts, target, result, start_time)

        except Exception:
            logger.exception("Scan failed")
            result.status = ScanStatus.FAILED

        result.duration_seconds = time.time() - start_time
        logger.info(
            "Scan completed in %.1fs: %d findings (%s)",
            result.duration_seconds,
            len(result.findings),
            result.findings_count,
        )
        return result

    def scan_files(self, repo_root: Path, files: list[Path]) -> ScanResult:
        """Scan a specific set of files (for PR-based scanning).

        Parses only the given files, then runs the full analysis pipeline.
        """
        start_time = time.time()
        result = ScanResult(status=ScanStatus.RUNNING)

        try:
            logger.info("Phase 1: Parsing %d specific files...", len(files))
            self._emit_progress(1, "Parsing ASTs", start_time)

            file_asts: list[FileAST] = []
            for f in files:
                ast = self.ast_parser.parse_file(f, repository_root=repo_root)
                if ast is not None:
                    file_asts.append(ast)

            result.files_scanned = len(file_asts)
            self._emit_progress(
                1,
                "Parsing ASTs",
                start_time,
                1.0,
                len(file_asts),
                len(file_asts),
                f"Parsed {len(file_asts)} files",
            )
            if not file_asts:
                logger.warning("No files to scan")
                result.status = ScanStatus.COMPLETED
                return result

            self._run_pipeline(file_asts, repo_root, result, start_time)

        except Exception:
            logger.exception("Scan failed")
            result.status = ScanStatus.FAILED

        result.duration_seconds = time.time() - start_time
        logger.info(
            "Scan completed in %.1fs: %d findings (%s)",
            result.duration_seconds,
            len(result.findings),
            result.findings_count,
        )
        return result

    def scan_workspace(self, manifest_path: Path) -> ScanResult:
        """Scan multiple repositories as one collision-safe analysis workspace."""
        from aegify.scanner.workspace import WorkspaceManifest

        start_time = time.time()
        result = ScanResult(status=ScanStatus.RUNNING)
        try:
            manifest = WorkspaceManifest.load(manifest_path)
            result.repository = manifest.name
            self._emit_progress(1, "Parsing workspace ASTs", start_time)
            workspace_files: list[tuple[Path, str, Path]] = []
            for repository in manifest.repositories:
                excludes = set(self.config.scan.exclude + repository.exclude)
                files = self.ast_parser._collect_files(repository.path, excludes)
                for file_path in files:
                    workspace_files.append((file_path, repository.id, repository.path))

            file_asts = self._parse_workspace_files(workspace_files)

            from aegify.semantic import SemanticAnalyzer

            semantic = SemanticAnalyzer().analyze(manifest, file_asts)
            self._last_semantic_graph = semantic.graph
            result.semantic_analysis = semantic.summary
            result.semantic_relationships = semantic.relationships[: self._SEMANTIC_RESULT_LIMIT]
            result.semantic_analysis.relationships_emitted = len(result.semantic_relationships)
            if len(semantic.relationships) > self._SEMANTIC_RESULT_LIMIT:
                result.semantic_analysis.relationships_truncated = True
                result.semantic_analysis.warnings.append(
                    "semantic relationships in ScanResult were capped at "
                    f"{self._SEMANTIC_RESULT_LIMIT}; export the semantic graph "
                    "artifact for the complete edge set"
                )

            from aegify.adapters import ExternalAnalysisBundle, ExternalAnalysisImporter

            external = ExternalAnalysisBundle()
            importer = ExternalAnalysisImporter()
            for repository in manifest.repositories:
                for analysis_artifact in repository.analysis_artifacts:
                    try:
                        external.merge(importer.load(analysis_artifact, repository))
                    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
                        external.summary.enabled = True
                        external.summary.artifacts += 1
                        external.summary.warnings.append(
                            f"failed to import {analysis_artifact.path}: {error}"
                        )
            result.external_analysis = external.summary

            from aegify.runtime import RuntimeEvidenceBundle, RuntimeEvidenceImporter

            runtime = RuntimeEvidenceBundle()
            runtime_importer = RuntimeEvidenceImporter()
            for repository in manifest.repositories:
                for runtime_artifact in repository.runtime_artifacts:
                    try:
                        runtime.merge(runtime_importer.load(runtime_artifact, repository))
                    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
                        runtime.summary.enabled = True
                        runtime.summary.artifacts += 1
                        runtime.summary.warnings.append(
                            f"failed to import {runtime_artifact.path}: {error}"
                        )
            result.runtime_evidence = runtime.summary
            result.runtime_observations = runtime.observations

            result.files_scanned = len(file_asts)
            self._emit_progress(
                1,
                "Parsing workspace ASTs",
                start_time,
                1.0,
                len(file_asts),
                len(file_asts),
                f"Parsed {len(file_asts)} files from {len(manifest.repositories)} repositories",
            )
            if file_asts:
                self._run_pipeline(
                    file_asts,
                    manifest_path.parent,
                    result,
                    start_time,
                    repository_roots=[r.path for r in manifest.repositories],
                    repository_ids_by_root={r.path.resolve(): r.id for r in manifest.repositories},
                    semantic_relationships=(
                        semantic.relationships + external.relationships + runtime.relationships
                    ),
                    semantic_graph=semantic.graph,
                    repository_dependencies={
                        repository.id: repository.depends_on for repository in manifest.repositories
                    },
                    runtime_observations=runtime.observations,
                )
                for finding in external.findings:
                    finding.provenance.workspace_snapshot = result.workspace_snapshot
                result.findings = self._filter_findings(
                    result.findings + external.findings,
                    self._parse_severity_threshold(),
                )
                result.findings.sort(
                    key=lambda finding: (
                        SEVERITY_ORDER.get(finding.severity, 99),
                        -finding.confidence,
                    )
                )
            else:
                result.findings = self._filter_findings(
                    external.findings,
                    self._parse_severity_threshold(),
                )
                result.status = ScanStatus.COMPLETED
        except Exception:
            logger.exception("Workspace scan failed")
            result.status = ScanStatus.FAILED

        result.duration_seconds = time.time() - start_time
        return result

    def export_semantic_graph(self, path: Path) -> None:
        """Stream the complete semantic graph as newline-delimited JSON."""
        if self._last_semantic_graph is None:
            raise ValueError("no workspace semantic graph is available")
        self._export_graph_jsonl(self._last_semantic_graph, path)

    def export_program_graph(self, path: Path) -> None:
        """Stream the normalized CFG/DFG/SSA/security graph as JSONL."""
        if self._last_program_graph is None:
            raise ValueError("no program graph is available")
        self._export_graph_jsonl(self._last_program_graph, path)

    @staticmethod
    def _export_graph_jsonl(graph: Any, path: Path) -> None:
        with path.open("w", encoding="utf-8") as stream:
            for node_id, attributes in graph.nodes(data=True):
                stream.write(
                    json.dumps(
                        {"record": "node", "id": node_id, **attributes},
                        sort_keys=True,
                    )
                    + "\n"
                )
            for source, target, key, attributes in graph.edges(keys=True, data=True):
                stream.write(
                    json.dumps(
                        {
                            "record": "edge",
                            "source": source,
                            "target": target,
                            "key": key,
                            **attributes,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )

    def _parse_workspace_files(
        self,
        workspace_files: list[tuple[Path, str, Path]],
    ) -> list[FileAST]:
        """Parse workspace files in parallel, then attach repository identity."""
        if not workspace_files:
            return []

        if len(workspace_files) <= 3 or self.max_workers <= 1:
            return self._parse_workspace_files_sequential(workspace_files)

        logger.info(
            "Parsing %d workspace files with %d workers",
            len(workspace_files),
            self.max_workers,
        )
        results: list[FileAST] = []
        batch_size = 5000
        for batch_start in range(0, len(workspace_files), batch_size):
            batch = workspace_files[batch_start : batch_start + batch_size]
            try:
                with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                    parsed = executor.map(
                        _parse_file_worker,
                        [str(file_path) for file_path, _, _ in batch],
                    )
                    for ast, (_, repository_id, repository_root) in zip(parsed, batch, strict=True):
                        if ast is None:
                            continue
                        self.ast_parser.apply_repository_context(
                            ast,
                            repository_id=repository_id,
                            repository_root=repository_root,
                        )
                        results.append(ast)
            except (OSError, PermissionError) as error:
                logger.warning(
                    "Process-based workspace parsing unavailable (%s); using sequential parsing",
                    error,
                )
                results.extend(self._parse_workspace_files_sequential(batch))
            if len(workspace_files) > batch_size:
                gc.collect()
        return results

    def _parse_workspace_files_sequential(
        self,
        workspace_files: list[tuple[Path, str, Path]],
    ) -> list[FileAST]:
        results: list[FileAST] = []
        for file_path, repository_id, repository_root in workspace_files:
            ast = self.ast_parser.parse_file(
                file_path,
                repository_id=repository_id,
                repository_root=repository_root,
            )
            if ast is not None:
                results.append(ast)
        return results

    def _run_pipeline(
        self,
        file_asts: list[FileAST],
        target: Path,
        result: ScanResult,
        start_time: float,
        repository_roots: list[Path] | None = None,
        repository_ids_by_root: dict[Path, str] | None = None,
        semantic_relationships: list[SemanticRelationship] | None = None,
        semantic_graph: Any | None = None,
        repository_dependencies: dict[str, list[str]] | None = None,
        runtime_observations: list[RuntimeObservation] | None = None,
    ) -> None:
        """Run phases 2-7 of the scan pipeline on pre-parsed file ASTs."""
        roots = repository_roots or [target if target.is_dir() else target.parent]
        result.workspace_snapshot = self._compute_workspace_snapshot(
            file_asts, roots, repository_ids_by_root
        )
        # Phase 2: Call Graph
        logger.info("Phase 2: Building call graph...")
        self._emit_progress(2, "Building call graph", start_time)
        call_graph = self.call_graph_builder.build(file_asts)
        self._overlay_semantic_dispatch(call_graph, semantic_relationships or [])
        self._last_call_graph = call_graph

        from aegify.ir import ProgramGraphBuilder

        program = ProgramGraphBuilder().build(file_asts)
        (
            interprocedural_call_edges,
            interprocedural_return_edges,
            interprocedural_callsites,
        ) = self._overlay_program_graph(
            program.graph,
            call_graph,
            semantic_relationships or [],
            semantic_graph,
        )
        self._overlay_repository_reachability(
            program.graph,
            file_asts,
            repository_dependencies or {},
        )
        from aegify.framework import SpringModelAnalyzer

        framework = SpringModelAnalyzer().analyze(
            file_asts,
            repository_dependencies or {},
            semantic_relationships or [],
        )
        self._overlay_framework_graph(
            program.graph,
            call_graph,
            framework.relationships,
        )
        self._last_program_graph = program.graph
        program.summary.callable_descriptors = self.call_graph_builder.descriptor_callables
        program.summary.overload_calls_resolved = self.call_graph_builder.overload_calls_resolved
        program.summary.overload_calls_ambiguous = self.call_graph_builder.overload_calls_ambiguous
        program.summary.interprocedural_callsites = interprocedural_callsites
        program.summary.interprocedural_call_edges = interprocedural_call_edges
        program.summary.interprocedural_return_edges = interprocedural_return_edges
        program.summary.interprocedural_bytecode_call_edges = sum(
            1
            for _, _, data in program.graph.edges(data=True)
            if data.get("kind") == "interprocedural-bytecode-call"
        )
        program.summary.interprocedural_bytecode_return_edges = sum(
            1
            for _, _, data in program.graph.edges(data=True)
            if data.get("kind") == "interprocedural-bytecode-return"
        )
        program.summary.interprocedural_bytecode_throw_edges = sum(
            1
            for _, _, data in program.graph.edges(data=True)
            if data.get("kind") == "interprocedural-bytecode-throw"
        )
        result.program_graph = program.summary
        result.framework_analysis = framework.summary
        self._emit_progress(
            2,
            "Building call graph",
            start_time,
            1.0,
            message=f"{call_graph.number_of_nodes()} nodes, {call_graph.number_of_edges()} edges",
        )

        # Phase 3: Endpoint Detection
        logger.info("Phase 3: Detecting endpoints...")
        self._emit_progress(3, "Detecting endpoints", start_time)
        from aegify.models import EndpointInfo, EndpointParam

        detected_endpoints = self.endpoint_detector.detect(file_asts)
        result.endpoints = [
            EndpointInfo(
                path=ep.path,
                method=ep.method,
                handler_function=ep.handler_function,
                file_path=ep.file_path,
                line_start=ep.line_start,
                line_end=ep.line_end,
                framework=ep.framework,
                auth_required=ep.auth_required,
                parameters=[
                    EndpointParam(name=p.name, location=p.location, param_type=p.param_type)
                    for p in ep.parameters
                ],
                middleware=ep.middleware,
                repository_id=ep.repository_id,
            )
            for ep in detected_endpoints
        ]
        self._emit_progress(
            3,
            "Detecting endpoints",
            start_time,
            1.0,
            len(detected_endpoints),
            len(detected_endpoints),
            f"{len(detected_endpoints)} endpoints detected",
        )

        # OpenAPI/Swagger endpoint detection
        openapi_seen: set[tuple[str, str]] = {(ep.path, ep.method) for ep in detected_endpoints}
        for repository_root in roots:
            openapi_files = find_openapi_files(repository_root)
            if openapi_files:
                logger.info("Found %d OpenAPI spec files", len(openapi_files))
                for spec_file in openapi_files:
                    for ep in parse_openapi_file(spec_file):
                        key = (ep.path, ep.method)
                        if key not in openapi_seen:
                            openapi_seen.add(key)
                            detected_endpoints.append(ep)
                            result.endpoints.append(
                                EndpointInfo(
                                    path=ep.path,
                                    method=ep.method,
                                    handler_function=ep.handler_function,
                                    file_path=ep.file_path,
                                    line_start=0,
                                    line_end=0,
                                    framework="OpenAPI",
                                    auth_required=ep.auth_required,
                                    parameters=[
                                        EndpointParam(
                                            name=p.name,
                                            location=p.location,
                                            param_type=p.param_type,
                                        )
                                        for p in ep.parameters
                                    ],
                                    middleware=ep.middleware,
                                    repository_id=(
                                        (repository_ids_by_root or {}).get(
                                            repository_root.resolve(), ""
                                        )
                                        or self._repository_id_for_file(spec_file, file_asts)
                                    ),
                                )
                            )
        logger.info("Total endpoints after OpenAPI merge: %d", len(result.endpoints))

        # Correlate frontend clients and Spring Cloud Gateway configuration with
        # backend endpoints before serialisation/reporting.
        frontend_calls, gateway_routes, attack_links = self.attack_surface_analyzer.analyze(
            roots,
            file_asts,
            result.endpoints,
            repository_ids_by_root,
        )
        result.frontend_calls = frontend_calls
        result.gateway_routes = gateway_routes
        result.attack_surface_links = attack_links
        result.runtime_observations = runtime_observations or []
        for observation in result.runtime_observations:
            observation.provenance.workspace_snapshot = result.workspace_snapshot
        result.runtime_evidence.endpoint_links = self._link_runtime_observations(result)
        self._attach_attack_surface_provenance(result)
        self._overlay_attack_surface_graph(self._last_program_graph, result)

        # Enrich call graph with endpoint info (both detected and OpenAPI)
        from aegify.scanner.call_graph import CallGraphNode as CGNode

        ep_count = 0
        for ep in detected_endpoints:
            # Try to match handler function to call graph node
            matched = False
            if ep.handler_function in call_graph:
                node_data = call_graph.nodes[ep.handler_function].get("data")
                if node_data:
                    node_data.is_entry_point = True
                    matched = True

            # Workspace graphs use repository-qualified node IDs while endpoint
            # handlers keep human-readable names. Match on identity metadata.
            if not matched:
                for graph_node in call_graph.nodes():
                    node_data = call_graph.nodes[graph_node].get("data")
                    if not node_data:
                        continue
                    if (
                        node_data.qualified_name == ep.handler_function
                        and node_data.file_path == ep.file_path
                    ):
                        node_data.is_entry_point = True
                        matched = True
                        break

            # For OpenAPI endpoints, try fuzzy matching by operation ID
            if not matched and ep.framework == "OpenAPI":
                # Try matching operationId to function names in graph
                op_id = ep.handler_function.lower().replace("-", "_")
                for node in call_graph.nodes():
                    node_lower = node.lower().rsplit(".", 1)[-1]
                    if node_lower == op_id:
                        nd = call_graph.nodes[node].get("data")
                        if nd:
                            nd.is_entry_point = True
                            matched = True
                            break

            # Add as virtual entry point node if no match found
            if not matched and ep.framework == "OpenAPI":
                vnode_name = f"<openapi:{ep.method}:{ep.path}>"
                if vnode_name not in call_graph:
                    call_graph.add_node(
                        vnode_name,
                        data=CGNode(
                            qualified_name=vnode_name,
                            file_path=ep.file_path,
                            line_start=0,
                            line_end=0,
                            is_entry_point=True,
                        ),
                    )
                    ep_count += 1

            if matched:
                ep_count += 1

        if ep_count > 0:
            logger.info("Marked %d endpoints as call graph entry points", ep_count)

        # Phase 4: Dataflow / Taint Analysis
        logger.info("Phase 4: Running taint analysis...")
        self._emit_progress(4, "Running taint analysis", start_time)
        taint_flows = self.dataflow_analyzer.analyze(
            file_asts,
            call_graph,
            self._last_program_graph,
        )
        result.taint_analysis = self.dataflow_analyzer.summary
        result.program_graph.interprocedural_taint_edges = self._overlay_taint_graph(
            self._last_program_graph,
            taint_flows,
        )
        self._emit_progress(
            4,
            "Running taint analysis",
            start_time,
            1.0,
            len(taint_flows),
            len(taint_flows),
            f"{len(taint_flows)} taint flows found",
        )

        # Phase 5: Load context
        logger.info("Phase 5: Loading context...")
        self._emit_progress(5, "Loading context", start_time)
        self.context_analyzer.load(file_asts)
        self._emit_progress(5, "Loading context", start_time, 1.0)

        # Phase 6: Rule Evaluation (the heaviest phase)
        logger.info("Phase 6: Evaluating rules...")
        self._emit_progress(6, "Evaluating rules", start_time)
        severity_threshold = self._parse_severity_threshold()
        enabled_rules = self.registry.get_enabled(self.config.rules.disabled_rules)

        # Build language-indexed file AST map for efficient pre-filtering
        lang_to_asts: dict[Language, list[FileAST]] = {}
        for ast in file_asts:
            lang_to_asts.setdefault(ast.language, []).append(ast)

        all_findings: list[Finding] = []
        total_rules = len(enabled_rules)
        skipped_rules = 0
        max_per_rule = self.config.scan.max_findings_per_rule
        for idx, rule in enumerate(enabled_rules):
            rule_started = time.monotonic()
            logger.debug(
                "Evaluating rule %d/%d: %s",
                idx + 1,
                total_rules,
                rule.definition.id,
            )
            if idx > 0 and idx % 50 == 0:
                logger.info(
                    "Phase 6: Evaluated %d/%d rules (%d findings so far, %d skipped)",
                    idx,
                    total_rules,
                    len(all_findings),
                    skipped_rules,
                )
            # Emit progress for rule evaluation
            if idx % 10 == 0:
                self._emit_progress(
                    6,
                    "Evaluating rules",
                    start_time,
                    idx / max(total_rules, 1),
                    idx,
                    total_rules,
                    f"Rule {idx}/{total_rules} ({len(all_findings)} findings)",
                )
            # Pre-filter: only pass files matching the rule's target languages
            if rule.definition.languages:
                filtered_asts: list[FileAST] = []
                for lang in rule.definition.languages:
                    filtered_asts.extend(lang_to_asts.get(lang, []))
                if not filtered_asts:
                    skipped_rules += 1
                    continue  # Skip rule entirely - no files match target language
                findings = rule.evaluate(filtered_asts, call_graph, taint_flows)
            else:
                findings = rule.evaluate(file_asts, call_graph, taint_flows)
            rule_elapsed = time.monotonic() - rule_started
            if rule_elapsed >= 2.0:
                logger.warning(
                    "Rule %s required %.2fs across %d candidate files",
                    rule.definition.id,
                    rule_elapsed,
                    len(filtered_asts) if rule.definition.languages else len(file_asts),
                )
            # Cap findings per rule to prevent memory explosion
            if len(findings) > max_per_rule:
                findings = sorted(findings, key=lambda f: -f.confidence)[:max_per_rule]
            all_findings.extend(findings)
        logger.info(
            "Phase 6: Completed %d rules, %d skipped, %d raw findings",
            total_rules,
            skipped_rules,
            len(all_findings),
        )
        self._emit_progress(
            6,
            "Evaluating rules",
            start_time,
            1.0,
            total_rules,
            total_rules,
            f"{len(all_findings)} raw findings from {total_rules} rules",
        )

        # Free language index after rule evaluation
        del lang_to_asts
        gc.collect()

        # Phase 7: Filter + Enrich
        logger.info("Phase 7: Filtering and enriching findings...")
        self._emit_progress(7, "Filtering and enriching", start_time)
        findings = self._filter_findings(all_findings, severity_threshold)
        logger.info(
            "Phase 7: Filtered %d raw findings down to %d",
            len(all_findings),
            len(findings),
        )

        # Free raw findings list to reclaim memory
        del all_findings
        gc.collect()

        # Only enrich taint-based findings with call chains (expensive shortest-path)
        taint_findings = [f for f in findings if f.taint_flow]
        logger.info(
            "Phase 7: Enriching %d taint-based findings (of %d total) with defense context...",
            len(taint_findings),
            len(findings),
        )
        entry_points = self.call_graph_builder.get_entry_points()

        for i, finding in enumerate(taint_findings):
            if i % 100 == 0:
                self._emit_progress(
                    7,
                    "Enriching findings",
                    start_time,
                    0.5 + 0.5 * (i / max(len(taint_findings), 1)),
                    i,
                    len(taint_findings),
                    f"Enriching {i}/{len(taint_findings)} taint findings",
                )
            self._attach_call_chain(finding, call_graph, entry_points)
            if finding.taint_flow is None:
                continue
            finding.defense_context = self.context_analyzer.analyze_defense(
                finding.taint_flow, call_graph
            )
            # Reduce confidence if defenses are present
            if finding.defense_context.auth_present:
                finding.confidence *= 0.5
            if finding.defense_context.sanitizer_present:
                finding.confidence *= 0.3
            if finding.defense_context.parameterized_query:
                finding.confidence *= 0.1

        # Sort by severity then confidence
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence))

        # Enrich code snippets
        self._enrich_snippets(findings)

        # Attach endpoint context to findings for LLM verification
        self._attach_endpoint_context(findings, detected_endpoints)

        self._attach_finding_provenance(findings, file_asts, result.workspace_snapshot, roots)

        result.findings = findings
        result.status = ScanStatus.COMPLETED
        self._emit_progress(
            7,
            "Complete",
            start_time,
            1.0,
            len(findings),
            len(findings),
            f"Scan complete: {len(findings)} findings",
        )

    @staticmethod
    def _overlay_semantic_dispatch(
        call_graph: Any,
        relationships: list[SemanticRelationship],
    ) -> None:
        """Add source-proved JVM dispatch edges to the ordinary call graph.

        RTA edges are preferred. CHA edges are only added for a source call site
        when no instantiated receiver target was found for that same caller and
        line, which bounds the fallback's false-positive amplification.
        """
        rta_sites = {
            (edge.source, edge.file_path, edge.line)
            for edge in relationships
            if edge.kind == "rta-call"
        }
        for edge in relationships:
            if edge.kind not in {"rta-call", "cha-call", "points-to-call"}:
                continue
            if (
                edge.kind == "cha-call"
                and (
                    edge.source,
                    edge.file_path,
                    edge.line,
                )
                in rta_sites
            ):
                continue
            if edge.source not in call_graph or edge.target not in call_graph:
                continue
            call_graph.add_edge(
                edge.source,
                edge.target,
                resolution=edge.kind,
                confidence=edge.confidence,
                provider=edge.provider,
                fidelity=edge.fidelity,
                line=edge.line,
                file_path=edge.file_path,
            )

    @staticmethod
    def _overlay_program_graph(
        program_graph: Any,
        call_graph: Any,
        relationships: list[SemanticRelationship],
        semantic_graph: Any | None = None,
    ) -> tuple[int, int, int]:
        """Overlay function calls plus bounded source-level ICFG edges.

        The ordinary call overlay retains each call-site edge.  When both
        caller and callee have source CFGs, an additional edge connects the
        narrowest caller statement containing the call to the callee entry,
        and callee normal exit to every caller continuation.  Existing caller
        exception edges remain authoritative: a source-only callee CFG cannot
        prove bytecode/library exception behavior.
        """

        call_edges = list(call_graph.edges(data=True))
        for source, target, attributes in call_edges:
            program_graph.add_node(source, kind="function")
            program_graph.add_node(target, kind="function")
            program_graph.add_edge(
                source,
                target,
                kind=attributes.get("resolution", "call"),
                overlay="call",
                confidence=attributes.get("confidence", 0.7),
                provider=attributes.get("provider", "aegify-call-graph"),
                line=attributes.get("line", 0),
                file_path=attributes.get("file_path", ""),
            )

        def statement_for(function: str, line: int) -> str | None:
            if line <= 0:
                return None
            candidates: list[tuple[int, int, int, str]] = []
            for node, data in program_graph.nodes(data=True):
                if data.get("kind") != "statement" or data.get("function") != function:
                    continue
                start = int(data.get("line_start", 0) or 0)
                end = int(data.get("line_end", start) or start)
                if start <= line <= end:
                    candidates.append(
                        (
                            end - start,
                            abs(line - start),
                            len(str(data.get("code", ""))),
                            str(node),
                        )
                    )
            return min(candidates)[-1] if candidates else None

        def normal_continuations(statement: str) -> list[str]:
            exceptional_kinds = {
                "exception",
                "exception-dispatch",
                "finally-resume-terminal",
                "uncaught-exception",
            }
            return list(
                dict.fromkeys(
                    str(target)
                    for _, target, data in program_graph.out_edges(statement, data=True)
                    if data.get("overlay") == "cfg" and data.get("kind") not in exceptional_kinds
                )
            )

        # Direct parser edges carry columns and are more precise than an
        # additional line-only CHA/RTA edge to the same target.
        direct_locations = {
            (
                str(source),
                str(target),
                str(attributes.get("file_path", "")),
                int(attributes.get("line", 0) or 0),
            )
            for source, target, attributes in call_edges
            if attributes.get("call_site") is not None
        }
        seen_icfg: set[tuple[str, str, int, int]] = set()
        call_count = 0
        return_count = 0
        callsite_ids: set[str] = set()
        for source, target, attributes in sorted(
            call_edges,
            key=lambda edge: edge[2].get("call_site") is None,
        ):
            call_site = attributes.get("call_site")
            line = int(getattr(call_site, "line", attributes.get("line", 0)) or 0)
            column = int(getattr(call_site, "column", -1) if call_site else -1)
            file_path = str(getattr(call_site, "file_path", attributes.get("file_path", "")))
            if (
                call_site is None
                and (str(source), str(target), file_path, line) in direct_locations
            ):
                continue

            statement = statement_for(str(source), line)
            callee_entry = f"{target}::cfg:entry"
            callee_exit = f"{target}::cfg:exit"
            if (
                statement is None
                or callee_entry not in program_graph
                or callee_exit not in program_graph
            ):
                continue
            identity = (statement, str(target), line, column)
            if identity in seen_icfg:
                continue
            seen_icfg.add(identity)
            digest = hashlib.sha256(f"{source}\0{file_path}\0{line}\0{column}".encode()).hexdigest()
            callsite_id = f"callsite:sha256:{digest}"
            callsite_ids.add(callsite_id)
            evidence = {
                "callsite_id": callsite_id,
                "caller": str(source),
                "callee": str(target),
                "line": line,
                "column": column,
                "file_path": file_path,
                "provider": attributes.get("provider", "aegify-source-icfg"),
                "confidence": attributes.get("confidence", 0.85),
                "fidelity": attributes.get("fidelity", "source-bounded"),
                "resolution": attributes.get("resolution", "source-call"),
            }
            program_graph.add_edge(
                statement,
                callee_entry,
                kind="interprocedural-call",
                overlay="icfg",
                **evidence,
            )
            call_count += 1
            for continuation in normal_continuations(statement):
                program_graph.add_edge(
                    callee_exit,
                    continuation,
                    kind="interprocedural-return",
                    overlay="icfg",
                    exception_behavior="caller-cfg-conservative",
                    **evidence,
                )
                return_count += 1

        if semantic_graph is not None:
            for node, attributes in semantic_graph.nodes(data=True):
                existing = dict(program_graph.nodes[node]) if node in program_graph else {}
                merged = dict(attributes)
                merged.update(existing)
                program_graph.add_node(node, **merged)

        for relationship in relationships:
            program_graph.add_node(relationship.source)
            program_graph.add_node(relationship.target)
            program_graph.add_edge(
                relationship.source,
                relationship.target,
                kind=relationship.kind,
                overlay="semantic",
                confidence=relationship.confidence,
                provider=relationship.provider,
                fidelity=relationship.fidelity,
                line=relationship.line,
                bytecode_offset=relationship.bytecode_offset,
                dispatch=relationship.dispatch,
                bootstrap_method=relationship.bootstrap_method,
                qualifier=relationship.qualifier,
                condition=relationship.condition,
                file_path=relationship.file_path,
            )

        declared_exceptions: dict[str, list[str]] = {}
        for relationship in relationships:
            if relationship.kind == "bytecode-declares-throws":
                declared_exceptions.setdefault(relationship.source, []).append(relationship.target)
        for relationship in relationships:
            if relationship.kind != "source-bytecode-call":
                continue
            statement = statement_for(relationship.source, relationship.line)
            if statement is None or relationship.target not in program_graph:
                continue
            digest = hashlib.sha256(
                (
                    f"{relationship.source}\0{relationship.file_path}\0"
                    f"{relationship.line}\0{relationship.target}\0bytecode"
                ).encode()
            ).hexdigest()
            evidence = {
                "callsite_id": f"callsite:sha256:{digest}",
                "caller": relationship.source,
                "callee": relationship.target,
                "line": relationship.line,
                "file_path": relationship.file_path,
                "provider": relationship.provider,
                "confidence": relationship.confidence,
                "fidelity": relationship.fidelity,
            }
            program_graph.add_edge(
                statement,
                relationship.target,
                kind="interprocedural-bytecode-call",
                overlay="icfg",
                **evidence,
            )
            for continuation in normal_continuations(statement):
                program_graph.add_edge(
                    relationship.target,
                    continuation,
                    kind="interprocedural-bytecode-return",
                    overlay="icfg",
                    exception_behavior="declared-exceptions-only",
                    **evidence,
                )
            exceptions = sorted(set(declared_exceptions.get(relationship.target, [])))
            if not exceptions:
                continue
            exception_continuations = {
                str(target)
                for _, target, data in program_graph.out_edges(statement, data=True)
                if data.get("overlay") == "cfg"
                and data.get("kind") in {"exception", "uncaught-exception"}
            }
            for continuation in sorted(exception_continuations):
                program_graph.add_edge(
                    relationship.target,
                    continuation,
                    kind="interprocedural-bytecode-throw",
                    overlay="icfg",
                    declared_exceptions=exceptions,
                    exception_behavior="declared-only-caller-cfg-conservative",
                    **evidence,
                )
        return call_count, return_count, len(callsite_ids)

    @staticmethod
    def _overlay_attack_surface_graph(graph: Any, result: ScanResult) -> None:
        if graph is None:
            return
        for endpoint in result.endpoints:
            endpoint_id = (
                f"endpoint:{endpoint.repository_id}:{endpoint.method}:{endpoint.path}:"
                f"{endpoint.file_path}"
            )
            graph.add_node(
                endpoint_id,
                kind="endpoint",
                method=endpoint.method,
                path=endpoint.path,
                repository_id=endpoint.repository_id,
                auth_required=endpoint.auth_required,
            )
        for link in result.attack_surface_links:
            source = f"{link.source_kind}:{link.source_id}"
            target_endpoint = (
                f"endpoint:{link.endpoint_repository_id}:{link.endpoint_method}:"
                f"{link.endpoint_path}:{link.endpoint_file_path}"
            )
            graph.add_node(source, kind=link.source_kind)
            graph.add_edge(
                source,
                target_endpoint,
                kind=link.match_kind,
                overlay="attack-surface",
                confidence=link.confidence,
            )

    def _link_runtime_observations(self, result: ScanResult) -> int:
        """Correlate observed runtime requests with direct or Gateway endpoints."""
        from aegify.models import AttackSurfaceLink, FrontendCall

        links = 0
        seen: set[tuple[str, str, str, str]] = set()
        for observation in result.runtime_observations:
            if not observation.path or not observation.method:
                continue
            for endpoint in result.endpoints:
                if not self.attack_surface_analyzer._method_matches(
                    observation.method,
                    endpoint.method,
                ):
                    continue
                match_kind = self.attack_surface_analyzer._endpoint_match(
                    observation.path,
                    endpoint.path,
                )
                if not match_kind:
                    runtime_call = FrontendCall(
                        id=observation.id,
                        path=observation.path,
                        method=observation.method,
                        file_path=observation.provenance.module_path,
                        line=0,
                        client=observation.kind,
                        repository_id=observation.repository_id,
                        confidence=1.0,
                    )
                    match_kind = self.attack_surface_analyzer._frontend_gateway_match(
                        runtime_call,
                        result.gateway_routes,
                        endpoint,
                    )
                if not match_kind:
                    continue
                key = (
                    observation.id,
                    endpoint.repository_id,
                    endpoint.method,
                    endpoint.path,
                )
                if key in seen:
                    continue
                seen.add(key)
                endpoint.runtime_observed = True
                endpoint.runtime_observation_count += 1
                result.attack_surface_links.append(
                    AttackSurfaceLink(
                        source_kind="runtime_observation",
                        source_id=observation.id,
                        endpoint_path=endpoint.path,
                        endpoint_method=endpoint.method,
                        endpoint_file_path=endpoint.file_path,
                        endpoint_repository_id=endpoint.repository_id,
                        match_kind=f"runtime_{match_kind}",
                        confidence=1.0,
                    )
                )
                links += 1
        return links

    @staticmethod
    def _overlay_repository_reachability(
        graph: Any,
        file_asts: list[FileAST],
        dependencies: dict[str, list[str]],
    ) -> None:
        repository_ids = {ast.repository_id for ast in file_asts if ast.repository_id}
        for repository_id in repository_ids:
            graph.add_node(
                f"repository:{repository_id}",
                kind="repository",
                repository_id=repository_id,
            )
        for node, attributes in list(graph.nodes(data=True)):
            repository_id = attributes.get("repository_id")
            if not repository_id or attributes.get("kind") != "function":
                continue
            repository = f"repository:{repository_id}"
            graph.add_edge(
                node,
                repository,
                kind="member-of",
                overlay="repository",
                confidence=1.0,
                fidelity="structural",
            )
            graph.add_edge(
                repository,
                node,
                kind="contains-function",
                overlay="repository",
                confidence=1.0,
                fidelity="structural",
            )
        for consumer, providers in dependencies.items():
            for provider in providers:
                graph.add_edge(
                    f"repository:{consumer}",
                    f"repository:{provider}",
                    kind="depends-on",
                    overlay="repository",
                    confidence=0.45,
                    fidelity="declared-dependency-coarse",
                )

    @staticmethod
    def _overlay_framework_graph(
        graph: Any,
        call_graph: Any,
        relationships: list[SemanticRelationship],
    ) -> None:
        for relationship in relationships:
            graph.add_node(relationship.source)
            graph.add_node(relationship.target)
            graph.add_edge(
                relationship.source,
                relationship.target,
                kind=relationship.kind,
                overlay="framework",
                confidence=relationship.confidence,
                provider=relationship.provider,
                fidelity=relationship.fidelity,
                line=relationship.line,
                bytecode_offset=relationship.bytecode_offset,
                dispatch=relationship.dispatch,
                bootstrap_method=relationship.bootstrap_method,
                qualifier=relationship.qualifier,
                condition=relationship.condition,
                file_path=relationship.file_path,
            )
            if (
                relationship.kind == "spring-di-call"
                and relationship.source in call_graph
                and relationship.target in call_graph
            ):
                call_graph.add_edge(
                    relationship.source,
                    relationship.target,
                    resolution="spring-di-call",
                    confidence=relationship.confidence,
                    provider=relationship.provider,
                    line=relationship.line,
                    file_path=relationship.file_path,
                )

    @staticmethod
    def _overlay_taint_graph(graph: Any, taint_flows: list[Any]) -> int:
        if graph is None:
            return 0

        def statement_for(file_path: str, line: int) -> str | None:
            candidates: list[tuple[int, str]] = []
            normalized = Path(file_path).as_posix()
            for node, attributes in graph.nodes(data=True):
                if attributes.get("kind") != "statement":
                    continue
                graph_file = str(attributes.get("file_path", ""))
                if not (normalized == graph_file or normalized.endswith(f"/{graph_file}")):
                    continue
                start = int(attributes.get("line_start", 0))
                end = int(attributes.get("line_end", start))
                distance = 0 if start <= line <= end else min(abs(line - start), abs(line - end))
                candidates.append((distance, node))
            return min(candidates)[1] if candidates else None

        count = 0
        for flow in taint_flows:
            source = statement_for(flow.source.file_path, flow.source.line)
            sink = statement_for(flow.sink.file_path, flow.sink.line)
            if source is None or sink is None:
                continue
            graph.add_edge(
                source,
                sink,
                kind="interprocedural-taint",
                overlay="taint",
                source_type=flow.source.source_type,
                sink_type=flow.sink.sink_type,
                sanitized=flow.sanitized,
                confidence=0.9 if not flow.sanitized else 0.4,
                provider="aegify-taint-v1",
            )
            count += 1
        return count

    @staticmethod
    def _repository_id_for_file(path: Path, file_asts: list[FileAST]) -> str:
        """Resolve repository identity for a non-source artifact such as OpenAPI."""
        resolved = path.resolve()
        candidates = [ast for ast in file_asts if ast.repository_id]
        for ast in candidates:
            module_path = Path(ast.module_path)
            source_path = Path(ast.file_path).resolve()
            root = source_path
            for _ in module_path.parts:
                root = root.parent
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            return ast.repository_id
        return ""

    @staticmethod
    def _compute_workspace_snapshot(
        file_asts: list[FileAST],
        roots: list[Path],
        repository_ids_by_root: dict[Path, str] | None = None,
    ) -> str:
        """Hash source and configuration evidence with path-stable identities."""
        entries: list[tuple[str, str, str]] = []
        resolved_roots = [root.resolve() for root in roots]
        scanned_paths: set[Path] = set()
        for ast in file_asts:
            file_path = Path(ast.file_path)
            scanned_paths.add(file_path.resolve())
            module_path = ast.module_path
            if not module_path:
                resolved_file = file_path.resolve()
                for root in resolved_roots:
                    try:
                        module_path = resolved_file.relative_to(root).as_posix()
                        break
                    except ValueError:
                        continue
                module_path = module_path or file_path.name
            try:
                content_digest = compute_file_hash(file_path)
            except OSError:
                content_digest = "unreadable"
            entries.append((ast.repository_id, module_path, content_digest))

        # Endpoint evidence can come from files that the language parser does
        # not turn into FileAST objects. Include those inputs in the same
        # snapshot so an OpenAPI or Gateway-only change invalidates evidence.
        config_patterns = (
            "application*.yml",
            "application*.yaml",
            "bootstrap*.yml",
            "bootstrap*.yaml",
        )
        for root in roots:
            evidence_files = set(find_openapi_files(root))
            for pattern in config_patterns:
                evidence_files.update(root.rglob(pattern))
            for file_path in evidence_files:
                resolved_file = file_path.resolve()
                if resolved_file in scanned_paths or not file_path.is_file():
                    continue
                try:
                    module_path = resolved_file.relative_to(root.resolve()).as_posix()
                except ValueError:
                    module_path = file_path.name
                repository_id = (repository_ids_by_root or {}).get(
                    root.resolve(), ""
                ) or ScanEngine._repository_id_for_file(file_path, file_asts)
                try:
                    content_digest = compute_file_hash(file_path)
                except OSError:
                    content_digest = "unreadable"
                entries.append((repository_id, module_path, content_digest))

        digest = hashlib.sha256()
        for repository_id, module_path, content_digest in sorted(entries):
            digest.update(f"{repository_id}\0{module_path}\0{content_digest}\n".encode())
        return f"sha256:{digest.hexdigest()}"

    def _attach_finding_provenance(
        self,
        findings: list[Finding],
        file_asts: list[FileAST],
        workspace_snapshot: str,
        roots: list[Path],
    ) -> None:
        """Attach stable rule, repository, module, and evidence identities."""
        from aegify import __version__

        ast_by_file = {str(Path(ast.file_path).resolve()): ast for ast in file_asts}
        rule_digests: dict[str, tuple[str, str]] = {}
        for finding in findings:
            rule = self.registry.get(finding.rule_id)
            if finding.rule_id not in rule_digests:
                if rule is None:
                    producer = "aegify.unknown-rule"
                    rule_payload = finding.rule_id
                else:
                    producer = f"aegify.{type(rule).__name__}"
                    raw_yaml = getattr(rule, "raw_yaml", "")
                    if raw_yaml:
                        rule_payload = raw_yaml
                    else:
                        rule_payload = json.dumps(
                            {
                                "definition": str(rule.definition),
                                "detection": rule.get_detection_metadata(),
                            },
                            sort_keys=True,
                            default=str,
                        )
                rule_digests[finding.rule_id] = (
                    producer,
                    hashlib.sha256(rule_payload.encode()).hexdigest(),
                )
            producer, rule_digest = rule_digests[finding.rule_id]

            ast = ast_by_file.get(str(Path(finding.file_path).resolve()))
            repository_id = ast.repository_id if ast else ""
            module_path = ast.module_path if ast else ""
            if not module_path:
                module_path = self._relative_module_path(Path(finding.file_path), roots)
            identity = "\0".join(
                (
                    workspace_snapshot,
                    producer,
                    rule_digest,
                    repository_id,
                    module_path,
                    str(finding.line_start),
                    str(finding.line_end),
                )
            )
            evidence_id = f"ev:{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
            finding.provenance = EvidenceProvenance(
                producer=producer,
                producer_version=__version__,
                analysis_kind=(
                    "semantic-taint"
                    if finding.taint_flow is not None
                    else (
                        "semantic-structural"
                        if finding.evidence_state != EvidenceState.CANDIDATE
                        else "heuristic-candidate"
                    )
                ),
                fidelity=(
                    "source-to-sink"
                    if finding.taint_flow is not None
                    else (
                        "same-function-structured"
                        if finding.evidence_state != EvidenceState.CANDIDATE
                        else "heuristic"
                    )
                ),
                repository_id=repository_id,
                module_path=module_path,
                workspace_snapshot=workspace_snapshot,
                rule_digest=f"sha256:{rule_digest}",
                evidence_id=evidence_id,
            )

    def _attach_attack_surface_provenance(self, result: ScanResult) -> None:
        """Attach evidence identity to frontend/gateway correlation edges."""
        from aegify import __version__

        source_repositories = {call.id: call.repository_id for call in result.frontend_calls}
        source_repositories.update(
            {route.id: route.repository_id for route in result.gateway_routes}
        )
        source_repositories.update(
            {
                observation.id: observation.repository_id
                for observation in result.runtime_observations
            }
        )
        for link in result.attack_surface_links:
            source_repository = source_repositories.get(link.source_id, "")
            identity = "\0".join(
                (
                    result.workspace_snapshot,
                    link.source_kind,
                    source_repository,
                    link.source_id,
                    link.endpoint_repository_id,
                    link.endpoint_method,
                    link.endpoint_path,
                    link.endpoint_file_path,
                    link.match_kind,
                )
            )
            evidence_id = f"edge:{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
            link.provenance = EvidenceProvenance(
                producer=(
                    "aegify.RuntimeEvidenceCorrelator"
                    if link.source_kind == "runtime_observation"
                    else "aegify.AttackSurfaceAnalyzer"
                ),
                producer_version=__version__,
                analysis_kind=(
                    "dynamic-correlation"
                    if link.source_kind == "runtime_observation"
                    else "static-correlation"
                ),
                repository_id=source_repository,
                workspace_snapshot=result.workspace_snapshot,
                evidence_id=evidence_id,
            )

    @staticmethod
    def _relative_module_path(path: Path, roots: list[Path]) -> str:
        resolved = path.resolve()
        for root in roots:
            try:
                return resolved.relative_to(root.resolve()).as_posix()
            except ValueError:
                continue
        return path.name

    def _create_storage(self) -> StorageBackend:
        """Create a storage backend based on configuration."""
        backend = self.config.storage.backend
        if backend == "sqlite":
            from aegify.storage.sqlite import SQLiteBackend

            return SQLiteBackend(self.config.storage.db_path)
        elif backend == "postgresql":
            from aegify.storage.postgresql import PostgreSQLBackend

            return PostgreSQLBackend(self.config.storage.db_url)
        elif backend == "s3":
            from aegify.storage.s3 import S3Backend

            return S3Backend(self.config.storage.s3_bucket, self.config.storage.s3_prefix)
        return InMemoryBackend()

    def _parse_directory_parallel(self, target: Path) -> list[FileAST]:
        """Parse a directory using parallel workers when beneficial."""
        files = list(self.ast_parser._collect_files(target, set(self.config.scan.exclude)))

        if not files:
            return []

        # For small file sets or single worker, use sequential parsing
        if len(files) <= 3 or self.max_workers <= 1:
            return self.ast_parser.parse_directory(target, self.config.scan.exclude)

        # Incremental AST cache: unchanged files are reconstructed from the
        # versioned storage index and are not sent to parser workers.
        project_id = str(target)
        stored_hashes = self.storage.load_file_hashes(project_id)
        stored_index = self.storage.load_index(project_id) or {}
        cached_payloads = stored_index.get("asts", {})
        if stored_index.get("version") != 1 or not isinstance(cached_payloads, dict):
            cached_payloads = {}
        files_to_parse: list[Path] = []
        cached_results: list[FileAST] = []

        for f in files:
            current_hash = compute_file_hash(f)
            self._file_hashes[str(f)] = current_hash

            cached_payload = cached_payloads.get(str(f))
            if stored_hashes.get(str(f)) == current_hash and cached_payload is not None:
                try:
                    cached_results.append(FileAST.model_validate(cached_payload))
                    continue
                except ValueError:
                    logger.debug("Invalid cached AST for %s; reparsing", f)
            files_to_parse.append(f)
            self.storage.store_file_hash(project_id, str(f), current_hash)

        # Parallel AST parsing in batches to limit peak memory
        logger.info(
            "Parsing %d changed files with %d workers (%d cache hits)",
            len(files_to_parse),
            self.max_workers,
            len(cached_results),
        )
        results: list[FileAST] = list(cached_results)
        batch_size = 5000  # Process files in batches to limit memory

        for batch_start in range(0, len(files_to_parse), batch_size):
            batch = files_to_parse[batch_start : batch_start + batch_size]
            try:
                with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                    parsed = executor.map(_parse_file_worker, [str(f) for f in batch])
                    for ast in parsed:
                        if ast is not None:
                            results.append(ast)
            except (OSError, PermissionError) as error:
                # Sandboxed CI runners may deny POSIX semaphore discovery. A
                # deterministic sequential fallback is preferable to failing a scan.
                logger.warning(
                    "Process-based parsing unavailable (%s); using sequential parsing",
                    error,
                )
                for file_path in batch:
                    ast = self.ast_parser.parse_file(file_path)
                    if ast is not None:
                        results.append(ast)
            # Allow GC between batches for large codebases
            if len(files_to_parse) > batch_size:
                gc.collect()

        # Single-repository scans still need module-qualified callable IDs.
        # Without this, common route names such as GET/POST collapse across
        # files in both the call graph and normalized program graph.
        for ast in results:
            self.ast_parser.apply_repository_context(
                ast,
                repository_id="",
                repository_root=target,
            )

        current_paths = {str(path) for path in files}
        self.storage.store_index(
            project_id,
            {
                "version": 1,
                "asts": {
                    ast.file_path: ast.model_dump(mode="json")
                    for ast in results
                    if ast.file_path in current_paths
                },
            },
        )
        logger.info(
            "Loaded %d ASTs from %s (%d parsed, %d cached)",
            len(results),
            target,
            len(results) - len(cached_results),
            len(cached_results),
        )
        return results

    def _parse_severity_threshold(self) -> Severity:
        threshold_str = self.config.rules.severity_threshold.lower()
        try:
            return Severity(threshold_str)
        except ValueError:
            return Severity.MEDIUM

    # Patterns indicating generated/build output files that should never produce findings
    _GENERATED_FILE_PATTERNS = (
        "_pb.js",
        "_pb.d.ts",
        "_grpc_web_pb",
        ".pb.go",
        ".generated.",
        "/generated/",
        "/proto/gen/",
        "/dist/",
        "/build/",
        "/.next/",
        "/__generated__/",
        "/node_modules/",
    )

    def _filter_findings(
        self, findings: list[Finding], severity_threshold: Severity
    ) -> list[Finding]:
        """Filter findings by severity threshold, confidence, generated files, and deduplicate."""
        threshold_order = SEVERITY_ORDER.get(severity_threshold, 2)
        min_confidence = 0.3  # Low confidence findings are likely false positives
        max_per_file = self.config.scan.max_findings_per_file

        filtered: list[Finding] = []
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 99) > threshold_order:
                continue
            if f.confidence < min_confidence:
                continue
            # Skip findings from generated/build files (safety net)
            if any(pat in f.file_path for pat in self._GENERATED_FILE_PATTERNS):
                continue
            # Skip findings with empty taint source (sink matched but no confirmed input)
            if "from '' (line )" in f.message or "from '' (line)" in f.message:
                continue
            filtered.append(f)

        # Within one scan, exact rule/location duplicates are the same occurrence.
        # The content-based public fingerprint intentionally excludes line numbers
        # so it can survive ordinary code movement between scans.
        seen: dict[str, Finding] = {}
        for f in filtered:
            fp = f"{f.rule_id}:{f.file_path}:{f.line_start}:{f.line_end}"
            current = seen.get(fp)
            candidate_rank = (
                1 if f.disposition == FindingDisposition.BLOCKING else 0,
                f.confidence,
            )
            current_rank = (
                (
                    1
                    if current is not None and current.disposition == FindingDisposition.BLOCKING
                    else 0
                ),
                current.confidence if current is not None else -1.0,
            )
            if current is None or candidate_rank > current_rank:
                seen[fp] = f

        deduped = list(seen.values())

        # Enforce per-file global cap (across all rules)
        if max_per_file > 0:
            from collections import Counter

            file_counts: Counter[str] = Counter()
            capped: list[Finding] = []
            # Sort by confidence descending so we keep the best findings per file
            deduped.sort(key=lambda f: -f.confidence)
            for f in deduped:
                if file_counts[f.file_path] < max_per_file:
                    capped.append(f)
                    file_counts[f.file_path] += 1
            return capped

        return deduped

    def _attach_call_chain(
        self,
        finding: Finding,
        call_graph: CodeGraph,
        entry_points: list[str],
    ) -> None:
        """Attach call graph path from nearest entry point to the finding's sink."""
        import networkx as nx

        # Determine the sink function from taint flow or file/line lookup
        sink_func: str | None = None
        if finding.taint_flow and finding.taint_flow.sink.in_function:
            sink_func = finding.taint_flow.sink.in_function
        else:
            # Try to find which function contains this line
            for node, data in call_graph.nodes(data=True):
                if not data or not data.get("data"):
                    continue
                nd = data["data"]
                if (
                    nd.file_path == finding.file_path
                    and nd.line_start <= finding.line_start <= nd.line_end
                ):
                    sink_func = node
                    break

        if not sink_func:
            return

        # Resolve short name to qualified name if needed
        if sink_func not in call_graph:
            for node in call_graph.nodes():
                if node.endswith(f".{sink_func}") or node == sink_func:
                    sink_func = node
                    break

        if sink_func not in call_graph:
            return

        # Find shortest path from any entry point to this sink
        best_chain: list[str] | None = None
        for ep in entry_points:
            try:
                path = nx.shortest_path(call_graph, ep, sink_func)
                if best_chain is None or len(path) < len(best_chain):
                    best_chain = path
            except nx.NodeNotFound, nx.NetworkXNoPath:
                continue

        # If no entry point reaches it, try ancestors
        if best_chain is None:
            try:
                ancestors = list(nx.ancestors(call_graph, sink_func))
                if ancestors:
                    # Use the ancestor with no predecessors (a root caller)
                    for anc in ancestors:
                        if call_graph.in_degree(anc) == 0:
                            try:
                                best_chain = nx.shortest_path(call_graph, anc, sink_func)
                                break
                            except nx.NetworkXNoPath:
                                continue
            except nx.NetworkXError:
                pass

        if not best_chain or len(best_chain) < 2:
            return

        # Convert to CallChainStep
        finding.call_chain = self.context_analyzer.get_call_chain_steps(
            best_chain[0], sink_func, call_graph
        )

    # Number of context lines before/after the finding to include in snippets
    _SNIPPET_CONTEXT_LINES = 5

    def _enrich_snippets(self, findings: list[Finding]) -> None:
        """Load code snippets for findings that don't have them."""
        ctx = self._SNIPPET_CONTEXT_LINES
        # Cache file contents to avoid re-reading the same file for multiple findings
        file_cache: dict[str, list[str]] = {}
        for finding in findings:
            if finding.code_snippet:
                continue
            try:
                fp = finding.file_path
                if fp not in file_cache:
                    file_cache[fp] = Path(fp).read_text(errors="replace").splitlines()
                lines = file_cache[fp]
                start = max(0, finding.line_start - 1 - ctx)
                end = min(len(lines), finding.line_end + ctx)
                finding.code_snippet = "\n".join(lines[start:end])
            except OSError:
                pass

    @staticmethod
    def _attach_endpoint_context(
        findings: list[Finding],
        endpoints: list[Any],
    ) -> None:
        """Attach endpoint context to findings in the same file/function."""
        if not endpoints:
            return

        # Build file_path -> endpoints index
        ep_by_file: dict[str, list[Any]] = {}
        for ep in endpoints:
            ep_by_file.setdefault(ep.file_path, []).append(ep)

        for finding in findings:
            file_eps = ep_by_file.get(finding.file_path)
            if not file_eps:
                continue
            # Find the closest endpoint (by line overlap or nearest)
            best_ep = None
            best_dist = float("inf")
            for ep in file_eps:
                if ep.line_start <= finding.line_start <= ep.line_end:
                    best_ep = ep
                    break
                dist = abs(ep.line_start - finding.line_start)
                if dist < best_dist:
                    best_dist = dist
                    best_ep = ep
            if best_ep:
                finding.defense_context.details["endpoint"] = {
                    "path": best_ep.path,
                    "method": best_ep.method,
                    "framework": best_ep.framework,
                    "auth_required": best_ep.auth_required,
                    "handler": best_ep.handler_function,
                }
