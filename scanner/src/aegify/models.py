"""Core data models for Aegify."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(StrEnum):
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class EvidenceState(StrEnum):
    """Strength of the evidence attached to a finding."""

    CANDIDATE = "candidate"
    REACHABLE = "reachable"
    OBSERVED = "observed"
    IMPACT_PROVEN = "impact_proven"


class FindingDisposition(StrEnum):
    """Whether a finding may fail a CI security gate."""

    ADVISORY = "advisory"
    BLOCKING = "blocking"


class AIReviewVerdict(StrEnum):
    """Non-authoritative AI recommendation for a finding."""

    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUST = "rust"
    SWIFT = "swift"
    KOTLIN = "kotlin"


# --- AST / Call Graph Models ---


class FileAST(BaseModel):
    """Parsed AST for a single file."""

    file_path: str
    language: Language
    functions: list[FunctionDef] = Field(default_factory=list)
    classes: list[ClassDef] = Field(default_factory=list)
    imports: list[ImportInfo] = Field(default_factory=list)
    calls: list[CallSite] = Field(default_factory=list)
    repository_id: str = ""
    module_path: str = ""


class FunctionDef(BaseModel):
    """Function/method definition extracted from AST."""

    name: str
    qualified_name: str  # module.class.method
    file_path: str
    line_start: int
    line_end: int
    parameters: list[str] = Field(default_factory=list)
    parameter_types: list[str] = Field(default_factory=list)
    parameter_defaults: list[bool] = Field(default_factory=list)
    variadic: bool = False
    return_type: str = ""
    decorators: list[str] = Field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None
    # Repository-aware identity is optional for backwards-compatible single-repo
    # scans. Workspace scans populate these fields so same-named symbols in
    # different repositories cannot collapse into one call-graph node.
    repository_id: str = ""
    module_path: str = ""
    symbol_id: str = ""
    language: Language | None = None

    @property
    def callable_descriptor(self) -> str:
        """Stable source descriptor used to distinguish JVM overloads."""

        types = list(self.parameter_types[: len(self.parameters)])
        types.extend("?" for _ in range(len(self.parameters) - len(types)))
        normalized = [self._normalize_type(value) for value in types]
        if self.variadic and normalized:
            normalized[-1] = normalized[-1].removesuffix("[]") + "..."
        return f"({','.join(normalized)})"

    @property
    def callable_name(self) -> str:
        return f"{self.qualified_name}{self.callable_descriptor}"

    @staticmethod
    def _normalize_type(value: str) -> str:
        candidate = re.sub(r"@[A-Za-z_$][\w$]*(?:\([^)]*\))?", "", value)
        candidate = re.sub(r"\s+", "", candidate).strip()
        return candidate or "?"


class ClassDef(BaseModel):
    """Class definition extracted from AST."""

    name: str
    file_path: str
    line_start: int
    line_end: int
    base_classes: list[str] = Field(default_factory=list)
    methods: list[FunctionDef] = Field(default_factory=list)
    decorators: list[str] = Field(default_factory=list)


class ImportInfo(BaseModel):
    """Import statement information."""

    module: str
    names: list[str] = Field(default_factory=list)
    alias: str | None = None
    # Local identifier -> exported/original identifier. This preserves
    # ``foo as bar`` semantics without changing the legacy ``names`` field.
    bindings: dict[str, str] = Field(default_factory=dict)
    line: int = 0


class CallSite(BaseModel):
    """Function call site in source code."""

    callee: str  # function being called
    file_path: str
    line: int
    column: int
    arguments: list[str] = Field(default_factory=list)
    argument_types: list[str] = Field(default_factory=list)
    receiver: str | None = None  # object.method() -> receiver = object
    receiver_type: str = ""
    in_function: str | None = None  # enclosing function
    caller_symbol_id: str = ""
    repository_id: str = ""


# --- Taint / Dataflow Models ---


class TaintSource(BaseModel):
    """A source of tainted (user-controlled) data."""

    variable: str
    file_path: str
    line: int
    source_type: str  # e.g., "request.args", "sys.argv"
    in_function: str | None = None


class TaintSink(BaseModel):
    """A dangerous operation that should not receive tainted data."""

    function: str  # e.g., "cursor.execute"
    file_path: str
    line: int
    sink_type: str  # e.g., "sql_query", "os_command"
    argument_index: int = 0  # dangerous argument; -1 denotes the call receiver
    in_function: str | None = None


class TaintFlow(BaseModel):
    """A complete taint flow from source to sink."""

    source: TaintSource
    sink: TaintSink
    path: list[TaintPropagation] = Field(default_factory=list)
    sanitized: bool = False
    sanitizer: str | None = None


class TaintPropagation(BaseModel):
    """A step in taint propagation."""

    variable: str
    file_path: str
    line: int
    propagation_type: str  # "assignment", "argument", "return"
    function: str | None = None
    call_context: list[str] = Field(default_factory=list)


# --- Defense Context ---


class DefenseContext(BaseModel):
    """Defense mechanisms detected in the call chain."""

    auth_present: bool = False
    auth_decorator: str | None = None
    sanitizer_present: bool = False
    sanitizer_function: str | None = None
    input_validation: bool = False
    parameterized_query: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


# --- Findings ---


class CallChainStep(BaseModel):
    """A step in a call chain leading to a vulnerability."""

    file_path: str
    function: str
    line: int
    code_snippet: str = ""


class EvidenceProvenance(BaseModel):
    """Reproducible producer and snapshot identity for static evidence."""

    contract_version: int = 1
    producer: str = ""
    producer_version: str = ""
    analysis_kind: str = "static-analysis"
    fidelity: str = "heuristic"
    repository_id: str = ""
    module_path: str = ""
    workspace_snapshot: str = ""
    rule_digest: str = ""
    evidence_id: str = ""


class AIToolEvidence(BaseModel):
    """Bounded, auditable output from an allowlisted analysis tool."""

    tool: str
    request_id: str = ""
    summary: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False


class ProofGuidance(BaseModel):
    """Safe validation guidance. This is never proof that impact occurred."""

    safety: str = "owned_fixture_only"
    requires_approval: bool = True
    preconditions: list[str] = Field(default_factory=list)
    request_template: str = ""
    payload_template: str = ""
    expected_signal: str = ""
    negative_control: str = ""
    harness_plan: dict[str, Any] = Field(default_factory=dict)


class AIReview(BaseModel):
    """Evidence-bound AI suggestion; humans and deterministic gates stay authoritative."""

    verdict: AIReviewVerdict = AIReviewVerdict.NEEDS_REVIEW
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    attack_scenario: str = ""
    remediation_summary: str = ""
    fixed_code: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    proof: ProofGuidance = Field(default_factory=ProofGuidance)
    tools_used: list[AIToolEvidence] = Field(default_factory=list)
    model: str = ""
    prompt_digest: str = ""
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Finding(BaseModel):
    """A detected security vulnerability."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    status: FindingStatus = FindingStatus.NEW
    evidence_state: EvidenceState = EvidenceState.CANDIDATE
    disposition: FindingDisposition = FindingDisposition.ADVISORY
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str = ""
    message: str = ""
    call_chain: list[CallChainStep] = Field(default_factory=list)
    taint_flow: TaintFlow | None = None
    defense_context: DefenseContext = Field(default_factory=DefenseContext)
    cwe_id: int | None = None
    owasp_category: str | None = None
    llm_analysis: str | None = None
    ai_review: AIReview | None = None
    remediation: str | None = None
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def fingerprint(self) -> str:
        """Stable hash for deduplication across scans."""
        evidence = re.sub(r"\s+", " ", self.code_snippet or self.message).strip()
        path = self.file_path.replace("\\", "/").removeprefix("./")
        key = f"aegify-finding/v1\n{self.rule_id.lower()}\n{path}\n{evidence}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def blocks_ci(self) -> bool:
        """Return whether this result participates in the CI exit-code gate."""
        return self.disposition == FindingDisposition.BLOCKING


# --- Scan Result ---


class EndpointParam(BaseModel):
    """A parameter accepted by an endpoint."""

    name: str
    location: str = "unknown"  # path, query, body, header
    param_type: str = ""


class EndpointInfo(BaseModel):
    """A detected API endpoint."""

    path: str
    method: str
    handler_function: str
    file_path: str
    line_start: int = 0
    line_end: int = 0
    framework: str = ""
    auth_required: bool = False
    parameters: list[EndpointParam] = Field(default_factory=list)
    middleware: list[str] = Field(default_factory=list)
    repository_id: str = ""
    called_by_frontend: bool = False
    frontend_call_count: int = 0
    exposed_via_gateway: bool = False
    gateway_route_ids: list[str] = Field(default_factory=list)
    runtime_observed: bool = False
    runtime_observation_count: int = 0


class FrontendCall(BaseModel):
    """An HTTP call found in JavaScript or TypeScript client code."""

    id: str
    path: str
    method: str
    file_path: str
    line: int
    client: str
    repository_id: str = ""
    dynamic: bool = False
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)


class GatewayRoute(BaseModel):
    """A Spring Cloud Gateway route and the public path it exposes."""

    id: str
    uri: str
    path_patterns: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)
    file_path: str
    line: int = 0
    repository_id: str = ""


class AttackSurfaceLink(BaseModel):
    """Evidence-backed relation between a client/gateway and a backend endpoint."""

    source_kind: str  # frontend_call | gateway_route
    source_id: str
    endpoint_path: str
    endpoint_method: str
    endpoint_file_path: str
    endpoint_repository_id: str = ""
    match_kind: str  # exact | template | gateway_pattern | gateway_transform
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)


class SemanticRelationship(BaseModel):
    """A typed relationship emitted by a semantic-analysis provider."""

    source: str
    target: str
    kind: str
    repository_id: str = ""
    file_path: str = ""
    line: int = 0
    bytecode_offset: int = -1
    dispatch: str = ""
    bootstrap_method: str = ""
    qualifier: str = ""
    condition: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provider: str = ""
    fidelity: str = "heuristic"


class JvmBuildProject(BaseModel):
    """A discovered Maven or Gradle build boundary."""

    repository_id: str
    root: str
    build_system: str
    descriptors: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    source_roots: list[str] = Field(default_factory=list)
    dependency_lockfiles: list[str] = Field(default_factory=list)


class SemanticAnalysisSummary(BaseModel):
    """Compact, serializable summary of the layered semantic graph."""

    enabled: bool = False
    fidelity: str = "none"
    providers: list[str] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    relationships_emitted: int = 0
    relationships_truncated: bool = False
    scip_documents: int = 0
    scip_symbols: int = 0
    scip_occurrences: int = 0
    scip_packages: int = 0
    scip_exact_external_resolutions: int = 0
    scip_unresolved_external_symbols: int = 0
    scip_package_version_conflicts: int = 0
    scip_cache_hits: int = 0
    scip_cache_misses: int = 0
    jvm_types: int = 0
    jvm_cha_edges: int = 0
    jvm_rta_edges: int = 0
    jvm_points_to_contexts: int = 0
    jvm_points_to_iterations: int = 0
    jvm_points_to_allocations: int = 0
    jvm_points_to_edges: int = 0
    jvm_points_to_alias_edges: int = 0
    jvm_points_to_argument_edges: int = 0
    jvm_points_to_return_edges: int = 0
    jvm_points_to_receiver_calls: int = 0
    jvm_points_to_direct_calls: int = 0
    jvm_points_to_truncated: bool = False
    jvm_modules: int = 0
    jvm_module_edges: int = 0
    jvm_artifacts: int = 0
    jvm_published_artifacts: int = 0
    jvm_declared_dependencies: int = 0
    jvm_locked_dependencies: int = 0
    jvm_dynamic_dependencies: int = 0
    jvm_dependency_lockfiles: int = 0
    jvm_version_catalogs: int = 0
    jvm_catalog_dependencies: int = 0
    jvm_exact_external_resolutions: int = 0
    jvm_ambiguous_external_resolutions: int = 0
    jvm_unresolved_workspace_dependencies: int = 0
    jvm_dependency_version_conflicts: int = 0
    jvm_classpath_snapshots: int = 0
    jvm_classpath_entries: int = 0
    jvm_classpath_entries_verified: int = 0
    jvm_classpath_entries_rejected: int = 0
    jvm_bytecode_classes: int = 0
    jvm_bytecode_methods: int = 0
    jvm_bytecode_invokes: int = 0
    jvm_bytecode_declared_exceptions: int = 0
    jvm_bytecode_unresolved_invokes: int = 0
    jvm_bytecode_ambiguous_invokes: int = 0
    jvm_bytecode_virtual_invokes: int = 0
    jvm_bytecode_virtual_single_target: int = 0
    jvm_bytecode_virtual_ambiguous: int = 0
    jvm_bytecode_allocation_sites: int = 0
    jvm_bytecode_rta_invokes: int = 0
    jvm_bytecode_rta_targets: int = 0
    jvm_bytecode_invokedynamic_sites: int = 0
    jvm_bytecode_lambda_targets: int = 0
    jvm_bytecode_unresolved_bootstraps: int = 0
    jvm_bytecode_source_calls_resolved: int = 0
    jvm_bytecode_source_calls_ambiguous: int = 0
    build_projects: list[JvmBuildProject] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ProgramGraphSummary(BaseModel):
    """Coverage counters for the normalized security program graph."""

    enabled: bool = False
    provider: str = "aegify-program-ir"
    fidelity: str = "source-structured"
    context_balanced_query_available: bool = True
    context_query_default_max_call_depth: int = 32
    context_query_default_max_states: int = 100_000
    functions: int = 0
    cfg_nodes: int = 0
    cfg_edges: int = 0
    branch_edges: int = 0
    exception_edges: int = 0
    finally_edges: int = 0
    switch_edges: int = 0
    dfg_edges: int = 0
    ssa_phi_nodes: int = 0
    points_to_edges: int = 0
    alias_edges: int = 0
    data_state_nodes: int = 0
    transformation_edges: int = 0
    interprocedural_callsites: int = 0
    interprocedural_call_edges: int = 0
    interprocedural_return_edges: int = 0
    interprocedural_bytecode_call_edges: int = 0
    interprocedural_bytecode_return_edges: int = 0
    interprocedural_bytecode_throw_edges: int = 0
    interprocedural_taint_edges: int = 0
    callable_descriptors: int = 0
    overload_calls_resolved: int = 0
    overload_calls_ambiguous: int = 0
    warnings: list[str] = Field(default_factory=list)


class TaintAnalysisSummary(BaseModel):
    """Coverage and precision counters for the bounded global taint solver."""

    enabled: bool = False
    provider: str = "aegify-taint-v2"
    fidelity: str = "flow-field-object-call-string-sensitive-bounded"
    context_depth: int = 0
    contexts_analyzed: int = 0
    library_model_pack: str | None = None
    library_models_loaded: int = 0
    library_summary_applications: int = 0
    iterations: int = 0
    sources: int = 0
    sinks: int = 0
    flows: int = 0
    argument_propagations: int = 0
    return_propagations: int = 0
    object_return_propagations: int = 0
    field_reads: int = 0
    field_writes: int = 0
    heap_strong_updates: int = 0
    heap_objects: int = 0
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class FrameworkAnalysisSummary(BaseModel):
    """Spring/JVM framework edges recovered beyond ordinary syntax calls."""

    enabled: bool = False
    spring_components: int = 0
    bean_bindings: int = 0
    bean_factories: int = 0
    qualified_bindings: int = 0
    primary_resolutions: int = 0
    conditional_candidates: int = 0
    ambiguous_bindings: int = 0
    cross_repository_di_edges: int = 0
    di_call_edges: int = 0
    security_guards: int = 0
    transaction_boundaries: int = 0
    coroutine_edges: int = 0
    reactive_edges: int = 0
    warnings: list[str] = Field(default_factory=list)


class ExternalAnalysisSummary(BaseModel):
    """Bounded provenance summary for imported analysis artifacts."""

    enabled: bool = False
    artifacts: int = 0
    findings_imported: int = 0
    graph_edges_imported: int = 0
    tools: list[str] = Field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class RuntimeObservation(BaseModel):
    """Redacted HTTP or trace fact imported from an isolated runtime artifact."""

    id: str
    kind: str
    method: str = ""
    path: str = ""
    status_code: int | None = None
    duration_ms: float | None = None
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    repository_id: str = ""
    passed: bool | None = None
    provenance: EvidenceProvenance = Field(default_factory=EvidenceProvenance)


class RuntimeEvidenceSummary(BaseModel):
    """Coverage and bounds for imported HTTP/browser/proxy/trace evidence."""

    enabled: bool = False
    artifacts: int = 0
    observations: int = 0
    trace_edges: int = 0
    endpoint_links: int = 0
    tools: list[str] = Field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete result of a security scan."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository: str = ""
    branch: str = ""
    commit_sha: str = ""
    workspace_snapshot: str = ""
    status: ScanStatus = ScanStatus.COMPLETED
    findings: list[Finding] = Field(default_factory=list)
    endpoints: list[EndpointInfo] = Field(default_factory=list)
    frontend_calls: list[FrontendCall] = Field(default_factory=list)
    gateway_routes: list[GatewayRoute] = Field(default_factory=list)
    attack_surface_links: list[AttackSurfaceLink] = Field(default_factory=list)
    semantic_analysis: SemanticAnalysisSummary = Field(default_factory=SemanticAnalysisSummary)
    semantic_relationships: list[SemanticRelationship] = Field(default_factory=list)
    program_graph: ProgramGraphSummary = Field(default_factory=ProgramGraphSummary)
    taint_analysis: TaintAnalysisSummary = Field(default_factory=TaintAnalysisSummary)
    framework_analysis: FrameworkAnalysisSummary = Field(default_factory=FrameworkAnalysisSummary)
    external_analysis: ExternalAnalysisSummary = Field(default_factory=ExternalAnalysisSummary)
    runtime_observations: list[RuntimeObservation] = Field(default_factory=list)
    runtime_evidence: RuntimeEvidenceSummary = Field(default_factory=RuntimeEvidenceSummary)
    files_scanned: int = 0
    duration_seconds: float = 0.0
    token_usage: TokenUsage = Field(default_factory=lambda: TokenUsage())
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def findings_count(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def disposition_count(self) -> dict[str, int]:
        counts = {disposition.value: 0 for disposition in FindingDisposition}
        for finding in self.findings:
            counts[finding.disposition.value] += 1
        return counts


class TokenUsage(BaseModel):
    """Token usage tracking for LLM calls."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_cost_usd: float = 0.0


class ScanProgress(BaseModel):
    """Real-time scan progress update."""

    phase: int = 1
    phase_name: str = ""
    phase_total: int = 7
    progress: float = 0.0  # 0.0 - 1.0 within current phase
    overall_progress: float = 0.0  # 0.0 - 1.0 across all phases
    message: str = ""
    items_processed: int = 0
    items_total: int = 0
    elapsed_seconds: float = 0.0
    eta_seconds: float | None = None  # Estimated time remaining


# Type alias for progress callback
ScanProgressCallback = Any  # Callable[[ScanProgress], None]


# Forward reference updates
FileAST.model_rebuild()
