"""Strict contracts shared by Aegify security agents and API adapters."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AgentRole(StrEnum):
    SURFACE = "surface"
    STATIC = "static"
    DYNAMIC = "dynamic"
    SYNTHESIS = "synthesis"
    CVE = "cve"
    STEWARD = "steward"


class AgentRunMode(StrEnum):
    LITE = "lite"
    DEEP = "deep"


class AgentProvider(StrEnum):
    DETERMINISTIC = "deterministic"
    ANTHROPIC_API = "anthropic_api"
    OPENAI_API = "openai_api"
    CODEX_CLI = "codex_cli"
    CLAUDE_CODE = "claude_code"


class AgentStageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class AgentRunStatus(StrEnum):
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvidenceKind(StrEnum):
    STATIC = "static"
    SEMANTIC = "semantic"
    ATTACK_SURFACE = "attack_surface"
    RUNTIME = "runtime"
    CONTROL = "control"
    TOOL = "tool"


class CveApplicability(StrEnum):
    NOT_AFFECTED = "not_affected"
    VERSION_EXPOSED = "version_exposed"
    REACHABLE = "reachable"
    EXPLOITABLE_IN_FIXTURE = "exploitable_in_fixture"
    NEEDS_EVIDENCE = "needs_evidence"


class AgentNarrative(BaseModel):
    """Bounded model-authored text. Deterministic facts remain authoritative."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(max_length=12_000)
    claims: list[str] = Field(default_factory=list, max_length=50)
    evidence_gaps: list[str] = Field(default_factory=list, max_length=50)
    recommendations: list[str] = Field(default_factory=list, max_length=50)


class ReachabilityHop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    label: str
    file_path: str = ""
    line: int = Field(default=0, ge=0)
    evidence_id: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ReachabilityTrace(BaseModel):
    """Entry-to-sink path with explicit completeness and missing links."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    endpoint: str = ""
    method: str = ""
    entry_point: str = ""
    sink: str
    hops: list[ReachabilityHop] = Field(default_factory=list, max_length=200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=200)
    static_complete: bool = False
    runtime_observed: bool = False
    impact_proven: bool = False
    unresolved_links: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def evidence_invariants(self) -> ReachabilityTrace:
        if self.impact_proven and not self.runtime_observed:
            raise ValueError("impact_proven requires runtime_observed evidence")
        if self.static_complete and (not self.entry_point or not self.hops):
            raise ValueError("static_complete requires an entry point and at least one hop")
        return self


class AgentEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: EvidenceKind
    producer: str
    summary: str = Field(max_length=4_000)
    fidelity: str
    source_ref: str = ""
    digest: str = ""
    observed: bool = False

    @field_validator("digest")
    @classmethod
    def digest_is_sha256(cls, value: str) -> str:
        if value and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("digest must be sha256:<64 lowercase hex>")
        return value


class DynamicValidationPlan(BaseModel):
    """A non-destructive validation plan; execution requires a separate approval event."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    target_scope: str = "owned_fixture_only"
    target_origin: str = "http://127.0.0.1"
    harness: str = "http"
    request_template: str = ""
    payload_template: str = "{{SAFE_CANARY}}"
    expected_signal: str
    negative_control: str
    cleanup: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    destructive: bool = False

    @model_validator(mode="after")
    def enforce_safety_boundary(self) -> DynamicValidationPlan:
        if self.target_scope != "owned_fixture_only":
            raise ValueError("dynamic validation is restricted to owned fixtures")
        if not self.requires_approval or self.destructive:
            raise ValueError("dynamic validation must be approved and non-destructive")
        if not re.match(
            r"^http://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$", self.target_origin
        ):
            raise ValueError("dynamic target origin must be loopback HTTP")
        blocked = re.compile(
            r"(?:rm\s+-rf|drop\s+(?:database|table)|truncate\s+table|/etc/shadow|"
            r"169\.254\.169\.254|(?:curl|wget)[^\n|]*\|\s*(?:sh|bash))",
            re.IGNORECASE,
        )
        if blocked.search(self.payload_template) or blocked.search(self.request_template):
            raise ValueError("unsafe dynamic template")
        return self


class CveCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    package: str = ""
    installed_version: str = ""
    dependency_present: bool | None = None
    version_affected: bool | None = None
    component_reachable: bool | None = None
    runtime_verified: bool = False
    evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("cve_id")
    @classmethod
    def valid_cve(cls, value: str) -> str:
        candidate = value.upper()
        if not re.fullmatch(r"CVE-(?:19|20)\d{2}-\d{4,}", candidate):
            raise ValueError("invalid CVE identifier")
        return candidate


class CveAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    applicability: CveApplicability
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class ImprovementProposal(BaseModel):
    """Evaluation-gated proposal. It can never apply itself to production."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    category: str
    hypothesis: str
    target_metric: str
    minimum_samples: int = Field(default=30, ge=10)
    required_gates: list[str] = Field(
        default_factory=lambda: [
            "owned benchmark passes",
            "precision does not regress",
            "security policy review",
            "human approval",
        ]
    )
    status: str = "proposed"
    auto_apply: bool = False

    @model_validator(mode="after")
    def cannot_self_apply(self) -> ImprovementProposal:
        if self.auto_apply or self.status != "proposed":
            raise ValueError("agent improvement proposals require external evaluation and approval")
        return self


class AgentStageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: AgentRole
    agent_code: str
    agent_name: str
    status: AgentStageStatus
    summary: str
    facts: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    reachability: list[ReachabilityTrace] = Field(default_factory=list)
    dynamic_plans: list[DynamicValidationPlan] = Field(default_factory=list)
    cve_assessments: list[CveAssessment] = Field(default_factory=list)
    improvement_proposals: list[ImprovementProposal] = Field(default_factory=list)
    narrative: AgentNarrative | None = None
    prompt_digest: str = ""
    error: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None


class SecurityAgentRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: int = 1
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    repository: str = ""
    workspace_snapshot: str = ""
    mode: AgentRunMode = AgentRunMode.DEEP
    provider: AgentProvider = AgentProvider.DETERMINISTIC
    status: AgentRunStatus = AgentRunStatus.RUNNING
    stages: list[AgentStageResult] = Field(default_factory=list)
    evidence: list[AgentEvidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @property
    def artifact_digest(self) -> str:
        material = self.model_dump_json(
            exclude={"completed_at", "created_at"},
            exclude_none=True,
        )
        return "sha256:" + hashlib.sha256(material.encode()).hexdigest()
