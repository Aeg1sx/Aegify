"""Deterministic security-agent pipeline with optional bounded model narratives."""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from aegify.agents.backends import AgentBackend
from aegify.agents.catalog import AGENT_CATALOG, AgentSpec
from aegify.agents.models import (
    AgentEvidence,
    AgentProvider,
    AgentRole,
    AgentRunMode,
    AgentRunStatus,
    AgentStageResult,
    AgentStageStatus,
    CveApplicability,
    CveAssessment,
    CveCandidate,
    DynamicValidationPlan,
    EvidenceKind,
    ImprovementProposal,
    ReachabilityHop,
    ReachabilityTrace,
    SecurityAgentRun,
)
from aegify.agents.tools import AgentToolCoordinator
from aegify.llm.tools import AnalysisToolContext, ToolRegistry
from aegify.models import EndpointInfo, EvidenceState, Finding, ScanResult


class SecurityAgentPipeline:
    """Build claim-evidence artifacts; model text never mutates deterministic facts."""

    def __init__(
        self,
        backend: AgentBackend | None = None,
        *,
        tool_registry: ToolRegistry | None = None,
    ) -> None:
        self.backend = backend
        self.tools = AgentToolCoordinator(tool_registry)

    def run(
        self,
        scan: ScanResult,
        *,
        mode: AgentRunMode = AgentRunMode.DEEP,
        cves: list[CveCandidate] | None = None,
    ) -> SecurityAgentRun:
        provider = self._provider()
        run = SecurityAgentRun(
            scan_id=scan.id,
            repository=scan.repository,
            workspace_snapshot=scan.workspace_snapshot,
            mode=mode,
            provider=provider,
        )
        evidence = self._evidence(scan)
        run.evidence = evidence
        tool_context = AnalysisToolContext(
            findings={finding.id: finding for finding in scan.findings},
            workspace={
                "workspace_snapshot": scan.workspace_snapshot,
                "repositories": sorted(
                    {
                        endpoint.repository_id
                        for endpoint in scan.endpoints
                        if endpoint.repository_id
                    }
                ),
                "semantic_summary": scan.semantic_analysis.model_dump(mode="json"),
                "runtime_evidence_summary": scan.runtime_evidence.model_dump(mode="json"),
                "attack_surface": [
                    endpoint.model_dump(mode="json") for endpoint in scan.endpoints[:500]
                ],
            },
        )
        traces = [self._trace(finding, scan.endpoints, scan) for finding in scan.findings]
        stages = [
            self._surface(scan, evidence),
            self._static(scan, traces, mode),
            self._dynamic(scan, traces),
            self._cve(cves or [], {observation.id for observation in scan.runtime_observations}),
            self._synthesis(scan, traces),
            self._steward(scan, traces),
        ]
        for stage in stages:
            run.evidence.extend(self._attach_narrative(stage, tool_context))
            run.stages.append(stage)
        run.status = (
            AgentRunStatus.AWAITING_APPROVAL
            if any(stage.status == AgentStageStatus.WAITING_APPROVAL for stage in stages)
            else AgentRunStatus.COMPLETED
        )
        if run.status == AgentRunStatus.COMPLETED:
            run.completed_at = datetime.now(UTC)
        return run

    def _provider(self) -> AgentProvider:
        if self.backend is None:
            return AgentProvider.DETERMINISTIC
        try:
            return AgentProvider(self.backend.provider_name)
        except ValueError:
            return AgentProvider.DETERMINISTIC

    @staticmethod
    def _evidence(scan: ScanResult) -> list[AgentEvidence]:
        output: list[AgentEvidence] = []
        for finding in scan.findings:
            evidence_id = finding.provenance.evidence_id or f"finding:{finding.id}"
            output.append(
                AgentEvidence(
                    id=evidence_id,
                    kind=EvidenceKind.STATIC,
                    producer=finding.provenance.producer or "aegify-scanner",
                    summary=f"{finding.rule_id} at {finding.file_path}:{finding.line_start}",
                    fidelity=finding.provenance.fidelity or "heuristic",
                    source_ref=f"{finding.file_path}:{finding.line_start}-{finding.line_end}",
                    digest=_digest(finding.code_snippet or finding.message),
                    observed=False,
                )
            )
        for index, endpoint in enumerate(scan.endpoints):
            material = (
                f"{endpoint.repository_id}:{endpoint.method}:{endpoint.path}:{endpoint.file_path}"
            )
            output.append(
                AgentEvidence(
                    id=f"surface:{hashlib.sha256(material.encode()).hexdigest()[:20]}",
                    kind=EvidenceKind.ATTACK_SURFACE,
                    producer="aegify-attack-surface",
                    summary=f"{endpoint.method} {endpoint.path} -> {endpoint.handler_function}",
                    fidelity="runtime-correlated"
                    if endpoint.runtime_observed
                    else "static-correlated",
                    source_ref=f"{endpoint.file_path}:{endpoint.line_start}",
                    digest=_digest(material),
                    observed=endpoint.runtime_observed,
                )
            )
        for observation in scan.runtime_observations:
            output.append(
                AgentEvidence(
                    id=observation.id,
                    kind=EvidenceKind.RUNTIME,
                    producer=observation.provenance.producer or "aegify-runtime-importer",
                    summary=(
                        f"Observed {observation.method} {observation.path} "
                        f"status={observation.status_code}"
                    ),
                    fidelity=observation.provenance.fidelity or observation.kind,
                    source_ref=observation.path,
                    digest=observation.provenance.rule_digest,
                    observed=True,
                )
            )
        return output

    @staticmethod
    def _trace(
        finding: Finding,
        endpoints: list[EndpointInfo],
        scan: ScanResult,
    ) -> ReachabilityTrace:
        endpoint = next(
            (
                item
                for item in endpoints
                if item.file_path == finding.file_path
                or any(step.file_path == item.file_path for step in finding.call_chain)
            ),
            None,
        )
        evidence_id = finding.provenance.evidence_id or f"finding:{finding.id}"
        hops = [
            ReachabilityHop(
                kind="call",
                label=step.function,
                file_path=step.file_path,
                line=step.line,
                evidence_id=evidence_id,
                confidence=finding.confidence,
            )
            for step in finding.call_chain
        ]
        runtime_observed = bool(endpoint and endpoint.runtime_observed)
        impact_proven = finding.evidence_state == EvidenceState.IMPACT_PROVEN and runtime_observed
        static_complete = bool(endpoint and hops)
        unresolved: list[str] = []
        if endpoint is None:
            unresolved.append("No endpoint-to-finding correlation was produced")
        if not hops:
            unresolved.append("No entry-to-sink call chain was produced")
        if not runtime_observed:
            unresolved.append("No runtime observation is linked to this path")
        ids = [evidence_id]
        if endpoint is not None:
            material = (
                f"{endpoint.repository_id}:{endpoint.method}:{endpoint.path}:{endpoint.file_path}"
            )
            ids.append(f"surface:{hashlib.sha256(material.encode()).hexdigest()[:20]}")
        ids.extend(
            observation.id
            for observation in scan.runtime_observations
            if endpoint is not None
            and observation.method == endpoint.method
            and observation.path == endpoint.path
        )
        return ReachabilityTrace(
            finding_id=finding.id,
            endpoint=endpoint.path if endpoint else "",
            method=endpoint.method if endpoint else "",
            entry_point=(finding.call_chain[0].function if finding.call_chain else ""),
            sink=f"{finding.file_path}:{finding.line_start}",
            hops=hops,
            evidence_ids=list(dict.fromkeys(ids)),
            static_complete=static_complete,
            runtime_observed=runtime_observed,
            impact_proven=impact_proven,
            unresolved_links=unresolved,
        )

    @staticmethod
    def _surface(scan: ScanResult, evidence: list[AgentEvidence]) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.SURFACE]
        public = [endpoint for endpoint in scan.endpoints if not endpoint.auth_required]
        facts = {
            "repositories": sorted(
                {item.repository_id for item in scan.endpoints if item.repository_id}
            ),
            "endpoints": len(scan.endpoints),
            "endpoints_without_detected_auth": len(public),
            "frontend_linked": sum(item.called_by_frontend for item in scan.endpoints),
            "gateway_exposed": sum(item.exposed_via_gateway for item in scan.endpoints),
            "runtime_observed": sum(item.runtime_observed for item in scan.endpoints),
            "frameworks": dict(Counter(item.framework or "unknown" for item in scan.endpoints)),
            "threat_scenarios": [
                {
                    "surface": f"{item.method} {item.path}",
                    "trust_boundary": "external-to-application",
                    "auth": "not detected" if not item.auth_required else "detected",
                    "runtime": item.runtime_observed,
                }
                for item in public[:100]
            ],
        }
        return _stage(
            spec,
            AgentStageStatus.COMPLETED,
            (
                f"Mapped {len(scan.endpoints)} endpoints; "
                f"{len(public)} have no detected auth evidence."
            ),
            facts,
            [item.id for item in evidence if item.kind == EvidenceKind.ATTACK_SURFACE],
        )

    @staticmethod
    def _static(
        scan: ScanResult,
        traces: list[ReachabilityTrace],
        mode: AgentRunMode,
    ) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.STATIC]
        complete = sum(trace.static_complete for trace in traces)
        observed = sum(trace.runtime_observed for trace in traces)
        facts = {
            "mode": mode.value,
            "findings": len(scan.findings),
            "severity": dict(Counter(finding.severity.value for finding in scan.findings)),
            "evidence_state": dict(
                Counter(finding.evidence_state.value for finding in scan.findings)
            ),
            "complete_static_paths": complete,
            "runtime_correlated_paths": observed,
            "semantic_fidelity": scan.semantic_analysis.fidelity,
            "program_graph_fidelity": scan.program_graph.fidelity,
            "taint_fidelity": scan.taint_analysis.fidelity,
        }
        status = (
            AgentStageStatus.COMPLETED
            if not scan.findings or complete
            else AgentStageStatus.PARTIAL
        )
        return _stage(
            spec,
            status,
            (
                f"Reviewed {len(scan.findings)} findings; "
                f"{complete} have endpoint-to-sink static paths."
            ),
            facts,
            [evidence_id for trace in traces for evidence_id in trace.evidence_ids],
            reachability=traces,
        )

    @staticmethod
    def _dynamic(scan: ScanResult, traces: list[ReachabilityTrace]) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.DYNAMIC]
        plans: list[DynamicValidationPlan] = []
        findings = {finding.id: finding for finding in scan.findings}
        for trace in traces:
            if not trace.static_complete or trace.runtime_observed:
                continue
            finding = findings[trace.finding_id]
            plans.append(
                DynamicValidationPlan(
                    finding_id=finding.id,
                    harness="http" if trace.endpoint else "container",
                    request_template=(
                        f"{trace.method or 'GET'} {trace.endpoint or '/{{FIXTURE_PATH}}'}"
                    ),
                    expected_signal=(
                        f"A bounded canary reaches {trace.sink} and is recorded by the fixture"
                    ),
                    negative_control=(
                        "The same request without {{SAFE_CANARY}} does not produce the signal"
                    ),
                    cleanup=[
                        "Stop the ephemeral fixture",
                        "Verify the container and temporary artifacts are removed",
                    ],
                )
            )
        facts = {
            "runtime_artifacts": scan.runtime_evidence.artifacts,
            "runtime_observations": scan.runtime_evidence.observations,
            "already_observed_paths": sum(trace.runtime_observed for trace in traces),
            "approval_required_plans": len(plans),
            "execution_policy": (
                "owned loopback fixture, non-destructive, negative control required"
            ),
        }
        status = AgentStageStatus.WAITING_APPROVAL if plans else AgentStageStatus.COMPLETED
        summary = (
            (
                f"Prepared {len(plans)} bounded validation plans; "
                "no plan was executed without approval."
            )
            if plans
            else "No unobserved complete static path required a new dynamic plan."
        )
        return _stage(
            spec,
            status,
            summary,
            facts,
            [
                evidence_id
                for trace in traces
                if trace.runtime_observed
                for evidence_id in trace.evidence_ids
            ],
            reachability=traces,
            dynamic_plans=plans,
        )

    @staticmethod
    def _cve(
        candidates: list[CveCandidate],
        trusted_runtime_evidence: set[str],
    ) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.CVE]
        assessments: list[CveAssessment] = []
        for candidate in candidates:
            missing: list[str] = []
            if candidate.dependency_present is None:
                missing.append("component presence")
            if candidate.version_affected is None:
                missing.append("affected version evaluation")
            if candidate.component_reachable is None:
                missing.append("component reachability")
            runtime_evidence_bound = bool(
                candidate.runtime_verified
                and trusted_runtime_evidence.intersection(candidate.evidence_ids)
            )
            if candidate.runtime_verified and not runtime_evidence_bound:
                missing.append("approved runtime evidence bound to this scan")
            if candidate.dependency_present is False or candidate.version_affected is False:
                applicability = CveApplicability.NOT_AFFECTED
                rationale = "The supplied inventory or version evidence excludes this environment."
            elif runtime_evidence_bound:
                applicability = CveApplicability.EXPLOITABLE_IN_FIXTURE
                rationale = "An approved owned-fixture validation was supplied as runtime evidence."
            elif candidate.component_reachable is True and candidate.version_affected is True:
                applicability = CveApplicability.REACHABLE
                rationale = (
                    "The affected version is present and a component path is supplied; "
                    "exploitability is unproven."
                )
            elif candidate.dependency_present is True and candidate.version_affected is True:
                applicability = CveApplicability.VERSION_EXPOSED
                rationale = (
                    "The affected version is present; application reachability is unresolved."
                )
            else:
                applicability = CveApplicability.NEEDS_EVIDENCE
                rationale = "The supplied CVE cannot be classified without the missing evidence."
            assessments.append(
                CveAssessment(
                    cve_id=candidate.cve_id,
                    applicability=applicability,
                    rationale=rationale,
                    evidence_ids=candidate.evidence_ids,
                    missing_evidence=missing,
                )
            )
        return _stage(
            spec,
            AgentStageStatus.COMPLETED,
            f"Assessed {len(assessments)} supplied CVE candidates.",
            {"candidates": len(assessments)},
            [item for assessment in assessments for item in assessment.evidence_ids],
            cve_assessments=assessments,
        )

    @staticmethod
    def _synthesis(scan: ScanResult, traces: list[ReachabilityTrace]) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.SYNTHESIS]
        trace_by_finding = {trace.finding_id: trace for trace in traces}
        findings: list[dict[str, Any]] = []
        for finding in scan.findings:
            trace = trace_by_finding[finding.id]
            likelihood = (
                "demonstrated_in_fixture"
                if trace.impact_proven
                else "observed_surface"
                if trace.runtime_observed
                else "statically_reachable"
                if trace.static_complete
                else "unresolved"
            )
            findings.append(
                {
                    "finding_id": finding.id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "likelihood": likelihood,
                    "attack_surface": f"{trace.method} {trace.endpoint}".strip(),
                    "preconditions": trace.unresolved_links,
                    "remediation": finding.remediation
                    or "Rule-specific remediation review required",
                    "evidence_ids": trace.evidence_ids,
                }
            )
        return _stage(
            spec,
            AgentStageStatus.COMPLETED,
            f"Reconciled {len(findings)} findings without upgrading unproven claims.",
            {"findings": findings},
            [evidence_id for trace in traces for evidence_id in trace.evidence_ids],
            reachability=traces,
        )

    @staticmethod
    def _steward(scan: ScanResult, traces: list[ReachabilityTrace]) -> AgentStageResult:
        spec = AGENT_CATALOG[AgentRole.STEWARD]
        proposals: list[ImprovementProposal] = []
        unresolved_paths = sum(not trace.static_complete for trace in traces)
        unobserved_paths = sum(
            trace.static_complete and not trace.runtime_observed for trace in traces
        )
        if unresolved_paths:
            proposals.append(
                ImprovementProposal(
                    title="Expand endpoint-to-sink reachability corpus",
                    category="reachability",
                    hypothesis=(
                        f"Framework models can close {unresolved_paths} currently unresolved paths."
                    ),
                    target_metric="recall and complete-path rate without precision regression",
                )
            )
        if unobserved_paths:
            proposals.append(
                ImprovementProposal(
                    title="Grow owned-fixture dynamic validation coverage",
                    category="dynamic-validation",
                    hypothesis=(
                        f"Bounded harness fixtures can validate {unobserved_paths} "
                        "complete static paths."
                    ),
                    target_metric="runtime-correlated path coverage and false-positive reduction",
                )
            )
        if scan.runtime_evidence.truncated:
            proposals.append(
                ImprovementProposal(
                    title="Tune runtime evidence bounds",
                    category="evidence-ingestion",
                    hypothesis=(
                        "A representative sampled corpus can reduce truncation without "
                        "retaining secrets."
                    ),
                    target_metric="endpoint observation coverage under storage and privacy limits",
                )
            )
        return _stage(
            spec,
            AgentStageStatus.COMPLETED,
            f"Proposed {len(proposals)} evaluation-gated improvements; none were auto-applied.",
            {
                "unresolved_paths": unresolved_paths,
                "unobserved_complete_paths": unobserved_paths,
                "auto_apply": False,
            },
            [],
            improvement_proposals=proposals,
        )

    def _attach_narrative(
        self,
        stage: AgentStageResult,
        context: AnalysisToolContext,
    ) -> list[AgentEvidence]:
        if self.backend is None:
            return []
        spec = AGENT_CATALOG[stage.role]
        tool_results = self.tools.collect(spec, stage, context)
        payload = {
            "deterministic_summary": stage.summary,
            "facts": stage.facts,
            "evidence_ids": stage.evidence_ids,
            "required_evidence": spec.required_evidence,
            "tools": [result.model_dump(mode="json") for result in tool_results],
        }
        try:
            stage.narrative = self.backend.invoke(spec, payload)
        except Exception as error:
            stage.error = str(error)[:1_000]
            if stage.status == AgentStageStatus.COMPLETED:
                stage.status = AgentStageStatus.PARTIAL
        return [
            AgentEvidence(
                id=f"tool:{result.request_id}",
                kind=EvidenceKind.TOOL,
                producer=result.name,
                summary=result.error or str(result.output.get("summary", "tool evidence")),
                fidelity="read-only-tool",
                source_ref=result.name,
                digest=_digest(result.model_dump_json()),
                observed=False,
            )
            for result in tool_results
        ]


def _stage(
    spec: AgentSpec,
    status: AgentStageStatus,
    summary: str,
    facts: dict[str, Any],
    evidence_ids: list[str],
    **kwargs: Any,
) -> AgentStageResult:
    return AgentStageResult(
        role=spec.role,
        agent_code=spec.code,
        agent_name=spec.name,
        status=status,
        summary=summary,
        facts=facts,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        prompt_digest=spec.prompt_digest,
        completed_at=datetime.now(UTC),
        **kwargs,
    )


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
