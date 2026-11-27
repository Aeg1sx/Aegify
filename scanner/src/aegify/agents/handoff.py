"""Bounded handoffs between the source review stages of a single scan."""

from __future__ import annotations

import re
from typing import Any

from aegify.agents.models import AgentRole, AgentStageResult, AgentStageStatus

_MAX_REFS = 16
_REFERENCE = re.compile(r"[a-zA-Z0-9_.:/@-]{1,160}")
_INPUTS = {
    AgentRole.STATIC: (AgentRole.SURFACE,),
    AgentRole.SYNTHESIS: (AgentRole.SURFACE, AgentRole.STATIC),
}


def review_handoff(
    role: AgentRole, completed: list[AgentStageResult], known_evidence: set[str]
) -> dict[str, Any] | None:
    if role not in _INPUTS:
        return None
    inputs = []
    gaps = []
    for stage in completed:
        if stage.role not in _INPUTS[role]:
            continue
        ids = dict.fromkeys(stage.evidence_ids)
        selected = [ref for ref in ids if ref in known_evidence and _REFERENCE.fullmatch(ref)]
        trace = stage.exploration
        citations = {c.citation_id: c for c in trace.citations} if trace else {}
        selected_citations = list(citations.values())[:_MAX_REFS]
        inputs.append(
            {
                "role": stage.role.value,
                "status": stage.status.value,
                "evidenceIds": selected[:_MAX_REFS],
                "omittedEvidence": len(ids) - min(_MAX_REFS, len(selected)),
                "sourceCitationIds": [c.citation_id for c in selected_citations],
                "sourceLocations": [
                    {
                        "repositoryId": c.repository_id,
                        "path": c.path,
                        "lineStart": c.line_start,
                        "lineEnd": c.line_end,
                        "citationId": c.citation_id,
                    }
                    for c in selected_citations
                ],
                "omittedCitations": max(0, len(citations) - _MAX_REFS),
            }
        )
        if stage.status in {AgentStageStatus.PARTIAL, AgentStageStatus.FAILED}:
            gaps.append(f"The {stage.role.value} review was incomplete.")
        if stage.role == AgentRole.SURFACE:
            if not stage.facts.get("endpoints"):
                gaps.append("The scan supplied no endpoint inventory.")
            elif stage.facts.get("endpoints_without_detected_auth"):
                gaps.append("Authentication enforcement is unresolved for some endpoints.")
        else:
            if any(not path.static_complete for path in stage.reachability):
                gaps.append("Some findings lack a complete source path.")
            ownership = stage.facts.get("gatewayOwnership", {})
            if ownership.get("ambiguous") or ownership.get("unresolved"):
                gaps.append("Some declared gateway routes lack a unique repository owner.")
            if ownership.get("inputStatus") == "partial":
                gaps.append("Gateway configuration coverage was incomplete.")
    return {"version": 1, "inputs": inputs, "gaps": gaps}


def provider_facts(stage: AgentStageResult) -> dict[str, Any]:
    """Keep the complete result in the run while bounding the synthesis prompt."""
    findings = stage.facts.get("findings")
    if stage.role != AgentRole.SYNTHESIS or not isinstance(findings, list):
        return stage.facts
    return {
        **stage.facts,
        "findings": findings[:25],
        "omitted_findings": max(0, len(findings) - 25),
    }
