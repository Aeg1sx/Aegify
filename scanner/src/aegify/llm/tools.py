"""Allowlisted, read-only tools for evidence-bound AI SAST review."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from aegify.models import Finding

_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_SENSITIVE_KEYS = re.compile(r"token|secret|password|authorization|api[_-]?key", re.I)


class ToolSpec(BaseModel):
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    read_only: bool = True


class ToolRequest(BaseModel):
    request_id: str = ""
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    request_id: str = ""
    name: str
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    truncated: bool = False


@dataclass(frozen=True)
class AnalysisToolContext:
    findings: Mapping[str, Finding] = field(default_factory=dict)
    workspace: Mapping[str, Any] = field(default_factory=dict)


ToolHandler = Callable[[dict[str, Any], AnalysisToolContext], dict[str, Any]]


class ToolRegistry:
    """Registers explicit Python handlers; it never invokes a shell or network."""

    def __init__(self, *, max_input_bytes: int = 16_384, max_output_bytes: int = 65_536) -> None:
        self._tools: dict[str, tuple[ToolSpec, ToolHandler]] = {}
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes

    def register(self, spec: ToolSpec, handler: ToolHandler) -> None:
        if not _TOOL_NAME.fullmatch(spec.name):
            raise ValueError(f"invalid tool name: {spec.name!r}")
        if not spec.read_only:
            raise ValueError("AI analysis tools must be read-only")
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = (spec, handler)

    def specs(self) -> list[ToolSpec]:
        return [spec.model_copy(deep=True) for spec, _handler in self._tools.values()]

    def execute(self, request: ToolRequest, context: AnalysisToolContext) -> ToolResult:
        registered = self._tools.get(request.name)
        if registered is None:
            return ToolResult(
                request_id=request.request_id,
                name=request.name,
                ok=False,
                error="tool is not allowlisted",
            )
        encoded_input = json.dumps(request.arguments, sort_keys=True, default=str).encode()
        if len(encoded_input) > self.max_input_bytes:
            return ToolResult(
                request_id=request.request_id,
                name=request.name,
                ok=False,
                error="tool input exceeds limit",
            )

        _spec, handler = registered
        try:
            output = redact_sensitive(handler(dict(request.arguments), context))
            encoded_output = json.dumps(output, sort_keys=True, default=str).encode()
            if len(encoded_output) > self.max_output_bytes:
                return ToolResult(
                    request_id=request.request_id,
                    name=request.name,
                    ok=True,
                    output={
                        "summary": "tool output exceeded the evidence limit",
                        "material_bytes": len(encoded_output),
                    },
                    truncated=True,
                )
            return ToolResult(
                request_id=request.request_id,
                name=request.name,
                ok=True,
                output=output,
            )
        except Exception as exc:
            return ToolResult(
                request_id=request.request_id,
                name=request.name,
                ok=False,
                error=str(redact_sensitive(str(exc)))[:500],
            )


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEYS.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
            value,
        )
        value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", "Bearer [REDACTED]", value)
        value = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED_AWS_KEY]", value)
        value = re.sub(
            r"\b(?:sk-ant-|sk-proj-|sk-)[A-Za-z0-9_-]{16,}\b",
            "[REDACTED_API_KEY]",
            value,
        )
        value = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED_GITHUB_TOKEN]", value)
        value = re.sub(r"\bAIza[A-Za-z0-9_-]{20,}\b", "[REDACTED_GOOGLE_KEY]", value)
        value = re.sub(
            r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+",
            r"\1=[REDACTED]",
            value,
        )
    return value


def redact_sensitive(value: Any) -> Any:
    """Return a recursively redacted copy safe to persist as AI evidence."""
    return _redact(value)


def _finding(arguments: dict[str, Any], context: AnalysisToolContext) -> Finding:
    finding_id = str(arguments.get("finding_id", ""))
    if not finding_id or finding_id not in context.findings:
        raise ValueError("finding_id is required and must exist in this review")
    return context.findings[finding_id]


def _finding_context(arguments: dict[str, Any], context: AnalysisToolContext) -> dict[str, Any]:
    finding = _finding(arguments, context)
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "location": {
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "line_end": finding.line_end,
        },
        "message": finding.message,
        "code_snippet": finding.code_snippet[:12_000],
        "taint_flow": finding.taint_flow.model_dump(mode="json") if finding.taint_flow else None,
        "defense_context": finding.defense_context.model_dump(mode="json"),
        "provenance": finding.provenance.model_dump(mode="json"),
    }


def _call_path(arguments: dict[str, Any], context: AnalysisToolContext) -> dict[str, Any]:
    finding = _finding(arguments, context)
    return {
        "finding_id": finding.id,
        "steps": [step.model_dump(mode="json") for step in finding.call_chain[:100]],
        "complete": bool(finding.call_chain),
    }


def _attack_surface(arguments: dict[str, Any], context: AnalysisToolContext) -> dict[str, Any]:
    repository_id = str(arguments.get("repository_id", ""))
    surfaces = context.workspace.get("attack_surface", [])
    if not isinstance(surfaces, list):
        surfaces = []
    filtered = [
        item
        for item in surfaces
        if isinstance(item, Mapping)
        and (not repository_id or item.get("repository_id") == repository_id)
    ]
    return {"repository_id": repository_id, "items": filtered[:250], "total": len(filtered)}


def _workspace_summary(_arguments: dict[str, Any], context: AnalysisToolContext) -> dict[str, Any]:
    allowed = {
        "workspace_snapshot",
        "repositories",
        "languages",
        "semantic_summary",
        "runtime_evidence_summary",
    }
    return {key: context.workspace[key] for key in allowed if key in context.workspace}


def _harness_plan(arguments: dict[str, Any], context: AnalysisToolContext) -> dict[str, Any]:
    finding = _finding(arguments, context)
    return {
        "finding_id": finding.id,
        "mode": "plan_only",
        "authorization": "owned_fixture_required",
        "requires_human_approval": True,
        "steps": [
            "Select an owned or explicitly authorized test fixture",
            "Capture a negative control before introducing the bounded payload",
            "Run through the Aegify HTTP, browser, proxy, or container harness",
            "Record the exact request, response signal, logs, and cleanup result",
        ],
        "prohibited": [
            "production targets without explicit authorization",
            "destructive payloads",
            "credential extraction",
            "persistence or lateral movement",
        ],
    }


def default_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    definitions: list[tuple[ToolSpec, ToolHandler]] = [
        (
            ToolSpec(
                name="finding_context",
                description="Return bounded code, taint, defense, and provenance evidence.",
                input_schema={"type": "object", "required": ["finding_id"]},
            ),
            _finding_context,
        ),
        (
            ToolSpec(
                name="call_path",
                description="Return the static call chain attached to a finding.",
                input_schema={"type": "object", "required": ["finding_id"]},
            ),
            _call_path,
        ),
        (
            ToolSpec(
                name="attack_surface",
                description="Return correlated endpoint, gateway, client, and runtime evidence.",
                input_schema={"type": "object"},
            ),
            _attack_surface,
        ),
        (
            ToolSpec(
                name="workspace_summary",
                description="Return the multi-repository snapshot and semantic analysis summary.",
                input_schema={"type": "object"},
            ),
            _workspace_summary,
        ),
        (
            ToolSpec(
                name="harness_plan",
                description="Create a non-executing, approval-gated validation plan.",
                input_schema={"type": "object", "required": ["finding_id"]},
            ),
            _harness_plan,
        ),
    ]
    for spec, handler in definitions:
        registry.register(spec, handler)
    return registry
