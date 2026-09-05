"""Role-scoped tool collection and normalized MCP evidence ingestion."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegify.agents.catalog import AgentSpec
from aegify.agents.models import AgentStageResult
from aegify.llm.tools import (
    AnalysisToolContext,
    ToolRegistry,
    ToolRequest,
    ToolResult,
    default_tool_registry,
    redact_sensitive,
)


class McpToolDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    name: str
    description: str
    read_only: bool = True
    input_schema: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_read_only(self) -> McpToolDescriptor:
        if not self.read_only:
            raise ValueError("agent MCP tools must be read-only")
        return self


class McpEvidenceEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    tool: str
    arguments_digest: str
    result: dict[str, Any]
    result_digest: str
    truncated: bool = False


class McpEvidenceBridge:
    """Normalize externally executed MCP results; this class never opens a connection itself."""

    def __init__(
        self,
        descriptors: list[McpToolDescriptor],
        *,
        max_input_bytes: int = 16_384,
        max_output_bytes: int = 65_536,
    ) -> None:
        self._tools = {(item.server, item.name): item for item in descriptors}
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes

    def normalize(
        self,
        server: str,
        tool: str,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> McpEvidenceEnvelope:
        if (server, tool) not in self._tools:
            raise ValueError("MCP tool is not allowlisted")
        input_bytes = json.dumps(arguments, sort_keys=True, default=str).encode()
        if len(input_bytes) > self.max_input_bytes:
            raise ValueError("MCP tool input exceeds limit")
        safe_result = redact_sensitive(dict(result))
        output_bytes = json.dumps(safe_result, sort_keys=True, default=str).encode()
        truncated = len(output_bytes) > self.max_output_bytes
        retained = (
            {
                "summary": "MCP output exceeded the evidence limit",
                "material_bytes": len(output_bytes),
            }
            if truncated
            else safe_result
        )
        assert isinstance(retained, dict)
        return McpEvidenceEnvelope(
            server=server,
            tool=tool,
            arguments_digest=_digest(input_bytes),
            result=retained,
            result_digest=_digest(output_bytes),
            truncated=truncated,
        )


class AgentToolCoordinator:
    """Collect only the read-only facts allowed for one agent role."""

    def __init__(self, registry: ToolRegistry | None = None, *, max_calls: int = 12) -> None:
        self.registry = registry or default_tool_registry()
        self.max_calls = max(0, min(max_calls, 30))

    def collect(
        self,
        spec: AgentSpec,
        stage: AgentStageResult,
        context: AnalysisToolContext,
    ) -> list[ToolResult]:
        requests: list[ToolRequest] = []
        if "workspace_summary" in spec.allowed_tools:
            requests.append(self._request(spec, "workspace_summary", {}))
        if "attack_surface" in spec.allowed_tools:
            requests.append(self._request(spec, "attack_surface", {}))
        for trace in stage.reachability[:5]:
            arguments = {"finding_id": trace.finding_id}
            for name in ("finding_context", "call_path"):
                if name in spec.allowed_tools:
                    requests.append(self._request(spec, name, arguments))
            if "harness_plan" in spec.allowed_tools:
                requests.append(self._request(spec, "harness_plan", arguments))
        return [self.registry.execute(request, context) for request in requests[: self.max_calls]]

    @staticmethod
    def _request(spec: AgentSpec, name: str, arguments: dict[str, Any]) -> ToolRequest:
        material = json.dumps(
            {"role": spec.role.value, "name": name, "arguments": arguments},
            sort_keys=True,
        )
        request_id = "tool-" + hashlib.sha256(material.encode()).hexdigest()[:20]
        return ToolRequest(request_id=request_id, name=name, arguments=arguments)


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()
