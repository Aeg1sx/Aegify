"""Model adapters for API calls and read-only Codex or Claude Code processes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aegify.agents.catalog import AgentSpec
from aegify.agents.models import AgentNarrative
from aegify.llm.client import LLMClient
from aegify.llm.tools import redact_sensitive


class AgentBackend(Protocol):
    provider_name: str

    def invoke(self, spec: AgentSpec, payload: Mapping[str, Any]) -> AgentNarrative: ...


class AnthropicAPIBackend:
    provider_name = "anthropic_api"

    def __init__(self, client: LLMClient) -> None:
        self.client = client

    def invoke(self, spec: AgentSpec, payload: Mapping[str, Any]) -> AgentNarrative:
        response = self.client.query(
            spec.system_prompt,
            _prompt(payload),
            phase=f"agent:{spec.role.value}",
            max_tokens=4_096,
        )
        if not isinstance(response, dict):
            raise RuntimeError("model did not return a JSON object")
        return AgentNarrative.model_validate(redact_sensitive(response))


class OpenAIResponsesBackend:
    """OpenAI Responses API adapter using strict JSON Schema output."""

    provider_name = "openai_api"

    def __init__(
        self,
        api_key: str,
        *,
        model: str,
        timeout_seconds: int = 120,
    ) -> None:
        if not api_key:
            raise ValueError("OpenAI API key is required")
        if not model:
            raise ValueError("OpenAI model is required")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = max(10, min(timeout_seconds, 300))

    def invoke(self, spec: AgentSpec, payload: Mapping[str, Any]) -> AgentNarrative:
        request_body = {
            "model": self.model,
            "instructions": spec.system_prompt,
            "input": _prompt(payload),
            "max_output_tokens": 4_096,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "aegify_agent_narrative",
                    "strict": True,
                    "schema": AgentNarrative.model_json_schema(),
                }
            },
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(request_body).encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            detail = error.read(2_000).decode("utf-8", errors="replace")
            raise RuntimeError(_bounded_error(detail, "OpenAI API request failed")) from error
        except (OSError, TimeoutError) as error:
            raise RuntimeError(f"OpenAI API unavailable: {error}") from error
        if len(raw) > 2_000_000:
            raise RuntimeError("OpenAI API response exceeded configured limit")
        envelope = json.loads(raw)
        if not isinstance(envelope, dict):
            raise ValueError("OpenAI API response must be an object")
        output_text = str(envelope.get("output_text", ""))
        if not output_text:
            for item in envelope.get("output", []):
                if not isinstance(item, dict):
                    continue
                for content in item.get("content", []):
                    if isinstance(content, dict) and content.get("type") == "output_text":
                        output_text = str(content.get("text", ""))
                        break
        return AgentNarrative.model_validate(redact_sensitive(_extract_json(output_text)))


class CommandBackendConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    executable: str
    model: str = ""
    timeout_seconds: int = Field(default=300, ge=10, le=1_800)
    max_output_bytes: int = Field(default=1_000_000, ge=1_024, le=10_000_000)
    inherit_environment: list[str] = Field(
        default_factory=lambda: [
            "PATH",
            "CODEX_HOME",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
        ]
    )


class CommandAgentBackend:
    """Run a known agent CLI without a shell, writes, or interactive approvals."""

    def __init__(self, config: CommandBackendConfig, workspace: Path) -> None:
        if config.kind not in {"codex", "claude"}:
            raise ValueError("command backend kind must be codex or claude")
        resolved = shutil.which(config.executable)
        if not resolved:
            raise ValueError(f"agent executable is unavailable: {config.executable}")
        self.config = config
        self.executable = resolved
        self.workspace = workspace.resolve()
        if not self.workspace.is_dir():
            raise ValueError("agent workspace must be an existing directory")
        self.provider_name = "codex_cli" if config.kind == "codex" else "claude_code"

    def invoke(self, spec: AgentSpec, payload: Mapping[str, Any]) -> AgentNarrative:
        prompt = spec.system_prompt + "\n\nINPUT JSON:\n" + _prompt(payload)
        environment = {
            key: os.environ[key] for key in self.config.inherit_environment if key in os.environ
        }
        environment["AEGIFY_AGENT_MODE"] = "read_only"
        with tempfile.TemporaryDirectory(prefix="aegify-agent-") as temporary:
            temp = Path(temporary)
            if self.config.kind == "codex":
                output_path = temp / "last-message.json"
                schema_path = temp / "response.schema.json"
                schema_path.write_text(
                    json.dumps(AgentNarrative.model_json_schema(), sort_keys=True),
                    encoding="utf-8",
                )
                command = [
                    self.executable,
                    "exec",
                    "--sandbox",
                    "read-only",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "--output-schema",
                    str(schema_path),
                    "--output-last-message",
                    str(output_path),
                    "--cd",
                    str(self.workspace),
                ]
                if self.config.model:
                    command.extend(["--model", self.config.model])
                command.append("-")
                completed = self._run(command, prompt, environment)
                if not output_path.is_file():
                    raise RuntimeError(_bounded_error(completed.stderr, "Codex produced no output"))
                raw = output_path.read_bytes()[: self.config.max_output_bytes].decode(
                    "utf-8", errors="replace"
                )
            else:
                command = [
                    self.executable,
                    "-p",
                    "--output-format",
                    "json",
                    "--permission-mode",
                    "plan",
                    "--max-turns",
                    "1",
                ]
                if self.config.model:
                    command.extend(["--model", self.config.model])
                completed = self._run(command, prompt, environment)
                wrapper = json.loads(completed.stdout)
                raw = str(wrapper.get("result", "")) if isinstance(wrapper, dict) else ""
            parsed = _extract_json(raw)
            return AgentNarrative.model_validate(redact_sensitive(parsed))

    def _run(
        self,
        command: list[str],
        prompt: str,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                command,
                cwd=self.workspace,
                env=environment,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(f"agent process unavailable: {error}") from error
        if len(result.stdout.encode()) > self.config.max_output_bytes:
            raise RuntimeError("agent output exceeded configured limit")
        if result.returncode != 0:
            raise RuntimeError(_bounded_error(result.stderr, "agent process failed"))
        return result


def _prompt(payload: Mapping[str, Any]) -> str:
    bounded = json.dumps(redact_sensitive(dict(payload)), sort_keys=True, default=str)
    if len(bounded.encode()) > 500_000:
        raise ValueError("agent input exceeds 500000 bytes")
    schema = AgentNarrative.model_json_schema()
    return json.dumps(
        {"input": json.loads(bounded), "required_output_schema": schema},
        sort_keys=True,
    )


def _extract_json(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("agent response did not contain JSON") from None
        value = json.loads(raw[start : end + 1])
    if not isinstance(value, dict):
        raise ValueError("agent response must be a JSON object")
    return value


def _bounded_error(value: str, fallback: str) -> str:
    redacted = str(redact_sensitive(value or fallback))
    return redacted[:1_000]
