"""Model adapters for API calls and read-only Codex or Claude Code processes."""

from __future__ import annotations

import json
import os
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
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


class AgentBackendError(RuntimeError):
    """A stable stop code and a bounded message without provider/source content."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise AgentBackendError("provider_error", "OpenAI API redirect was rejected")


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
                    "schema": _narrative_schema(),
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
            opener = urllib.request.build_opener(_NoRedirects())
            with opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            error.close()
            raise AgentBackendError(
                "provider_error", f"OpenAI API request failed (HTTP {error.code})"
            ) from None
        except TimeoutError:
            raise AgentBackendError("timeout", "OpenAI API request timed out") from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, TimeoutError):
                raise AgentBackendError("timeout", "OpenAI API request timed out") from None
            raise AgentBackendError("provider_error", "OpenAI API unavailable") from None
        except OSError:
            raise AgentBackendError("provider_error", "OpenAI API unavailable") from None
        if len(raw) > 2_000_000:
            raise AgentBackendError("response_limit", "OpenAI API response exceeded byte limit")
        return _openai_narrative(_json_object(raw))


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
    """Bound a known CLI's POSIX process group and output; pass read-only/plan flags.

    Operator-owned CLI configuration and external filesystem/network isolation
    remain required. A CLI flag does not isolate inherited integrations or hooks.
    """

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
                    json.dumps(_narrative_schema(), sort_keys=True),
                    encoding="utf-8",
                )
                command = [
                    self.executable,
                    "exec",
                    "--sandbox",
                    "read-only",
                    "-c",
                    'approval_policy="never"',
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
                self._run(command, prompt, environment, output_path=output_path)
                message_bytes = _read_message_file(output_path, self.config.max_output_bytes)
                return _validate_narrative(_json_object(message_bytes), require_all=True)
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
                wrapper = _json_object(completed.stdout)
                if (
                    wrapper.get("type") != "result"
                    or wrapper.get("subtype") != "success"
                    or wrapper.get("is_error") is not False
                    or wrapper.get("api_error_status") is not None
                ):
                    raise AgentBackendError(
                        "provider_error", "Claude Code did not return a successful result"
                    )
                stop_reason = wrapper.get("stop_reason")
                if stop_reason == "refusal":
                    raise AgentBackendError("refused", "Claude Code declined the review")
                if stop_reason not in (None, "end_turn", "stop_sequence"):
                    raise AgentBackendError("incomplete", "Claude Code review was incomplete")
                raw = wrapper.get("result")
                if not isinstance(raw, str):
                    raise AgentBackendError("invalid_response", "Claude Code result is not text")
                return _validate_narrative(_json_object(raw), require_all=True)

    def _run(
        self,
        command: list[str],
        prompt: str,
        environment: dict[str, str],
        *,
        output_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if os.name != "posix":
            raise AgentBackendError(
                "unsupported_platform", "CLI agent process limits require POSIX"
            )
        deadline = time.monotonic() + self.config.timeout_seconds
        try:
            process = subprocess.Popen(
                command,
                cwd=self.workspace,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            raise AgentBackendError("process_error", "Agent process unavailable") from None
        stdout, stderr = bytearray(), bytearray()
        streams = (process.stdin, process.stdout, process.stderr)
        try:
            assert process.stdin is not None and process.stdout is not None
            assert process.stderr is not None
            with selectors.DefaultSelector() as selector:
                pending = memoryview(prompt.encode())
                for stream in streams:
                    assert stream is not None
                    os.set_blocking(stream.fileno(), False)
                if pending:
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    process.stdin.close()
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                while selector.get_map() or process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AgentBackendError("timeout", "Agent process timed out")
                    if output_path is not None:
                        _check_message_file(output_path, self.config.max_output_bytes)
                    for key, _mask in selector.select(min(remaining, 0.05)):
                        if key.data == "stdin":
                            try:
                                pending = pending[os.write(key.fd, pending[:8192]) :]
                            except BrokenPipeError:
                                raise AgentBackendError(
                                    "process_error", "Agent closed input before prompt delivery"
                                ) from None
                            except BlockingIOError:
                                continue
                            if not pending:
                                selector.unregister(key.fd)
                                process.stdin.close()
                            continue
                        try:
                            chunk = os.read(key.fd, 8192)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fd)
                            continue
                        if len(stdout) + len(stderr) + len(chunk) > self.config.max_output_bytes:
                            raise AgentBackendError(
                                "response_limit", "Agent stdout/stderr exceeded byte limit"
                            )
                        (stdout if key.data == "stdout" else stderr).extend(chunk)
            returncode = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if returncode != 0:
                raise AgentBackendError(
                    "process_error", f"Agent process failed (exit {returncode})"
                )
            try:
                return subprocess.CompletedProcess(
                    command, returncode, stdout.decode("utf-8"), stderr.decode("utf-8")
                )
            except UnicodeError:
                raise AgentBackendError("invalid_response", "Agent output is not UTF-8") from None
        except subprocess.TimeoutExpired:
            raise AgentBackendError("timeout", "Agent process timed out") from None
        except OSError:
            raise AgentBackendError("process_error", "Agent process I/O failed") from None
        finally:
            # Also stop descendants that outlive a successfully exited CLI parent.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for stream in streams:
                if stream is not None:
                    stream.close()
            process.wait()


def _narrative_schema() -> dict[str, Any]:
    schema = AgentNarrative.model_json_schema()
    # Local defaults keep legacy artifacts readable. Strict wire output must
    # explicitly include even empty lists; Pydantic's schema alone omits them.
    schema["required"] = list(schema["properties"])
    return schema


def _json_object(raw: str | bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> Any:
        raise ValueError("non-JSON constant")

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
        if isinstance(value, dict):
            return value
    except ValueError, UnicodeError, RecursionError:
        pass
    raise AgentBackendError("invalid_response", "Agent response is not a strict JSON object")


def _validate_narrative(value: dict[str, Any], *, require_all: bool = False) -> AgentNarrative:
    if require_all and set(value) != set(AgentNarrative.model_fields):
        raise AgentBackendError("invalid_response", "Agent response is missing required fields")
    try:
        return AgentNarrative.model_validate(redact_sensitive(value), strict=True)
    except ValueError:
        raise AgentBackendError(
            "invalid_response", "Agent response failed schema validation"
        ) from None


def _openai_narrative(envelope: dict[str, Any]) -> AgentNarrative:
    status = envelope.get("status")
    if status == "incomplete":
        raise AgentBackendError("incomplete", "OpenAI response was incomplete")
    if status != "completed" or envelope.get("error") is not None:
        raise AgentBackendError("provider_error", "OpenAI response did not complete successfully")
    if envelope.get("incomplete_details") is not None:
        raise AgentBackendError("invalid_response", "OpenAI response has inconsistent status")
    output = envelope.get("output")
    if not isinstance(output, list):
        raise AgentBackendError("invalid_response", "OpenAI response has no output list")
    messages = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") not in ("message", "reasoning"):
            raise AgentBackendError("invalid_response", "OpenAI returned unexpected output")
        if item.get("type") == "message":
            content = item.get("content")
            if not isinstance(content, list):
                raise AgentBackendError("invalid_response", "OpenAI message has no content list")
            if any(isinstance(part, dict) and part.get("type") == "refusal" for part in content):
                raise AgentBackendError("refused", "OpenAI declined the review")
            messages.append(item)
    if len(messages) != 1:
        raise AgentBackendError("invalid_response", "OpenAI response needs one assistant message")
    message = messages[0]
    if message.get("role") != "assistant" or message.get("status") != "completed":
        raise AgentBackendError("invalid_response", "OpenAI assistant message is not complete")
    content = message["content"]
    if (
        len(content) != 1
        or not isinstance(content[0], dict)
        or content[0].get("type") != "output_text"
        or not isinstance(content[0].get("text"), str)
    ):
        raise AgentBackendError(
            "invalid_response", "OpenAI response needs one structured text part"
        )
    return _validate_narrative(_json_object(content[0]["text"]), require_all=True)


def _check_message_file(path: Path, limit: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode):
        raise AgentBackendError("invalid_response", "Agent message must be a regular file")
    if info.st_size > limit:
        raise AgentBackendError("response_limit", "Agent message file exceeded byte limit")


def _read_message_file(path: Path, limit: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise AgentBackendError("invalid_response", "Agent message must be a regular file")
            if info.st_size > limit:
                raise AgentBackendError("response_limit", "Agent message file exceeded byte limit")
            raw = stream.read(limit + 1)
    except OSError:
        raise AgentBackendError("invalid_response", "Agent message file is unavailable") from None
    if len(raw) > limit:
        raise AgentBackendError("response_limit", "Agent message file exceeded byte limit")
    return raw


def _prompt(payload: Mapping[str, Any]) -> str:
    bounded = json.dumps(redact_sensitive(dict(payload)), sort_keys=True, default=str)
    if len(bounded.encode()) > 500_000:
        raise ValueError("agent input exceeds 500000 bytes")
    schema = _narrative_schema()
    return json.dumps(
        {"input": json.loads(bounded), "required_output_schema": schema},
        sort_keys=True,
    )
