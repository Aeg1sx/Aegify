"""Opt-in durable model-call replay. Uncertain dispatches never retry themselves."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegify.agents.backends import (
    AgentBackend,
    AgentBackendError,
    AgentTurnBackend,
    AnthropicAPIBackend,
    _narrative_schema,
    _validate_narrative,
)
from aegify.agents.catalog import AgentSpec
from aegify.agents.models import AgentNarrative
from aegify.llm.tools import redact_sensitive
from aegify.models import TokenUsage
from aegify.quality.artifacts import parse_json_object, read_regular_file
from aegify.quality.provenance import json_digest

_MAX_BYTES = 8 * 1024 * 1024


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state: Literal["pending", "completed", "error"] = "pending"
    response: dict[str, Any] | None = None
    error_code: str = Field(default="", pattern=r"^[a-z_]{0,80}$")

    @model_validator(mode="after")
    def consistent_state(self) -> _Record:
        if (self.state == "completed") != (self.response is not None):
            raise ValueError("checkpoint response disagrees with call state")
        if (self.state == "error") != bool(self.error_code):
            raise ValueError("checkpoint error disagrees with call state")
        return self


class _State(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    identity_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    records: list[_Record] = Field(default_factory=list, max_length=48)
    usage: TokenUsage | None = None


class CheckpointBackend:
    """Replay validated responses and rebuild facts/tools from the current scan.

    The private local file is not an authenticated artifact. Its owner is trusted.
    A sibling advisory lock excludes concurrent Aegify writers. Callers must close
    this object in a finally block, and call finish() before publishing a run.
    """

    def __init__(
        self, backend: AgentBackend, path: Path, *, identity: Mapping[str, Any], resume: bool
    ) -> None:
        if os.name != "posix":
            raise ValueError("durable checkpoints require a POSIX host")
        import fcntl

        if not isinstance(backend, AgentTurnBackend):
            raise ValueError("checkpoint requires a structured-turn backend")
        self.backend = backend
        self.provider_name = backend.provider_name
        self.path = path.absolute()
        self.cursor = 0
        self.replayed_calls = 0
        self.new_calls = 0
        self.failed = False
        self._lock = -1
        # The parent is operator-owned; never create a path inside reviewed code.
        if not self.path.parent.is_dir() or self.path.parent.is_symlink():
            raise ValueError("checkpoint parent must be an existing real directory")
        try:
            self._lock = os.open(
                str(self.path) + ".lock",
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
            )
            self._private(self._lock)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            digest = json_digest(dict(identity))
            if resume:
                descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    self._private(descriptor)
                finally:
                    os.close(descriptor)
                self.state = _State.model_validate(
                    parse_json_object(read_regular_file(self.path, limit=_MAX_BYTES))
                )
                if self.state.identity_digest != digest:
                    raise ValueError("checkpoint input, provider, limits or implementation changed")
                if any(record.state == "pending" for record in self.state.records):
                    raise ValueError(
                        "checkpoint contains an uncertain dispatch; automatic retry refused"
                    )
                if isinstance(backend, AnthropicAPIBackend):
                    if self.state.records and self.state.usage is None:
                        raise ValueError("checkpoint is missing model usage")
                    if self.state.usage is not None:
                        backend.client.budget.restore_usage(self.state.usage)
            else:
                # Reserve the destination exclusively; an existing run is never overwritten.
                descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
                self.state = _State(identity_digest=digest)
                self._save()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _private(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or metadata.st_nlink != 1
        ):
            raise ValueError("checkpoint and lock must be private, singly linked regular files")

    def close(self) -> None:
        if self._lock >= 0:
            os.close(self._lock)
            self._lock = -1

    def _save(self) -> None:
        material = self.state.model_dump_json(indent=2).encode("utf-8")
        if len(material) > _MAX_BYTES:
            raise ValueError("checkpoint exceeds its byte limit")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(material)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            descriptor = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _usage(self) -> None:
        if isinstance(self.backend, AnthropicAPIBackend):
            self.state.usage = self.backend.client.budget.get_token_usage()

    def invoke(self, spec: AgentSpec, payload: Mapping[str, Any]) -> AgentNarrative:
        return _validate_narrative(
            self.invoke_turn(spec, payload, _narrative_schema()), require_all=True
        )

    def invoke_turn(
        self, spec: AgentSpec, payload: Mapping[str, Any], schema: dict[str, Any]
    ) -> dict[str, Any]:
        if self.failed or self._lock < 0:
            raise AgentBackendError("checkpoint_stopped", "Checkpoint run is stopped")
        digest = json_digest({"prompt": spec.system_prompt, "payload": payload, "schema": schema})
        try:
            if self.cursor < len(self.state.records):
                record = self.state.records[self.cursor]
                if record.request_digest != digest:
                    raise ValueError("checkpoint replay request changed")
                self.cursor += 1
                self.replayed_calls += 1
                if record.state == "error":
                    raise AgentBackendError(record.error_code, "Replayed provider stop")
                try:
                    response = self._response(record.response, schema)
                except Exception:
                    self.failed = True
                    raise AgentBackendError(
                        "checkpoint_stopped", "Invalid checkpoint response"
                    ) from None
                return deepcopy(response)
            if len(self.state.records) >= 48:
                raise ValueError("checkpoint call limit reached")
            record = _Record(request_digest=digest)
            self.state.records.append(record)
            # A crash from this point until the next durable save is uncertain.
            self._save()
            self.new_calls += 1
            assert isinstance(self.backend, AgentTurnBackend)
            try:
                response = self._response(self.backend.invoke_turn(spec, payload, schema), schema)
            except Exception as error:
                code = error.code if isinstance(error, AgentBackendError) else "invalid_response"
                record.error_code = (
                    code if re.fullmatch(r"[a-z_]{1,80}", code) else "provider_error"
                )
                record.state = "error"
                self._usage()
                self._save()
                self.cursor += 1
                raise AgentBackendError(record.error_code, "Checkpointed provider stop") from None
            record.response = response
            record.state = "completed"
            self._usage()
            self._save()
            self.cursor += 1
            return deepcopy(response)
        except AgentBackendError:
            # A provider stop is replayable. No automatic retry of the same call.
            raise
        except Exception:
            self.failed = True
            raise AgentBackendError(
                "checkpoint_stopped", "Checkpoint persistence or replay failed"
            ) from None

    @staticmethod
    def _response(response: Any, schema: dict[str, Any]) -> dict[str, Any]:
        # Validate before persistence; no raw prompts, exception text or credentials.
        material = json.dumps(response, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(material) > 65_536:
            raise AgentBackendError("response_limit", "Checkpoint response exceeds byte limit")
        if "kind" in schema.get("properties", {}):
            from aegify.agents.exploration import AgentSourceExplorer

            AgentSourceExplorer._validate_turn(response)
        else:
            _validate_narrative(response, require_all=True)
        safe = redact_sensitive(response)
        if not isinstance(safe, dict):
            raise AgentBackendError("invalid_response", "Checkpoint response must be an object")
        return safe

    def finish(self) -> None:
        if self.failed or self.cursor != len(self.state.records):
            raise ValueError("checkpoint replay did not consume the complete history")

    def token_usage(self) -> TokenUsage | None:
        self._usage()
        return self.state.usage
