"""Contracts for reproducible, policy-bounded dynamic verification."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class VerificationStatus(StrEnum):
    PLANNED = "planned"
    PASSED = "passed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


class VerificationPolicy(BaseModel):
    """Security controls applied to every step in a plan."""

    model_config = ConfigDict(extra="forbid")

    network: str = "none"
    cpus: float = Field(default=2.0, gt=0.0, le=8.0)
    memory: str = "2g"
    pids_limit: int = Field(default=256, ge=16, le=4096)
    tmpfs_size: str = "256m"
    max_output_bytes: int = Field(default=1_000_000, ge=1024, le=20_000_000)
    max_artifact_bytes: int = Field(
        default=200_000_000,
        ge=1024,
        le=2_000_000_000,
    )
    allowed_commands: list[str] = Field(
        default_factory=lambda: [
            "./gradlew",
            "./mvnw",
            "gradle",
            "java",
            "mvn",
            "node",
            "npm",
            "pnpm",
            "pytest",
            "python",
            "python3",
            "scip-java",
            "yarn",
        ]
    )
    exclude: list[str] = Field(
        default_factory=lambda: [".git", ".idea", "node_modules", "build", "target"]
    )

    @field_validator("network")
    @classmethod
    def network_must_be_disabled(cls, value: str) -> str:
        if value != "none":
            raise ValueError("alpha harness only permits network: none")
        return value

    @field_validator("memory", "tmpfs_size")
    @classmethod
    def validate_size(cls, value: str) -> str:
        if not re.fullmatch(r"[1-9][0-9]*[kmg]", value.lower()):
            raise ValueError("size must be an integer followed by k, m, or g")
        return value.lower()

    @field_validator("allowed_commands")
    @classmethod
    def require_explicit_commands(cls, value: list[str]) -> list[str]:
        if not value or any(not command.strip() for command in value):
            raise ValueError("allowed_commands must contain non-empty entries")
        return value


class VerificationStep(BaseModel):
    """One argv-only process invocation inside an isolated container."""

    model_config = ConfigDict(extra="forbid")

    id: str
    command: list[str]
    working_directory: str = "."
    timeout_seconds: int = Field(default=300, ge=1, le=1800)
    outputs: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("step id must use letters, digits, dot, underscore, or dash")
        return value

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if not value or any("\x00" in item for item in value):
            raise ValueError("command must be a non-empty argv list without NUL bytes")
        secret = re.compile(
            r"(?i)(?:password|passwd|secret|token|api[_-]?key|authorization)(?:=|:)"
        )
        secret_flags = {
            "--password",
            "--passwd",
            "--secret",
            "--token",
            "--api-key",
            "--authorization",
        }
        if any(secret.search(item) or item.lower() in secret_flags for item in value):
            raise ValueError("secrets are not permitted in verification command arguments")
        return value

    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("working_directory must stay beneath the workspace")
        return path.as_posix()

    @field_validator("outputs")
    @classmethod
    def validate_outputs(cls, value: list[str]) -> list[str]:
        for item in value:
            path = Path(item)
            if not item or path.is_absolute() or ".." in path.parts:
                raise ValueError("outputs must stay beneath the step working directory")
        if len(value) != len(set(value)):
            raise ValueError("outputs must not contain duplicate paths")
        return value


class VerificationPlan(BaseModel):
    """Versioned plan loaded from YAML and safe to serialize as evidence."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str
    image: str
    policy: VerificationPolicy = Field(default_factory=VerificationPolicy)
    steps: list[VerificationStep]
    stop_on_failure: bool = True

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError(f"unsupported verification plan version: {value}")
        return value

    @field_validator("image")
    @classmethod
    def require_digest_pinned_image(cls, value: str) -> str:
        if not re.search(r"@sha256:[0-9a-fA-F]{64}$", value):
            raise ValueError("image must be pinned by @sha256:<64 hex digest>")
        return value

    @model_validator(mode="after")
    def validate_unique_step_ids(self) -> VerificationPlan:
        ids = [step.id for step in self.steps]
        if not ids:
            raise ValueError("verification plan requires at least one step")
        if len(ids) != len(set(ids)):
            raise ValueError("verification step ids must be unique")
        allowed = set(self.policy.allowed_commands)
        for step in self.steps:
            executable = step.command[0]
            if executable not in allowed:
                raise ValueError(f"step {step.id!r} command {executable!r} is not allowlisted")
        return self

    @classmethod
    def load(cls, path: Path) -> VerificationPlan:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValueError(f"unable to load verification plan {path}: {error}") from error
        return cls.model_validate(data)


class VerificationStepResult(BaseModel):
    """Tamper-evident evidence for one isolated execution."""

    id: str
    status: VerificationStatus
    command: list[str]
    container_name: str
    exit_code: int | None = None
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    stdout_sha256: str = ""
    stderr_sha256: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    error: str = ""
    artifacts: list[VerificationArtifact] = Field(default_factory=list)


class VerificationArtifact(BaseModel):
    """A regular-file output retained from the ephemeral workspace."""

    relative_path: str
    retained_path: str = ""
    size_bytes: int
    sha256: str


class VerificationReport(BaseModel):
    """Complete plan/run evidence with source and policy identity."""

    contract_version: int = 1
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plan_name: str
    status: VerificationStatus
    executed: bool
    image: str
    workspace_sha256: str
    policy_sha256: str
    docker_commands: list[list[str]] = Field(default_factory=list)
    steps: list[VerificationStepResult] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
