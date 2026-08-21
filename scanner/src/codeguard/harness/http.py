"""Loopback-only HTTP verification plans executed in an isolated container."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from codeguard.harness.docker import DockerVerificationExecutor
from codeguard.harness.models import (
    VerificationPlan,
    VerificationPolicy,
    VerificationReport,
    VerificationStep,
)


class HttpVerificationCase(BaseModel):
    """One body-free request to a loopback application."""

    model_config = ConfigDict(extra="forbid")

    id: str
    method: str = "GET"
    path: str
    expected_status: list[int] = Field(default_factory=lambda: [200])

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("HTTP case id contains unsupported characters")
        return value

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"unsupported HTTP method: {value}")
        return method

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        if not value.startswith("/") or parsed.scheme or parsed.netloc:
            raise ValueError("HTTP case path must be relative to the loopback origin")
        if ".." in Path(parsed.path).parts:
            raise ValueError("HTTP case path must not contain parent traversal")
        return value

    @field_validator("expected_status")
    @classmethod
    def validate_status(cls, value: list[int]) -> list[int]:
        if not value or any(status < 100 or status > 599 for status in value):
            raise ValueError("expected_status must contain HTTP status codes")
        return sorted(set(value))


class HttpVerificationPlan(BaseModel):
    """Versioned loopback service and request contract."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str
    image: str
    service_command: list[str]
    base_url: str
    cases: list[HttpVerificationCase]
    startup_timeout_seconds: int = Field(default=60, ge=1, le=300)
    request_timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=20_000_000)
    policy: VerificationPolicy = Field(default_factory=VerificationPolicy)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError(f"unsupported HTTP verification plan version: {value}")
        return value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("base_url must be loopback HTTP")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, query, or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("base_url must be an origin without a path")
        return value.rstrip("/")

    @field_validator("service_command")
    @classmethod
    def validate_service_command(cls, value: list[str]) -> list[str]:
        VerificationStep(id="service", command=value)
        return value

    @model_validator(mode="after")
    def validate_policy_and_cases(self) -> HttpVerificationPlan:
        if self.service_command[0] not in set(self.policy.allowed_commands):
            raise ValueError(f"service command {self.service_command[0]!r} is not allowlisted")
        ids = [case.id for case in self.cases]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("HTTP verification cases must be non-empty with unique ids")
        self.to_verification_plan()
        return self

    def to_verification_plan(self) -> VerificationPlan:
        return VerificationPlan(
            name=self.name,
            image=self.image,
            policy=self.policy,
            steps=[
                VerificationStep(
                    id="verify-http",
                    command=[
                        "python3",
                        ".codeguard-runtime/http_runner.py",
                        ".codeguard-runtime/http-plan.json",
                    ],
                    timeout_seconds=min(
                        1800,
                        self.startup_timeout_seconds
                        + len(self.cases) * self.request_timeout_seconds
                        + 30,
                    ),
                    outputs=[".codeguard-runtime/http-evidence.json"],
                )
            ],
        )

    @classmethod
    def load(cls, path: Path) -> HttpVerificationPlan:
        import yaml

        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValueError(f"unable to load HTTP verification plan {path}: {error}") from error
        return cls.model_validate(payload)


class HttpVerificationExecutor:
    """Stage a trusted runner into an ephemeral source copy and execute it."""

    def __init__(self, docker_binary: str | None = None) -> None:
        self.docker = DockerVerificationExecutor(docker_binary)

    def plan(
        self,
        plan: HttpVerificationPlan,
        workspace: Path,
    ) -> VerificationReport:
        with self._staged_workspace(plan, workspace) as staged:
            return self.docker.plan(plan.to_verification_plan(), staged)

    def execute(
        self,
        plan: HttpVerificationPlan,
        workspace: Path,
        artifact_directory: Path,
    ) -> VerificationReport:
        with self._staged_workspace(plan, workspace) as staged:
            return self.docker.execute(
                plan.to_verification_plan(),
                staged,
                artifact_directory=artifact_directory,
            )

    class _StagedWorkspace:
        def __init__(self, plan: HttpVerificationPlan, workspace: Path) -> None:
            self.plan = plan
            self.workspace = workspace
            self.temporary: tempfile.TemporaryDirectory[str] | None = None

        def __enter__(self) -> Path:
            self.temporary = tempfile.TemporaryDirectory(prefix="codeguard-http-")
            staged = Path(self.temporary.name) / "workspace"
            shutil.copytree(
                self.workspace.resolve(),
                staged,
                symlinks=True,
                ignore=shutil.ignore_patterns(*self.plan.policy.exclude),
            )
            runtime = staged / ".codeguard-runtime"
            runtime.mkdir()
            runner = Path(__file__).with_name("http_runner.py")
            shutil.copyfile(runner, runtime / "http_runner.py")
            (runtime / "http-plan.json").write_text(
                json.dumps(self.plan.model_dump(mode="json"), sort_keys=True),
                encoding="utf-8",
            )
            return staged

        def __exit__(
            self,
            exc_type: object,
            exc_value: object,
            traceback: object,
        ) -> None:
            if self.temporary is not None:
                self.temporary.cleanup()

    def _staged_workspace(
        self,
        plan: HttpVerificationPlan,
        workspace: Path,
    ) -> HttpVerificationExecutor._StagedWorkspace:
        return self._StagedWorkspace(plan, workspace)
