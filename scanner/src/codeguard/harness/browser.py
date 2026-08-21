"""Loopback-only Playwright verification with redacted network evidence."""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from codeguard.harness.docker import DockerVerificationExecutor
from codeguard.harness.models import (
    VerificationPlan,
    VerificationPolicy,
    VerificationReport,
    VerificationStep,
)


class BrowserAction(BaseModel):
    """A bounded browser action that never carries user-entered secret values."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["navigate", "click", "wait_for_selector"]
    path: str = ""
    selector: str = ""
    timeout_seconds: int = Field(default=10, ge=1, le=60)

    @model_validator(mode="after")
    def validate_action_fields(self) -> BrowserAction:
        if self.action == "navigate":
            parsed = urlsplit(self.path)
            if not self.path.startswith("/") or parsed.scheme or parsed.netloc:
                raise ValueError("browser navigation must use a loopback-relative path")
            if ".." in Path(parsed.path).parts:
                raise ValueError("browser navigation path must not contain traversal")
        elif not self.selector or len(self.selector) > 500 or "\x00" in self.selector:
            raise ValueError("browser selector must be 1-500 characters without NUL")
        return self


class BrowserScenario(BaseModel):
    """One ordered browser journey."""

    model_config = ConfigDict(extra="forbid")

    id: str
    actions: list[BrowserAction]

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("browser scenario id contains unsupported characters")
        return value

    @field_validator("actions")
    @classmethod
    def validate_actions(cls, value: list[BrowserAction]) -> list[BrowserAction]:
        if not value or len(value) > 100:
            raise ValueError("browser scenario requires 1-100 actions")
        return value


class BrowserVerificationPlan(BaseModel):
    """Versioned Playwright plan restricted to an owned loopback application."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str
    image: str
    service_command: list[str]
    base_url: str
    scenarios: list[BrowserScenario]
    startup_timeout_seconds: int = Field(default=60, ge=1, le=300)
    policy: VerificationPolicy = Field(default_factory=VerificationPolicy)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError(f"unsupported browser plan version: {value}")
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
            raise ValueError("browser base_url must be loopback HTTP")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("browser base_url must be a credential-free origin")
        return value.rstrip("/")

    @field_validator("service_command")
    @classmethod
    def validate_service_command(cls, value: list[str]) -> list[str]:
        VerificationStep(id="service", command=value)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> BrowserVerificationPlan:
        if self.service_command[0] not in set(self.policy.allowed_commands):
            raise ValueError(f"service command {self.service_command[0]!r} is not allowlisted")
        ids = [scenario.id for scenario in self.scenarios]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("browser scenarios must be non-empty with unique ids")
        self.to_verification_plan()
        return self

    def to_verification_plan(self) -> VerificationPlan:
        action_count = sum(len(scenario.actions) for scenario in self.scenarios)
        return VerificationPlan(
            name=self.name,
            image=self.image,
            policy=self.policy,
            steps=[
                VerificationStep(
                    id="verify-browser",
                    command=[
                        "python3",
                        ".codeguard-runtime/browser_runner.py",
                        ".codeguard-runtime/browser-plan.json",
                    ],
                    timeout_seconds=min(
                        1800,
                        self.startup_timeout_seconds + action_count * 60 + 30,
                    ),
                    outputs=[".codeguard-runtime/browser-evidence.json"],
                )
            ],
        )

    @classmethod
    def load(cls, path: Path) -> BrowserVerificationPlan:
        import yaml

        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValueError(f"unable to load browser plan {path}: {error}") from error
        return cls.model_validate(payload)


class BrowserVerificationExecutor:
    """Stage and run the trusted Playwright driver in an ephemeral source copy."""

    def __init__(self, docker_binary: str | None = None) -> None:
        self.docker = DockerVerificationExecutor(docker_binary)

    def plan(
        self,
        plan: BrowserVerificationPlan,
        workspace: Path,
    ) -> VerificationReport:
        with self._staged(plan, workspace) as staged:
            return self.docker.plan(plan.to_verification_plan(), staged)

    def execute(
        self,
        plan: BrowserVerificationPlan,
        workspace: Path,
        artifact_directory: Path,
    ) -> VerificationReport:
        with self._staged(plan, workspace) as staged:
            return self.docker.execute(
                plan.to_verification_plan(),
                staged,
                artifact_directory=artifact_directory,
            )

    class _Staged:
        def __init__(self, plan: BrowserVerificationPlan, workspace: Path) -> None:
            self.plan = plan
            self.workspace = workspace
            self.temporary: tempfile.TemporaryDirectory[str] | None = None

        def __enter__(self) -> Path:
            self.temporary = tempfile.TemporaryDirectory(prefix="codeguard-browser-")
            staged = Path(self.temporary.name) / "workspace"
            shutil.copytree(
                self.workspace.resolve(),
                staged,
                symlinks=True,
                ignore=shutil.ignore_patterns(*self.plan.policy.exclude),
            )
            runtime = staged / ".codeguard-runtime"
            runtime.mkdir()
            shutil.copyfile(
                Path(__file__).with_name("browser_runner.py"),
                runtime / "browser_runner.py",
            )
            (runtime / "browser-plan.json").write_text(
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

    def _staged(
        self,
        plan: BrowserVerificationPlan,
        workspace: Path,
    ) -> BrowserVerificationExecutor._Staged:
        return self._Staged(plan, workspace)
