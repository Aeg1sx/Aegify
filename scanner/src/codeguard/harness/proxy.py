"""Loopback intercepting-proxy plans with declarative request mutation."""

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

_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
_FORBIDDEN_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "proxy-authenticate",
    "set-cookie",
    "x-api-key",
}


def _is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in _FORBIDDEN_HEADERS or any(
        marker in lowered
        for marker in ("authorization", "cookie", "password", "secret", "token", "api-key")
    )


class RequestMutation(BaseModel):
    """One auditable mutation applied by the in-container proxy."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "method",
        "path-replace",
        "query-set",
        "query-delete",
        "header-set",
        "header-delete",
        "body-replace",
        "json-set",
        "json-delete",
    ]
    name: str = ""
    value: str = ""
    match: str = ""
    replacement: str = ""

    @model_validator(mode="after")
    def validate_shape(self) -> RequestMutation:
        if self.kind == "method":
            self.value = self.value.upper()
            if self.value not in _METHODS:
                raise ValueError(f"unsupported mutated HTTP method: {self.value}")
        elif self.kind == "path-replace":
            if not self.match or not self.replacement.startswith("/"):
                raise ValueError("path-replace requires match and loopback-relative replacement")
            parsed = urlsplit(self.replacement)
            if parsed.scheme or parsed.netloc or ".." in Path(parsed.path).parts:
                raise ValueError("path replacement must remain loopback-relative")
        elif self.kind.startswith("query-"):
            self._validate_name("query parameter")
        elif self.kind.startswith("header-"):
            self._validate_name("header")
            if _is_sensitive_header(self.name):
                raise ValueError(f"sensitive header mutation is forbidden: {self.name}")
            if "\r" in self.value or "\n" in self.value:
                raise ValueError("header mutation value must not contain CR/LF")
        elif self.kind.startswith("json-"):
            self._validate_name("JSON field path")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", self.name):
                raise ValueError("JSON field path contains unsupported characters")
        if len(self.value.encode("utf-8")) > 1_000_000:
            raise ValueError("mutation value exceeds 1,000,000 UTF-8 bytes")
        if any("\x00" in item for item in (self.name, self.value, self.match, self.replacement)):
            raise ValueError("mutation fields must not contain NUL")
        return self

    def _validate_name(self, label: str) -> None:
        if not self.name or len(self.name) > 200:
            raise ValueError(f"{label} name must contain 1-200 characters")


class ProxyVerificationCase(BaseModel):
    """One original request and its ordered proxy mutation program."""

    model_config = ConfigDict(extra="forbid")

    id: str
    method: str = "GET"
    path: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    mutations: list[RequestMutation]
    expected_status: list[int] = Field(default_factory=lambda: [200])

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("proxy case id contains unsupported characters")
        return value

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        method = value.upper()
        if method not in _METHODS:
            raise ValueError(f"unsupported HTTP method: {value}")
        return method

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        parsed = urlsplit(value)
        if not value.startswith("/") or parsed.scheme or parsed.netloc:
            raise ValueError("proxy case path must be loopback-relative")
        if ".." in Path(parsed.path).parts:
            raise ValueError("proxy case path must not contain parent traversal")
        return value

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if (
                not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}", name)
                or "\r" in header_value
                or "\n" in header_value
                or "\x00" in header_value
            ):
                raise ValueError("request headers contain invalid characters")
            if _is_sensitive_header(name):
                raise ValueError(f"sensitive request header is forbidden: {name}")
        return value

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 1_000_000:
            raise ValueError("request body exceeds 1,000,000 UTF-8 bytes")
        return value

    @field_validator("mutations")
    @classmethod
    def validate_mutations(cls, value: list[RequestMutation]) -> list[RequestMutation]:
        if not value or len(value) > 50:
            raise ValueError("proxy case requires 1-50 mutations")
        return value

    @field_validator("expected_status")
    @classmethod
    def validate_status(cls, value: list[int]) -> list[int]:
        if not value or any(status < 100 or status > 599 for status in value):
            raise ValueError("expected_status must contain HTTP status codes")
        return sorted(set(value))


class ProxyVerificationPlan(BaseModel):
    """Versioned active-proxy contract for one owned loopback service."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str
    image: str
    service_command: list[str]
    base_url: str
    cases: list[ProxyVerificationCase]
    startup_timeout_seconds: int = Field(default=60, ge=1, le=300)
    request_timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_response_bytes: int = Field(default=1_000_000, ge=1024, le=20_000_000)
    policy: VerificationPolicy = Field(default_factory=VerificationPolicy)

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError(f"unsupported proxy verification plan version: {value}")
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
            raise ValueError("proxy base_url must be loopback HTTP")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("proxy base_url must be a credential-free origin")
        return value.rstrip("/")

    @field_validator("service_command")
    @classmethod
    def validate_service_command(cls, value: list[str]) -> list[str]:
        VerificationStep(id="service", command=value)
        return value

    @model_validator(mode="after")
    def validate_contract(self) -> ProxyVerificationPlan:
        if self.service_command[0] not in set(self.policy.allowed_commands):
            raise ValueError(f"service command {self.service_command[0]!r} is not allowlisted")
        ids = [case.id for case in self.cases]
        if not ids or len(ids) > 200 or len(ids) != len(set(ids)):
            raise ValueError("proxy cases must be 1-200 entries with unique ids")
        self.to_verification_plan()
        return self

    def to_verification_plan(self) -> VerificationPlan:
        return VerificationPlan(
            name=self.name,
            image=self.image,
            policy=self.policy,
            steps=[
                VerificationStep(
                    id="verify-proxy",
                    command=[
                        "python3",
                        ".codeguard-runtime/proxy_runner.py",
                        ".codeguard-runtime/proxy-plan.json",
                    ],
                    timeout_seconds=min(
                        1800,
                        self.startup_timeout_seconds
                        + len(self.cases) * self.request_timeout_seconds
                        + 30,
                    ),
                    outputs=[".codeguard-runtime/proxy-evidence.json"],
                )
            ],
        )

    @classmethod
    def load(cls, path: Path) -> ProxyVerificationPlan:
        import yaml

        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, UnicodeError, yaml.YAMLError) as error:
            raise ValueError(f"unable to load proxy verification plan {path}: {error}") from error
        return cls.model_validate(payload)


class ProxyVerificationExecutor:
    """Stage and run the trusted proxy driver in an ephemeral source copy."""

    def __init__(self, docker_binary: str | None = None) -> None:
        self.docker = DockerVerificationExecutor(docker_binary)

    def plan(self, plan: ProxyVerificationPlan, workspace: Path) -> VerificationReport:
        with self._staged(plan, workspace) as staged:
            return self.docker.plan(plan.to_verification_plan(), staged)

    def execute(
        self,
        plan: ProxyVerificationPlan,
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
        def __init__(self, plan: ProxyVerificationPlan, workspace: Path) -> None:
            self.plan = plan
            self.workspace = workspace
            self.temporary: tempfile.TemporaryDirectory[str] | None = None

        def __enter__(self) -> Path:
            self.temporary = tempfile.TemporaryDirectory(prefix="codeguard-proxy-")
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
                Path(__file__).with_name("proxy_runner.py"),
                runtime / "proxy_runner.py",
            )
            (runtime / "proxy-plan.json").write_text(
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
        self, plan: ProxyVerificationPlan, workspace: Path
    ) -> ProxyVerificationExecutor._Staged:
        return self._Staged(plan, workspace)
