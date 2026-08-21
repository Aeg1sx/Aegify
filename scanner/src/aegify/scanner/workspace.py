"""Manifest model for deterministic multi-repository scans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalysisArtifact(BaseModel):
    """A bounded external static-analysis artifact attached to one repository."""

    model_config = ConfigDict(extra="forbid")

    format: Literal["sarif", "semgrep-json", "joern-jsonl"]
    path: Path
    tool: str = ""
    version: str = ""
    max_results: int = Field(default=25_000, ge=1, le=25_000)
    max_path_locations: int = Field(default=1_000, ge=1, le=1_000)


class RuntimeArtifact(BaseModel):
    """Redacted runtime evidence produced by a browser, proxy, or trace collector."""

    model_config = ConfigDict(extra="forbid")

    format: Literal[
        "har",
        "browser-har",
        "proxy-har",
        "otel-json",
        "http-evidence-json",
        "browser-evidence-json",
        "proxy-evidence-json",
    ]
    path: Path
    tool: str = ""
    version: str = ""
    max_observations: int = Field(default=25_000, ge=1, le=25_000)


class JvmClasspathArtifact(BaseModel):
    """Retained compiler classpath snapshot plus co-located immutable JARs."""

    model_config = ConfigDict(extra="forbid")

    path: Path
    max_entries: int = Field(default=2_000, ge=1, le=20_000)
    max_jar_bytes: int = Field(default=500_000_000, ge=1_024, le=2_000_000_000)
    max_total_bytes: int = Field(
        default=2_000_000_000,
        ge=1_024,
        le=10_000_000_000,
    )
    max_classes: int = Field(default=100_000, ge=1, le=1_000_000)
    max_class_bytes: int = Field(default=10_000_000, ge=1_024, le=100_000_000)
    max_compression_ratio: float = Field(default=200.0, ge=1.0, le=1_000.0)


class WorkspaceRepository(BaseModel):
    """One repository participating in a workspace scan."""

    model_config = ConfigDict(extra="forbid")

    id: str
    path: Path
    role: str = "service"
    exclude: list[str] = Field(default_factory=list)
    # Repository IDs this consumer depends on. This creates an explicitly
    # fidelity-labeled coarse reachability fallback when compiler indexes are
    # unavailable; SCIP/API edges remain the precise path.
    depends_on: list[str] = Field(default_factory=list)
    # SCIP protobuf JSON (or a native .scip file when the `scip` CLI is
    # available). Keeping this per repository preserves project-root identity.
    scip_index: Path | None = None
    # Independent build roots in a monorepo may emit one index each.
    scip_indexes: list[Path] = Field(default_factory=list)
    analysis_artifacts: list[AnalysisArtifact] = Field(default_factory=list)
    runtime_artifacts: list[RuntimeArtifact] = Field(default_factory=list)
    jvm_classpath_snapshots: list[JvmClasspathArtifact] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
            raise ValueError("repository id must use letters, digits, dot, underscore, or dash")
        return value


class WorkspaceManifest(BaseModel):
    """Versioned workspace configuration resolved relative to its YAML file."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    name: str = "aegify-workspace"
    scip_cache_dir: Path | None = None
    repositories: list[WorkspaceRepository]

    @classmethod
    def load(cls, path: Path) -> WorkspaceManifest:
        source = path.resolve()
        with source.open() as stream:
            data = yaml.safe_load(stream) or {}
        manifest = cls.model_validate(data)
        if manifest.version != 1:
            raise ValueError(f"unsupported workspace manifest version: {manifest.version}")
        seen: set[str] = set()
        if manifest.scip_cache_dir is not None:
            cache_dir = manifest.scip_cache_dir
            if not cache_dir.is_absolute():
                cache_dir = source.parent / cache_dir
            manifest.scip_cache_dir = cache_dir.resolve()
        seen_paths: set[Path] = set()
        for repository in manifest.repositories:
            if repository.id in seen:
                raise ValueError(f"duplicate repository id: {repository.id}")
            seen.add(repository.id)
            candidate = repository.path
            if not candidate.is_absolute():
                candidate = source.parent / candidate
            repository.path = candidate.resolve()
            if not repository.path.is_dir():
                raise ValueError(
                    f"repository path does not exist or is not a directory: {repository.path}"
                )
            if repository.path in seen_paths:
                raise ValueError(f"repository path appears more than once: {repository.path}")
            seen_paths.add(repository.path)
            if repository.scip_index is not None:
                scip_index = repository.scip_index
                if not scip_index.is_absolute():
                    scip_index = source.parent / scip_index
                repository.scip_index = scip_index.resolve()
                if not repository.scip_index.is_file():
                    raise ValueError(
                        f"SCIP index does not exist or is not a file: {repository.scip_index}"
                    )
            resolved_scip_indexes: list[Path] = []
            for index_path in repository.scip_indexes:
                candidate_index = index_path
                if not candidate_index.is_absolute():
                    candidate_index = source.parent / candidate_index
                candidate_index = candidate_index.resolve()
                if not candidate_index.is_file():
                    raise ValueError(
                        f"SCIP index does not exist or is not a file: {candidate_index}"
                    )
                resolved_scip_indexes.append(candidate_index)
            repository.scip_indexes = resolved_scip_indexes
            for analysis_artifact in repository.analysis_artifacts:
                artifact_path = analysis_artifact.path
                if not artifact_path.is_absolute():
                    artifact_path = source.parent / artifact_path
                analysis_artifact.path = artifact_path.resolve()
                if not analysis_artifact.path.is_file():
                    raise ValueError(
                        "analysis artifact does not exist or is not a file: "
                        f"{analysis_artifact.path}"
                    )
            for runtime_artifact in repository.runtime_artifacts:
                artifact_path = runtime_artifact.path
                if not artifact_path.is_absolute():
                    artifact_path = source.parent / artifact_path
                runtime_artifact.path = artifact_path.resolve()
                if not runtime_artifact.path.is_file():
                    raise ValueError(
                        f"runtime artifact does not exist or is not a file: {runtime_artifact.path}"
                    )
            for classpath_artifact in repository.jvm_classpath_snapshots:
                artifact_path = classpath_artifact.path
                if not artifact_path.is_absolute():
                    artifact_path = source.parent / artifact_path
                classpath_artifact.path = artifact_path.resolve()
                if not classpath_artifact.path.is_file():
                    raise ValueError(
                        "JVM classpath snapshot does not exist or is not a file: "
                        f"{classpath_artifact.path}"
                    )
        if not manifest.repositories:
            raise ValueError("workspace must contain at least one repository")
        repository_ids = {repository.id for repository in manifest.repositories}
        for repository in manifest.repositories:
            unknown = set(repository.depends_on) - repository_ids
            if unknown:
                raise ValueError(
                    f"repository {repository.id} depends on unknown repositories: "
                    f"{', '.join(sorted(unknown))}"
                )
            if repository.id in repository.depends_on:
                raise ValueError(f"repository {repository.id} cannot depend on itself")
        return manifest
