"""Configuration management for Aegify."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanConfig(BaseModel):
    """Scan-related configuration."""

    languages: list[str] = Field(
        default=[
            "python",
            "javascript",
            "typescript",
            "java",
            "kotlin",
            "go",
            "rust",
            "swift",
        ]
    )
    exclude: list[str] = Field(
        default=[
            # Test directories (Python tests/, Java/Kotlin src/test/, JS __tests__/)
            "tests/**",
            "**/test/**",
            "**/tests/**",
            "**/__tests__/**",
            "**/src/test/**",
            "**/src/testFixtures/**",
            # Test files by naming convention
            "**/*Test.java",
            "**/*Test.kt",
            "**/*Tests.java",
            "**/*Tests.kt",
            "**/*Spec.java",
            "**/*Spec.kt",
            "**/*Spec.ts",
            "**/test_*.py",
            "**/*_test.py",
            "**/*_test.go",
            "**/*.test.ts",
            "**/*.test.js",
            "**/*.spec.ts",
            "**/*.spec.js",
            # Dependencies / vendored
            "vendor/**",
            "node_modules/**",
            ".git/**",
            "__pycache__/**",
            # Generated / build artifacts
            "*_pb.js",
            "*_pb.d.ts",
            "*_grpc_web_pb*",
            "*.pb.go",
            "**/generated/**",
            "**/dist/**",
            "**/build/**",
            "**/.next/**",
            "**/proto/**",
            "**/__generated__/**",
            # Static assets / non-code
            "**/static/**",
            "**/assets/**",
            "**/public/**",
        ]
    )
    max_file_size_kb: int = 500
    max_workers: int = 0  # 0 = auto (min(cpu_count, 8)), 1 = sequential
    max_findings_per_rule: int = 50  # Cap findings per rule to prevent explosion
    max_findings_per_file: int = 50  # Global cap across all rules for a single file


class StorageConfig(BaseModel):
    """Storage backend configuration."""

    backend: Literal["memory", "sqlite", "postgresql", "s3"] = "memory"
    db_path: str = ".aegify.db"  # SQLite path
    db_url: str = ""  # PostgreSQL connection URL
    s3_bucket: str = ""
    s3_prefix: str = "aegify"


class RulesConfig(BaseModel):
    """Rules configuration."""

    severity_threshold: str = "medium"
    custom_rules: str | None = None
    disabled_rules: list[str] = Field(default_factory=list)


class LLMConfig(BaseModel):
    """LLM integration configuration."""

    enabled: bool = False
    model: str = "claude-opus-4-6"
    base_url: str | None = None
    token_budget: int = 100_000
    verify_threshold: float = 0.7
    batch_size: int = 5
    max_retries: int = 3


class ReportingConfig(BaseModel):
    """Reporting configuration."""

    sarif: bool = True
    github_comment: bool = False
    defectdojo_url: str | None = None
    defectdojo_token: str | None = None
    defectdojo_engagement_id: int = 1


class ContextConfig(BaseModel):
    """Context analysis patterns."""

    auth_patterns: list[str] = Field(
        default=[
            "@auth_required",
            "@login_required",
            "requireAuth",
            "@permission_required",
            "@jwt_required",
            "authenticate",
        ]
    )
    sanitizer_patterns: list[str] = Field(
        default=[
            "parameterized",
            "escape",
            "sanitize",
            "clean",
            "validate",
            "html.escape",
            "bleach.clean",
            "shlex.quote",
            "DOMPurify",
        ]
    )


class AegifyConfig(BaseSettings):
    """Root configuration for Aegify."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIFY_",
        env_nested_delimiter="__",
    )

    scan: ScanConfig = Field(default_factory=ScanConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)

    # API keys (from env)
    anthropic_api_key: str = ""

    @classmethod
    def from_yaml(cls, path: Path) -> AegifyConfig:
        """Load configuration from a YAML file."""
        if not path.exists():
            return cls()
        with open(path) as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
        return cls(**data)

    @classmethod
    def load(cls, project_dir: Path) -> AegifyConfig:
        """Load config from .aegify.yml in the project directory, with env overrides."""
        config_path = project_dir / ".aegify.yml"
        if config_path.exists():
            return cls.from_yaml(config_path)
        config_path = project_dir / ".aegify.yaml"
        if config_path.exists():
            return cls.from_yaml(config_path)
        return cls()
