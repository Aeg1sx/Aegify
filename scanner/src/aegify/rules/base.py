"""Base rule definition and rule registry."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    DefenseContext,
    EvidenceState,
    FileAST,
    Finding,
    FindingDisposition,
    Language,
    Severity,
    TaintFlow,
)

logger = logging.getLogger(__name__)


@dataclass
class RuleDefinition:
    """Static definition of a security rule."""

    id: str  # e.g., "AEG-SQL-001"
    name: str  # e.g., "SQL Injection via string concatenation"
    description: str
    severity: Severity
    default_confidence: float  # 0.0 - 1.0
    languages: list[Language]
    cwe_id: int | None = None  # CWE identifier
    owasp_category: str | None = None  # e.g., "A03:2021-Injection"
    masvs_category: str | None = None  # e.g., "MASVS-STORAGE-1"
    requires_taint_path: bool = True
    llm_verify_threshold: float = 0.7  # below this, send to LLM
    defense_patterns: list[str] = field(default_factory=list)


class SecurityRule(ABC):
    """Base class for security rules."""

    definition: RuleDefinition

    @abstractmethod
    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        """Evaluate this rule against the analyzed codebase."""
        ...

    def get_detection_metadata(self) -> dict[str, Any]:
        """Return detection-specific metadata for SARIF/YAML output.

        Override in subclasses to provide actual detection patterns,
        taint sink types, callee matchers, etc.
        """
        return {}

    def _create_finding(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        message: str,
        confidence: float | None = None,
        taint_flow: TaintFlow | None = None,
        defense_context: DefenseContext | None = None,
        evidence_state: EvidenceState = EvidenceState.CANDIDATE,
        disposition: FindingDisposition | None = None,
    ) -> Finding:
        """Helper to create a Finding from this rule."""
        if taint_flow is not None and evidence_state == EvidenceState.CANDIDATE:
            evidence_state = EvidenceState.REACHABLE
        if disposition is None:
            disposition = (
                FindingDisposition.BLOCKING
                if taint_flow is not None
                else FindingDisposition.ADVISORY
            )
        return Finding(
            rule_id=self.definition.id,
            rule_name=self.definition.name,
            severity=self.definition.severity,
            confidence=confidence or self.definition.default_confidence,
            evidence_state=evidence_state,
            disposition=disposition,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            message=message,
            cwe_id=self.definition.cwe_id,
            owasp_category=self.definition.owasp_category,
            taint_flow=taint_flow,
            defense_context=defense_context or DefenseContext(),
        )


class RuleRegistry:
    """Registry of all available security rules."""

    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}

    def register(self, rule: SecurityRule) -> None:
        """Register a security rule."""
        self._rules[rule.definition.id] = rule
        logger.debug("Registered rule: %s", rule.definition.id)

    def get(self, rule_id: str) -> SecurityRule | None:
        return self._rules.get(rule_id)

    def get_all(self) -> list[SecurityRule]:
        return list(self._rules.values())

    def get_by_language(self, language: Language) -> list[SecurityRule]:
        return [r for r in self._rules.values() if language in r.definition.languages]

    def get_enabled(self, disabled_ids: list[str] | None = None) -> list[SecurityRule]:
        disabled = set(disabled_ids or [])
        return [r for r in self._rules.values() if r.definition.id not in disabled]


# Global registry
_registry = RuleRegistry()


def get_registry() -> RuleRegistry:
    return _registry


def register_rule(rule: SecurityRule) -> None:
    _registry.register(rule)
