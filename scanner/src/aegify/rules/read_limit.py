"""Review whole-file reads followed immediately by a rejecting length guard."""

from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import FileAST, Finding, FindingDisposition, Language, Severity, TaintFlow
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule


class PostReadLimitRule(SecurityRule):
    definition = RuleDefinition(
        id="AEG-IO-001",
        name="File size checked after reading",
        description="A length guard runs after a read_bytes() or read_text() call returns.",
        languages=[Language.PYTHON],
        severity=Severity.MEDIUM,
        default_confidence=0.75,
        cwe_id=400,
        requires_taint_path=False,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {"detection_method": "ast", "methods": ["read_bytes", "read_text"]}

    def evaluate(
        self, file_asts: list[FileAST], call_graph: CodeGraph, taint_flows: list[TaintFlow]
    ) -> list[Finding]:
        findings = []
        for file in file_asts:
            for check in file.python_read_limits:
                finding = self._create_finding(
                    file.file_path,
                    check.line,
                    check.end_line,
                    "",
                    f"{check.method}() returns before line {check.guard_line} checks the result's "
                    "length. Verify how much data the reader can allocate before that check.",
                    disposition=FindingDisposition.ADVISORY,
                )
                finding.remediation = (
                    "When enforcing a byte limit, open the file in binary mode, read at most "
                    "the limit plus one byte, and reject excess data before decoding or parsing."
                )
                findings.append(finding)
        return findings


register_rule(PostReadLimitRule())
