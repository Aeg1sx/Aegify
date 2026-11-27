"""Report partial host comparisons for review at the policy decision."""

from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import FileAST, Finding, FindingDisposition, Language, Severity, TaintFlow
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule
from aegify.scanner.python_scope import PythonModules


class PartialHostRule(SecurityRule):
    definition = RuleDefinition(
        id="AEG-HOST-001",
        name="Partial URL host comparison",
        description="A prefix or suffix comparison against a host name can match other hosts.",
        languages=[Language.PYTHON],
        severity=Severity.MEDIUM,
        default_confidence=0.8,
        cwe_id=187,
        requires_taint_path=False,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "ast",
            "apis": ["urllib.parse.urlparse", "urllib.parse.urlsplit"],
        }

    def evaluate(
        self, file_asts: list[FileAST], call_graph: CodeGraph, taint_flows: list[TaintFlow]
    ) -> list[Finding]:
        modules = PythonModules(file_asts)
        findings = []
        for file in file_asts:
            if not modules.external(file, "urllib"):
                continue
            for check in file.python_host_checks:
                finding = self._create_finding(
                    file.file_path,
                    check.line,
                    check.end_line,
                    "",
                    f"{check.parser} supplies the {check.component} checked with "
                    f"{check.comparison}(). Other hosts can share the same text. "
                    "Review which decision uses this comparison.",
                    disposition=FindingDisposition.ADVISORY,
                )
                finding.remediation = (
                    "Compare the parsed hostname with an explicit allowlist. If subdomains are "
                    "intended, require a DNS label boundary. Check the scheme and port separately."
                )
                findings.append(finding)
        return findings


register_rule(PartialHostRule())
