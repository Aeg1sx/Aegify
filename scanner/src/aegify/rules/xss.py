"""Cross-Site Scripting (XSS) detection rules."""

from __future__ import annotations

from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    FileAST,
    Finding,
    Language,
    Severity,
    TaintFlow,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule


class XSSRule(SecurityRule):
    """Detect XSS via taint analysis."""

    definition = RuleDefinition(
        id="AEG-XSS-001",
        name="Cross-Site Scripting (XSS)",
        description=(
            "User-controlled input flows into HTML rendering without proper "
            "escaping, potentially allowing cross-site scripting attacks."
        ),
        severity=Severity.HIGH,
        default_confidence=0.8,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
        cwe_id=79,
        owasp_category="A03:2021-Injection",
        requires_taint_path=True,
        llm_verify_threshold=0.7,
        defense_patterns=["escape", "sanitize", "DOMPurify", "bleach"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["xss"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": self.definition.defense_patterns,
            },
            "description": (
                "Traces data flow from user-controlled sources to HTML rendering "
                "sinks (innerHTML, document.write, render, template output). "
                "Reports when no HTML escaping or sanitization (escape, DOMPurify, bleach) "
                "is found in the flow path."
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for flow in taint_flows:
            if flow.sink.sink_type != "xss":
                continue
            if flow.sanitized:
                continue

            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    message=(
                        f"Potential XSS: user input from "
                        f"'{flow.source.variable}' (line {flow.source.line}) "
                        f"flows to '{flow.sink.function}' (line {flow.sink.line}) "
                        f"without HTML escaping."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


class DangerousInnerHTMLRule(SecurityRule):
    """Detect usage of dangerouslySetInnerHTML in React."""

    definition = RuleDefinition(
        id="AEG-XSS-002",
        name="dangerouslySetInnerHTML Usage",
        description=(
            "React's dangerouslySetInnerHTML is used, which bypasses React's "
            "XSS protections. Ensure content is properly sanitized."
        ),
        severity=Severity.MEDIUM,
        default_confidence=0.6,
        languages=[Language.JAVASCRIPT, Language.TYPESCRIPT],
        cwe_id=79,
        owasp_category="A03:2021-Injection",
        requires_taint_path=False,
        llm_verify_threshold=0.5,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "pattern_matching",
            "patterns": {
                "callee_match": ["dangerouslySetInnerHTML"],
                "match_type": "substring (callee contains 'dangerouslySetInnerHTML')",
            },
            "description": (
                "Scans all function calls and JSX attributes in JavaScript/TypeScript files. "
                "Flags any usage of React's dangerouslySetInnerHTML, which bypasses React's "
                "built-in XSS auto-escaping. Content passed to this prop must be sanitized "
                "with a library like DOMPurify."
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        for ast in file_asts:
            if ast.language not in (Language.JAVASCRIPT, Language.TYPESCRIPT):
                continue
            for call in ast.calls:
                if "dangerouslySetInnerHTML" in call.callee:
                    findings.append(
                        self._create_finding(
                            file_path=ast.file_path,
                            line_start=call.line,
                            line_end=call.line,
                            code_snippet="",
                            message=(
                                f"dangerouslySetInnerHTML at line {call.line} bypasses "
                                f"React's built-in XSS protection. Ensure content is sanitized."
                            ),
                        )
                    )

        return findings


register_rule(XSSRule())
register_rule(DangerousInnerHTMLRule())
