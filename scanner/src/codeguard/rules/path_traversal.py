"""Path Traversal detection rules."""

from __future__ import annotations

from typing import Any

from codeguard.graph_types import CodeGraph
from codeguard.models import (
    FileAST,
    Finding,
    Language,
    Severity,
    TaintFlow,
)
from codeguard.rules.base import RuleDefinition, SecurityRule, register_rule


class PathTraversalRule(SecurityRule):
    """Detect path traversal via taint analysis."""

    definition = RuleDefinition(
        id="CG-PATH-001",
        name="Path Traversal",
        description=(
            "User-controlled input flows into a file system operation without "
            "proper path validation, potentially allowing access to arbitrary files."
        ),
        severity=Severity.HIGH,
        default_confidence=0.8,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
        cwe_id=22,
        owasp_category="A01:2021-Broken Access Control",
        requires_taint_path=True,
        llm_verify_threshold=0.6,
        defense_patterns=["realpath", "abspath", "normalize", "sanitize_path"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["file_access"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": self.definition.defense_patterns,
            },
            "description": (
                "Traces data flow from user-controlled sources to file system operation "
                "sinks (open, read, write, Path, etc.). "
                "Reports when no path validation (realpath, abspath, normalize) "
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
            if flow.sink.sink_type != "file_access":
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
                        f"Potential path traversal: user input from "
                        f"'{flow.source.variable}' (line {flow.source.line}) "
                        f"flows to '{flow.sink.function}' (line {flow.sink.line}) "
                        f"without path validation."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


class CodeExecutionRule(SecurityRule):
    """Detect code execution (eval/exec) with user input."""

    definition = RuleDefinition(
        id="CG-EXEC-001",
        name="Code Execution",
        description=(
            "User-controlled input flows into a code execution function (eval/exec), "
            "potentially allowing arbitrary code execution."
        ),
        severity=Severity.CRITICAL,
        default_confidence=0.95,
        languages=[Language.PYTHON, Language.JAVASCRIPT],
        cwe_id=94,
        owasp_category="A03:2021-Injection",
        requires_taint_path=True,
        llm_verify_threshold=0.8,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["code_exec"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": [],
                "note": "No sanitizer is considered safe for code execution sinks",
            },
            "description": (
                "Traces data flow from user-controlled sources to code execution "
                "functions (eval, exec, compile, Function constructor). "
                "Reports any unsanitized flow - code execution sinks "
                "should never receive user input."
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
            if flow.sink.sink_type != "code_exec":
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
                        f"Critical: user input from '{flow.source.variable}' "
                        f"(line {flow.source.line}) flows to code execution function "
                        f"'{flow.sink.function}' (line {flow.sink.line})."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


register_rule(PathTraversalRule())
register_rule(CodeExecutionRule())
