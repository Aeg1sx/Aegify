"""Path Traversal detection rules."""

from __future__ import annotations

from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    EvidenceState,
    FileAST,
    Finding,
    FindingDisposition,
    Language,
    Severity,
    TaintFlow,
    inferred_process_field,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule


class PathTraversalRule(SecurityRule):
    """Detect path traversal via taint analysis."""

    definition = RuleDefinition(
        id="AEG-PATH-001",
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
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["file_access"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": [],
            },
            "description": (
                "Traces unsanitized path operands from user-controlled sources to file "
                "operations. Review whether the application enforces containment in the "
                "intended directory after path normalization."
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

            cli_path = (
                flow.source.source_type == "cli_arg"
                and flow.source.file_path == flow.sink.file_path
                and flow.source.line == flow.sink.cli_path_origin_line
            )
            evidence_state = EvidenceState.REACHABLE
            disposition = FindingDisposition.BLOCKING
            if cli_path:
                disposition = FindingDisposition.ADVISORY
                message = (
                    f"A script argument at line {flow.source.line} selects the path or a fixed "
                    f"sibling for {flow.sink.function} at line {flow.sink.line}. "
                    "Whether its caller must stay within a specific directory needs review."
                )
            elif inferred_process_field(flow.source, flow.path):
                evidence_state = EvidenceState.CANDIDATE
                disposition = FindingDisposition.ADVISORY
                message = (
                    f"Process input ({flow.source.source_type}) at line {flow.source.line} reaches "
                    "an object. The analysis could not bind that value to the field in the path "
                    f"for {flow.sink.function} at line {flow.sink.line}."
                )
            else:
                message = (
                    f"Potential path traversal: {flow.source.source_type} from "
                    f"'{flow.source.variable}' (line {flow.source.line}) flows to "
                    f"'{flow.sink.function}' (line {flow.sink.line}). Review path containment."
                )
            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    message=message,
                    evidence_state=evidence_state,
                    disposition=disposition,
                    taint_flow=flow,
                )
            )

        return findings


class CodeExecutionRule(SecurityRule):
    """Detect code execution (eval/exec) with user input."""

    definition = RuleDefinition(
        id="AEG-EXEC-001",
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


class DirectoryPrefixRule(SecurityRule):
    definition = RuleDefinition(
        id="AEG-PATH-003",
        name="Directory check uses a character prefix",
        description="A directory check compares the text prefix of its path operands.",
        severity=Severity.MEDIUM,
        default_confidence=0.85,
        languages=[Language.PYTHON],
        cwe_id=22,
        requires_taint_path=False,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "ast",
            "apis": ["os.path.commonprefix", "posixpath.commonprefix", "ntpath.commonprefix"],
        }

    def evaluate(
        self, file_asts: list[FileAST], call_graph: CodeGraph, taint_flows: list[TaintFlow]
    ) -> list[Finding]:
        findings = []
        for ast in file_asts:
            for check in ast.python_directory_checks:
                finding = self._create_finding(
                    ast.file_path,
                    check.line,
                    check.end_line,
                    "",
                    f"{check.api} compares path text character by character. Line "
                    f"{check.comparison_line} uses its result in a directory check. "
                    "Review the directory boundary and the origin of the candidate path.",
                )
                finding.remediation = (
                    "Resolve the root and candidate according to the application's symlink policy. "
                    "Use os.path.commonpath or Path.is_relative_to to compare path components."
                )
                findings.append(finding)
        return findings


register_rule(DirectoryPrefixRule())
