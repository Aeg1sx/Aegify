"""Command Injection detection rules."""

from __future__ import annotations

from collections import Counter
from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    FileAST,
    Finding,
    FindingDisposition,
    Language,
    Severity,
    TaintFlow,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule
from aegify.scanner.python_process import process_input
from aegify.scanner.python_scope import PythonModules


def _git_revision_sinks(file_asts: list[FileAST]) -> set[tuple[str, int, str, int]]:
    modules = PythonModules(file_asts)
    sinks = set()
    for file in file_asts:
        if file.language != Language.PYTHON:
            continue
        candidates = [
            (call, fact)
            for call in file.calls
            if (fact := call.python_process_input)
            and fact.git_diff_revision_only
            and fact.shell is False
        ]
        if not candidates or not modules.external(file, "subprocess"):
            continue
        # Taint sink identity has a line but no column. A second call on that
        # line can represent an entirely different command.
        counts = Counter(call.line for call in file.calls)
        for call, fact in candidates:
            if counts[call.line] == 1 and fact.argument_index is not None:
                sinks.add((file.file_path, call.line, fact.api, fact.argument_index))
    return sinks


class CommandInjectionRule(SecurityRule):
    """Detect OS command injection via taint analysis."""

    definition = RuleDefinition(
        id="AEG-CMD-001",
        name="OS Command Injection",
        description=(
            "User-controlled input flows into an OS command execution function "
            "without proper sanitization, potentially allowing arbitrary command execution."
        ),
        severity=Severity.CRITICAL,
        default_confidence=0.9,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
        cwe_id=78,
        owasp_category="A03:2021-Injection",
        requires_taint_path=True,
        llm_verify_threshold=0.7,
        defense_patterns=["shlex.quote", "escape", "sanitize"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["os_command"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": self.definition.defense_patterns,
            },
            "description": (
                "Traces data flow from user-controlled sources to OS command execution "
                "sinks (os.system, subprocess.*, exec, etc.). "
                "Reports when no sanitization (shlex.quote, escape) is found in the flow path."
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        revision_sinks = _git_revision_sinks(file_asts) if taint_flows else set()
        for flow in taint_flows:
            if flow.sink.sink_type != "os_command":
                continue
            if flow.sanitized:
                continue

            sink = flow.sink
            revision_only = (
                sink.file_path,
                sink.line,
                sink.function,
                sink.argument_index,
            ) in revision_sinks
            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    disposition=FindingDisposition.ADVISORY if revision_only else None,
                    message=(
                        f"Input from '{flow.source.variable}' reaches a revision operand of a "
                        "shell-free, name-only Git diff with external diff and text conversion "
                        "disabled. Review which revisions the caller may select."
                    )
                    if revision_only
                    else (
                        f"Potential command injection: user input from "
                        f"'{flow.source.variable}' (line {flow.source.line}) "
                        f"flows to '{flow.sink.function}' (line {flow.sink.line}) "
                        f"without sanitization."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


class ShellTrueRule(SecurityRule):
    """Detect subprocess calls with shell=True."""

    definition = RuleDefinition(
        id="AEG-CMD-002",
        name="Subprocess Shell=True",
        description=(
            "subprocess call uses shell=True which can lead to command injection "
            "if any part of the command is user-controlled."
        ),
        severity=Severity.HIGH,
        default_confidence=0.75,
        languages=[Language.PYTHON],
        cwe_id=78,
        owasp_category="A03:2021-Injection",
        requires_taint_path=False,
        llm_verify_threshold=0.6,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "pattern_matching",
            "patterns": {
                "callee_match": [
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.Popen",
                    "subprocess.check_output",
                    "subprocess.check_call",
                ],
                "args_match": {
                    "required": ["shell=True"],
                    "logic": "resolved subprocess API with an enabled shell argument",
                },
            },
            "description": (
                "Resolves standard-library subprocess calls and checks whether their shell "
                "option is enabled. Review the command input for each observed use."
            ),
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings: list[Finding] = []

        modules = PythonModules(file_asts)
        for ast in file_asts:
            if ast.language != Language.PYTHON:
                continue

            for call in ast.calls:
                process = process_input(call, ast, modules)
                if process and process.shell is True:
                    findings.append(
                        self._create_finding(
                            file_path=ast.file_path,
                            line_start=call.line,
                            line_end=call.line,
                            code_snippet="",
                            message=(
                                f"{process.api} enables the shell on line {call.line}. "
                                "Review how the command text is constructed."
                            ),
                        )
                    )

        return findings


register_rule(CommandInjectionRule())
register_rule(ShellTrueRule())
