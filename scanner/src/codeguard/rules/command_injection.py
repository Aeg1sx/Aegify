"""Command Injection detection rules."""

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


class CommandInjectionRule(SecurityRule):
    """Detect OS command injection via taint analysis."""

    definition = RuleDefinition(
        id="CG-CMD-001",
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

        for flow in taint_flows:
            if flow.sink.sink_type != "os_command":
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
        id="CG-CMD-002",
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
                    "logic": "callee is a subprocess function AND arguments contain shell=True",
                },
            },
            "description": (
                "Scans for subprocess function calls (run, call, Popen, check_output, check_call) "
                "that include shell=True in their arguments. When shell=True, the command is "
                "executed through the shell interpreter, making it vulnerable to command injection "
                "if any part of the command string is user-controlled."
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
            if ast.language != Language.PYTHON:
                continue

            for call in ast.calls:
                callee = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                if callee not in (
                    "subprocess.run",
                    "subprocess.call",
                    "subprocess.Popen",
                    "subprocess.check_output",
                    "subprocess.check_call",
                ):
                    continue

                if any("shell=True" in arg or "shell = True" in arg for arg in call.arguments):
                    findings.append(
                        self._create_finding(
                            file_path=ast.file_path,
                            line_start=call.line,
                            line_end=call.line,
                            code_snippet="",
                            message=(
                                f"subprocess call at line {call.line} uses shell=True. "
                                f"This is dangerous if any command argument is user-controlled."
                            ),
                        )
                    )

        return findings


register_rule(CommandInjectionRule())
register_rule(ShellTrueRule())
