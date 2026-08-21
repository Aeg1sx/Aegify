"""SQL Injection detection rules."""

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


class SQLInjectionRule(SecurityRule):
    """Detect SQL injection via taint analysis."""

    definition = RuleDefinition(
        id="AEG-SQL-001",
        name="SQL Injection",
        description=(
            "User-controlled input flows into a SQL query without proper "
            "parameterization or sanitization, potentially allowing SQL injection attacks."
        ),
        severity=Severity.CRITICAL,
        default_confidence=0.85,
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.JAVA, Language.GO],
        cwe_id=89,
        owasp_category="A03:2021-Injection",
        requires_taint_path=True,
        llm_verify_threshold=0.7,
        defense_patterns=["parameterized", "prepare", "escape", "sanitize"],
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "sink_types": ["sql_query"],
                "source_types": ["user_input", "request_param", "query_string"],
                "sanitizers": self.definition.defense_patterns,
            },
            "description": (
                "Traces data flow from user-controlled sources (request parameters, "
                "query strings, form data) to SQL query execution sinks. "
                "Reports when no sanitization or parameterization is found in the flow path."
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
            if flow.sink.sink_type != "sql_query":
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
                        f"Potential SQL injection: user input from "
                        f"'{flow.source.variable}' (line {flow.source.line}) "
                        f"flows to '{flow.sink.function}' (line {flow.sink.line}) "
                        f"without sanitization."
                    ),
                    taint_flow=flow,
                )
            )

        return findings


class SQLStringConcatRule(SecurityRule):
    """Detect SQL queries built with string concatenation."""

    definition = RuleDefinition(
        id="AEG-SQL-002",
        name="SQL Query String Concatenation",
        description=(
            "SQL query is constructed using string concatenation or f-strings, "
            "which may lead to SQL injection if any input is user-controlled."
        ),
        severity=Severity.HIGH,
        default_confidence=0.7,
        languages=[Language.PYTHON, Language.JAVASCRIPT],
        cwe_id=89,
        owasp_category="A03:2021-Injection",
        requires_taint_path=False,
        llm_verify_threshold=0.6,
    )

    SQL_KEYWORDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE"]

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "pattern_matching",
            "patterns": {
                "callee_match": ["execute", "query", "raw", "cursor"],
                "args_match": {
                    "sql_keywords": self.SQL_KEYWORDS,
                    "concat_operators": ["+", "f'", 'f"', ".format(", "%"],
                    "logic": "argument contains SQL keyword AND string concatenation operator",
                },
            },
            "description": (
                "Scans all function calls matching DB execution methods "
                "(execute, query, raw, cursor). "
                "For each matching call, checks if arguments contain SQL keywords combined with "
                "string concatenation operators (f-strings, +, .format(), %). "
                "Flags queries built via string interpolation instead of parameterized queries."
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
            for call in ast.calls:
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee

                if not any(
                    sink in call_text.lower() for sink in ("execute", "query", "raw", "cursor")
                ):
                    continue

                for arg in call.arguments:
                    if self._is_string_concat_sql(arg):
                        findings.append(
                            self._create_finding(
                                file_path=ast.file_path,
                                line_start=call.line,
                                line_end=call.line,
                                code_snippet="",
                                message=(
                                    f"SQL query at line {call.line} uses string concatenation "
                                    f"in call to '{call_text}'. Use parameterized queries instead."
                                ),
                            )
                        )
                        break

        return findings

    def _is_string_concat_sql(self, arg: str) -> bool:
        """Check if an argument looks like SQL built with string concat."""
        arg_upper = arg.upper()
        has_sql = any(kw in arg_upper for kw in self.SQL_KEYWORDS)
        has_concat = any(op in arg for op in ["+", "f'", 'f"', ".format(", "%"])
        return has_sql and has_concat


# Register rules
register_rule(SQLInjectionRule())
register_rule(SQLStringConcatRule())
