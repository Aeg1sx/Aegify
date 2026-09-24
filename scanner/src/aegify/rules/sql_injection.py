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
from aegify.scanner.sql_queries import QUERY_METHODS, SUPPORTED


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
        languages=[Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT],
        cwe_id=89,
        owasp_category="A03:2021-Injection",
        requires_taint_path=False,
        llm_verify_threshold=0.6,
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "structural_sql_expression",
            "contract_version": 1,
            "patterns": {
                "callee_match": sorted(QUERY_METHODS),
                "callee_match_mode": "full_leaf_name",
                "query_selection": [
                    "first_positional",
                    "sql/query/operation/statement_keyword",
                    "sql/text_object_property",
                ],
                "constructions": [
                    "concatenation",
                    "interpolation",
                    "percent_format",
                    "format_call",
                ],
            },
            "description": (
                "Selects query text separately from bound values, follows bounded local string "
                "assignments, and reports SQL text assembled with unresolved values. Fixed strings "
                "and finite literal-only compositions are not constructions with external data. "
                "This is candidate evidence; source trust and database receiver identity "
                "require review."
            ),
            "uncertainty": (
                "Unmodeled values are unknown; parser cache version changes "
                "require reparsing legacy ASTs."
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
            if ast.language not in SUPPORTED:
                continue
            for call in ast.calls:
                facts = call.query_expression
                if facts is None or facts.state != "constructed" or not facts.has_sql:
                    continue
                call_text = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
                origin = ", ".join(str(line) for line in facts.origin_lines) or str(call.line)
                operations = ", ".join(facts.constructions)
                uncertainty = (
                    f" Unresolved analysis details: {', '.join(facts.uncertainties)}."
                    if facts.uncertainties
                    else ""
                )
                findings.append(
                    self._create_finding(
                        file_path=ast.file_path,
                        line_start=call.line,
                        line_end=call.line,
                        code_snippet="",
                        message=(
                            f"SQL text passed to '{call_text}' is assembled using {operations} "
                            f"with unresolved values (selected {facts.selection}; "
                            f"value origins: {origin}). "
                            "Use bound parameters for data values. Static construction candidate; "
                            f"input trust and database binding require review.{uncertainty}"
                        ),
                    )
                )

        return findings


# Register rules
register_rule(SQLInjectionRule())
register_rule(SQLStringConcatRule())
