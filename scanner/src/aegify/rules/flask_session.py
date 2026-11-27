"""Request data crossing a Flask session trust boundary."""

from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import FileAST, Finding, FindingDisposition, Language, Severity, TaintFlow
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule

_DESTINATIONS = {"session_key": "the session key", "session_identity": "an identity or role field"}
_HTTP_SOURCES = {"http_param", "http_query", "http_body", "http_header", "http_cookie"}


class FlaskSessionRule(SecurityRule):
    definition = RuleDefinition(
        id="AEG-SESS-501",
        name="Request data written to a Flask session boundary",
        description="Review request-controlled session keys and writes to identity or role fields.",
        severity=Severity.HIGH,
        default_confidence=0.75,
        languages=[Language.PYTHON],
        cwe_id=501,
        owasp_category="A01:2021-Broken Access Control",
    )

    def get_detection_metadata(self) -> dict[str, Any]:
        return {
            "detection_method": "taint_analysis",
            "taint": {
                "source_types": sorted(_HTTP_SOURCES),
                "sink_types": sorted(_DESTINATIONS),
            },
        }

    def evaluate(
        self,
        file_asts: list[FileAST],
        call_graph: CodeGraph,
        taint_flows: list[TaintFlow],
    ) -> list[Finding]:
        findings = []
        for flow in taint_flows:
            destination = _DESTINATIONS.get(flow.sink.sink_type)
            if not destination or flow.source.source_type not in _HTTP_SOURCES:
                continue
            # Escaping for output or SQL does not authenticate a principal.
            findings.append(
                self._create_finding(
                    file_path=flow.sink.file_path,
                    line_start=flow.sink.line,
                    line_end=flow.sink.line,
                    code_snippet="",
                    taint_flow=flow,
                    disposition=FindingDisposition.ADVISORY,
                    message=f"Request input reaches {destination} in Flask session state. "
                    "Use a server-selected key and derive privileges from the authenticated "
                    "principal. "
                    "Check how this field is consumed before assigning impact.",
                )
            )
        return findings


register_rule(FlaskSessionRule())
