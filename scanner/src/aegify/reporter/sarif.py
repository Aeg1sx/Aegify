"""SARIF 2.1.0 report generator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegify.models import Finding, ScanResult, Severity

# SARIF severity mapping
SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

CONFIDENCE_MAP: dict[str, str] = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


class SARIFReporter:
    """Generates SARIF 2.1.0 compliant reports."""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    TOOL_NAME = "Aegify"
    TOOL_VERSION = "0.2.0"

    def generate(
        self,
        scan_result: ScanResult,
        call_graph: Any | None = None,
    ) -> dict[str, Any]:
        """Generate a complete SARIF report.

        Args:
            scan_result: The scan result with findings.
            call_graph: Optional networkx DiGraph to include in the report.
        """
        rules = self._build_rules(scan_result.findings)
        results = [self._build_result(f) for f in scan_result.findings]

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": self.TOOL_NAME,
                    "version": self.TOOL_VERSION,
                    "informationUri": "https://github.com/Aeg1sx/Aegify",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": scan_result.status == "completed",
                    "properties": {
                        "filesScanned": scan_result.files_scanned,
                        "durationSeconds": scan_result.duration_seconds,
                        "tokenUsage": scan_result.token_usage.model_dump(),
                        "workspaceSnapshot": scan_result.workspace_snapshot,
                    },
                }
            ],
        }

        # Serialize call graph and endpoints if provided
        run_props: dict[str, Any] = {
            "evidenceContractVersion": 1,
            "workspaceSnapshot": scan_result.workspace_snapshot,
            "semanticAnalysis": scan_result.semantic_analysis.model_dump(mode="json"),
            "programGraph": scan_result.program_graph.model_dump(mode="json"),
            "frameworkAnalysis": scan_result.framework_analysis.model_dump(mode="json"),
            "taintAnalysis": scan_result.taint_analysis.model_dump(mode="json"),
            "externalAnalysis": scan_result.external_analysis.model_dump(mode="json"),
            "runtimeEvidence": scan_result.runtime_evidence.model_dump(mode="json"),
            "findingDisposition": scan_result.disposition_count,
        }
        if call_graph is not None:
            run_props["callGraph"] = self._serialize_call_graph(call_graph)
        if scan_result.endpoints:
            run_props["endpoints"] = [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "handlerFunction": ep.handler_function,
                    "filePath": ep.file_path,
                    "lineStart": ep.line_start,
                    "lineEnd": ep.line_end,
                    "framework": ep.framework,
                    "authRequired": ep.auth_required,
                    "parameters": [
                        {"name": p.name, "location": p.location, "paramType": p.param_type}
                        for p in ep.parameters
                    ],
                    "middleware": ep.middleware,
                    "repositoryId": ep.repository_id,
                    "calledByFrontend": ep.called_by_frontend,
                    "frontendCallCount": ep.frontend_call_count,
                    "exposedViaGateway": ep.exposed_via_gateway,
                    "gatewayRouteIds": ep.gateway_route_ids,
                    "runtimeObserved": ep.runtime_observed,
                    "runtimeObservationCount": ep.runtime_observation_count,
                }
                for ep in scan_result.endpoints
            ]
        if scan_result.frontend_calls:
            run_props["frontendCalls"] = [
                {
                    "id": call.id,
                    "path": call.path,
                    "method": call.method,
                    "filePath": call.file_path,
                    "line": call.line,
                    "client": call.client,
                    "repositoryId": call.repository_id,
                    "dynamic": call.dynamic,
                    "confidence": call.confidence,
                }
                for call in scan_result.frontend_calls
            ]
        if scan_result.gateway_routes:
            run_props["gatewayRoutes"] = [
                route.model_dump(mode="json") for route in scan_result.gateway_routes
            ]
        if scan_result.attack_surface_links:
            run_props["attackSurfaceLinks"] = [
                link.model_dump(mode="json") for link in scan_result.attack_surface_links
            ]
        if scan_result.runtime_observations:
            run_props["runtimeObservations"] = [
                {
                    "id": observation.id,
                    "kind": observation.kind,
                    "method": observation.method,
                    "path": observation.path,
                    "statusCode": observation.status_code,
                    "durationMs": observation.duration_ms,
                    "traceId": observation.trace_id,
                    "spanId": observation.span_id,
                    "parentSpanId": observation.parent_span_id,
                    "repositoryId": observation.repository_id,
                    "passed": observation.passed,
                    "provenance": observation.provenance.model_dump(mode="json"),
                }
                for observation in scan_result.runtime_observations
            ]
        if run_props:
            run["properties"] = run_props

        sarif: dict[str, Any] = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [run],
        }

        return sarif

    def _serialize_call_graph(self, graph: Any) -> dict[str, Any]:
        """Serialize a networkx DiGraph to a JSON-friendly structure."""
        nodes = []
        for name, data in graph.nodes(data=True):
            node_data = data.get("data")
            node: dict[str, Any] = {"qualifiedName": name}
            if node_data:
                node["displayName"] = node_data.qualified_name
                node["filePath"] = node_data.file_path
                node["lineStart"] = node_data.line_start
                node["lineEnd"] = node_data.line_end
                node["isEntryPoint"] = node_data.is_entry_point
                node["isSink"] = node_data.is_sink
                node["repositoryId"] = node_data.repository_id
            nodes.append(node)

        edges = []
        for source, target, data in graph.edges(data=True):
            edge: dict[str, Any] = {
                "source": source,
                "target": target,
            }
            if data.get("line"):
                edge["callSiteLine"] = data["line"]
            edges.append(edge)

        return {"nodes": nodes, "edges": edges}

    def write(
        self,
        scan_result: ScanResult,
        output_path: Path,
        call_graph: Any | None = None,
    ) -> None:
        """Generate and write SARIF report to file."""
        sarif = self.generate(scan_result, call_graph=call_graph)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)

    def _build_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Build the rules array from unique finding rules."""
        from aegify.rules.base import get_registry

        registry = get_registry()
        rule_map = {r.definition.id: r for r in registry.get_all()}

        seen: set[str] = set()
        rules: list[dict[str, Any]] = []

        for finding in findings:
            if finding.rule_id in seen:
                continue
            seen.add(finding.rule_id)

            tags = ["security"]
            if finding.owasp_category:
                tags.append(f"OWASP:{finding.owasp_category}")

            rule: dict[str, Any] = {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "defaultConfiguration": {"level": SEVERITY_MAP.get(finding.severity, "warning")},
                "properties": {
                    "tags": tags,
                },
            }

            # Include description from registry
            reg_rule = rule_map.get(finding.rule_id)
            if reg_rule:
                rule["fullDescription"] = {"text": reg_rule.definition.description}
                # Include YAML content for YAML rules
                if hasattr(reg_rule, "raw_yaml") and reg_rule.raw_yaml:
                    rule["properties"]["yamlContent"] = reg_rule.raw_yaml
                else:
                    # Generate YAML-like metadata for built-in Python rules
                    rule["properties"]["yamlContent"] = self._generate_rule_yaml(reg_rule)
                rule["properties"]["description"] = reg_rule.definition.description

            if finding.cwe_id:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": f"CWE-{finding.cwe_id}",
                            "toolComponent": {"name": "CWE"},
                        },
                        "kinds": ["superset"],
                    }
                ]
                rule["properties"]["cwe"] = f"CWE-{finding.cwe_id}"

            rules.append(rule)

        return rules

    def _get_taint_config(self) -> Any:
        """Lazily load the default TaintConfig for concrete pattern lookup."""
        if not hasattr(self, "_taint_config"):
            from aegify.scanner.dataflow import TaintConfig

            self._taint_config = TaintConfig.default()
        return self._taint_config

    def _generate_rule_yaml(self, rule: Any) -> str:
        """Generate a YAML-like metadata representation for built-in Python rules."""
        d = rule.definition
        lines = [
            f"# Built-in Python rule: {d.id}",
            "# This rule uses native Python analysis (not YAML pattern matching)",
            "",
            f"id: {d.id}",
            f"name: {d.name}",
            "type: python-native",
            "description: >",
            f"  {d.description}",
            f"severity: {d.severity.value}",
            f"confidence: {d.default_confidence}",
        ]
        if d.cwe_id:
            lines.append(f"cwe: CWE-{d.cwe_id}")
        if d.owasp_category:
            lines.append(f"owasp: {d.owasp_category}")
        if d.masvs_category:
            lines.append(f"masvs: {d.masvs_category}")
        lines.append(f"languages: [{', '.join(lang.value for lang in d.languages)}]")
        lines.append(f"requires_taint_path: {str(d.requires_taint_path).lower()}")
        if d.defense_patterns:
            lines.append(f"defense_patterns: [{', '.join(d.defense_patterns)}]")
        lines.append(f"llm_verify_threshold: {d.llm_verify_threshold}")

        # Include actual detection metadata
        meta = rule.get_detection_metadata() if hasattr(rule, "get_detection_metadata") else {}
        if meta:
            lines.append("")
            lines.append("# === Detection Logic ===")
            lines.append(f"detection_method: {meta.get('detection_method', 'unknown')}")

            if "taint" in meta:
                taint = meta["taint"]
                lines.append("")
                lines.append("taint:")
                lines.append(f"  sink_types: [{', '.join(taint.get('sink_types', []))}]")
                if taint.get("source_types"):
                    lines.append(f"  source_types: [{', '.join(taint['source_types'])}]")
                if taint.get("sanitizers"):
                    lines.append(f"  sanitizers: [{', '.join(taint['sanitizers'])}]")
                if taint.get("note"):
                    lines.append(f"  # {taint['note']}")

                # Resolve concrete sink/source functions from TaintConfig
                tc = self._get_taint_config()
                sink_types = set(taint.get("sink_types", []))
                if sink_types:
                    lines.append("")
                    lines.append("  # Concrete sink functions per language")
                    lines.append("  sink_functions:")
                    for lang in d.languages:
                        lang_sinks = [
                            s for s in tc.sinks.get(lang, []) if s.sink_type in sink_types
                        ]
                        if lang_sinks:
                            lines.append(f"    {lang.value}:")
                            for s in lang_sinks:
                                lines.append(f'      - "{s.pattern}"')

                # Resolve concrete source functions
                lines.append("")
                lines.append("  # Concrete source functions per language")
                lines.append("  source_functions:")
                for lang in d.languages:
                    lang_sources = tc.sources.get(lang, [])
                    if lang_sources:
                        lines.append(f"    {lang.value}:")
                        for s in lang_sources:
                            lines.append(f'      - "{s.pattern}"  # {s.source_type}')

                # Resolve concrete sanitizers
                lines.append("")
                lines.append("  # Concrete sanitizer functions per language")
                lines.append("  sanitizer_functions:")
                for lang in d.languages:
                    lang_sanitizers = tc.sanitizers.get(lang, [])
                    if lang_sanitizers:
                        lines.append(f"    {lang.value}:")
                        for s in lang_sanitizers:
                            lines.append(f'      - "{s}"')

            if "patterns" in meta:
                patterns = meta["patterns"]
                lines.append("")
                lines.append("patterns:")
                if "callee_match" in patterns:
                    lines.append("  callee_match:")
                    for cm in patterns["callee_match"]:
                        lines.append(f'    - "{cm}"')
                if "match_type" in patterns:
                    lines.append(f"  match_type: {patterns['match_type']}")
                if "args_match" in patterns:
                    am = patterns["args_match"]
                    lines.append("  args_match:")
                    if isinstance(am, dict):
                        for k, v in am.items():
                            if isinstance(v, list):
                                lines.append(f"    {k}: [{', '.join(str(i) for i in v)}]")
                            else:
                                lines.append(f'    {k}: "{v}"')
                if "entry_point_decorators" in patterns:
                    lines.append("  entry_point_decorators:")
                    for ep in patterns["entry_point_decorators"]:
                        lines.append(f'    - "{ep}"')
                if "db_query_patterns" in patterns:
                    lines.append("  db_query_patterns:")
                    for qp in patterns["db_query_patterns"]:
                        lines.append(f'    - "{qp}"')
                if "id_argument_pattern" in patterns:
                    lines.append(f'  id_argument_pattern: "{patterns["id_argument_pattern"]}"')
                if "ownership_check_patterns" in patterns:
                    lines.append("  ownership_check_patterns:")
                    for op in patterns["ownership_check_patterns"]:
                        lines.append(f'    - "{op}"')
                if "auth_decorators" in patterns:
                    lines.append("  auth_decorators:")
                    for ad in patterns["auth_decorators"]:
                        lines.append(f'    - "{ad}"')
                if "method_patterns" in patterns:
                    lines.append("  method_patterns:")
                    for mp in patterns["method_patterns"]:
                        lines.append(f'    - callee: "{mp["callee"]}"')
                        lines.append(f'      args: "{mp["args"]}"')
                if "safe_patterns" in patterns:
                    lines.append("  safe_patterns:")
                    for sp in patterns["safe_patterns"]:
                        lines.append(f'    - "{sp}"')

            if meta.get("call_graph_analysis"):
                lines.append("")
                lines.append("call_graph_analysis: true")

            if "additional_checks" in meta:
                ac = meta["additional_checks"]
                lines.append("")
                lines.append("additional_checks:")
                if "path_validation_patterns" in ac:
                    lines.append("  path_validation_patterns:")
                    for pvp in ac["path_validation_patterns"]:
                        lines.append(f'    - "{pvp}"')
                if "logic" in ac:
                    lines.append("  logic: >")
                    lines.append(f"    {ac['logic']}")

            if "logic" in meta:
                lines.append("")
                lines.append("logic: |")
                for logic_line in meta["logic"].split("\n"):
                    lines.append(f"  {logic_line}")

            if "confidence_adjustment" in meta:
                lines.append("")
                lines.append("confidence_adjustment: >")
                lines.append(f"  {meta['confidence_adjustment']}")

            if "description" in meta:
                lines.append("")
                lines.append("detection_description: >")
                lines.append(f"  {meta['description']}")

        lines.append("")
        lines.append(f"# Implementation: {type(rule).__name__}")
        return "\n".join(lines)

    def _build_result(self, finding: Finding) -> dict[str, Any]:
        """Build a SARIF result from a Finding."""
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": (
                SEVERITY_MAP.get(finding.severity, "warning") if finding.blocks_ci else "note"
            ),
            "kind": "fail" if finding.blocks_ci else "review",
            "message": {"text": finding.message},
            "partialFingerprints": {
                "aegifyFingerprint/v1": finding.fingerprint,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line_start,
                            "endLine": finding.line_end,
                            **(
                                {"snippet": {"text": finding.code_snippet}}
                                if finding.code_snippet
                                else {}
                            ),
                        },
                    }
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "status": finding.status.value,
                "severity": finding.severity.value,
                "evidenceState": finding.evidence_state.value,
                "disposition": finding.disposition.value,
                "blocksCi": finding.blocks_ci,
                "provenance": finding.provenance.model_dump(mode="json"),
            },
        }

        # Add code flows if taint flow exists
        if finding.taint_flow and finding.taint_flow.path:
            code_flow = self._build_code_flow(finding)
            if code_flow:
                result["codeFlows"] = [code_flow]

        # Add fixes if remediation exists
        if finding.remediation:
            result["properties"]["remediation"] = finding.remediation

        # Add LLM analysis if available
        if finding.llm_analysis:
            result["properties"]["llmAnalysis"] = finding.llm_analysis
        if finding.ai_review:
            review = finding.ai_review.model_dump(mode="json")
            result["properties"]["aiReview"] = review
            result["properties"]["aiProof"] = review["proof"]

        # Serialize call chain with rich context for LLM verification
        if finding.call_chain:
            result["properties"]["callChain"] = [
                {
                    "function": step.function,
                    "filePath": step.file_path,
                    "line": step.line,
                    "snippet": step.code_snippet,
                }
                for step in finding.call_chain
            ]

        # Serialize defense context for LLM verification
        if finding.defense_context:
            dc = finding.defense_context
            result["properties"]["defenseContext"] = {
                "authPresent": dc.auth_present,
                "authDecorator": dc.auth_decorator,
                "sanitizerPresent": dc.sanitizer_present,
                "sanitizerFunction": dc.sanitizer_function,
                "parameterizedQuery": dc.parameterized_query,
                "inputValidation": dc.input_validation,
                "endpoint": dc.details.get("endpoint"),
            }

        return result

    def _build_code_flow(self, finding: Finding) -> dict[str, Any] | None:
        """Build SARIF codeFlow from taint path."""
        if not finding.taint_flow or not finding.taint_flow.path:
            return None

        locations: list[dict[str, Any]] = []
        for step in finding.taint_flow.path:
            locations.append(
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": step.file_path},
                            "region": {"startLine": step.line},
                        },
                        "message": {"text": f"{step.propagation_type}: {step.variable}"},
                    }
                }
            )

        return {"threadFlows": [{"locations": locations}]}
