"""Import CodeQL/Semgrep SARIF, Semgrep JSON, and Joern JSONL evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from codeguard.models import (
    CallChainStep,
    EvidenceProvenance,
    ExternalAnalysisSummary,
    Finding,
    SemanticRelationship,
    Severity,
)
from codeguard.scanner.workspace import AnalysisArtifact, WorkspaceRepository


@dataclass
class ExternalAnalysisBundle:
    """Imported findings and graph edges plus their bounded summary."""

    findings: list[Finding] = field(default_factory=list)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    summary: ExternalAnalysisSummary = field(default_factory=ExternalAnalysisSummary)

    def merge(self, other: ExternalAnalysisBundle) -> None:
        self.findings.extend(other.findings)
        self.relationships.extend(other.relationships)
        self.summary.enabled = self.summary.enabled or other.summary.enabled
        self.summary.artifacts += other.summary.artifacts
        self.summary.findings_imported += other.summary.findings_imported
        self.summary.graph_edges_imported += other.summary.graph_edges_imported
        self.summary.tools = sorted(set(self.summary.tools + other.summary.tools))
        self.summary.truncated = self.summary.truncated or other.summary.truncated
        self.summary.warnings.extend(other.summary.warnings)


class ExternalAnalysisImporter:
    """Convert external tool output into stable CodeGuard evidence contracts."""

    def load(
        self,
        artifact: AnalysisArtifact,
        repository: WorkspaceRepository,
    ) -> ExternalAnalysisBundle:
        digest = self._sha256(artifact.path)
        if artifact.format == "sarif":
            bundle = self._load_sarif(artifact, repository, digest)
        elif artifact.format == "semgrep-json":
            bundle = self._load_semgrep(artifact, repository, digest)
        else:
            bundle = self._load_joern_jsonl(artifact, repository, digest)
        bundle.summary.enabled = True
        bundle.summary.artifacts = 1
        bundle.summary.findings_imported = len(bundle.findings)
        bundle.summary.graph_edges_imported = len(bundle.relationships)
        return bundle

    def _load_sarif(
        self,
        artifact: AnalysisArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> ExternalAnalysisBundle:
        payload = self._object(json.loads(artifact.path.read_text(encoding="utf-8")))
        if payload.get("version") != "2.1.0":
            raise ValueError(f"unsupported SARIF version in {artifact.path}; expected 2.1.0")
        bundle = ExternalAnalysisBundle()
        seen_results = 0
        for raw_run in self._list(payload.get("runs")):
            run = self._object(raw_run)
            driver = self._object(self._object(run.get("tool")).get("driver"))
            tool = artifact.tool or str(driver.get("name") or "sarif")
            version = artifact.version or str(
                driver.get("semanticVersion") or driver.get("version") or ""
            )
            bundle.summary.tools.append(self._tool_label(tool, version))
            rules = {
                str(rule.get("id")): rule
                for raw_rule in self._list(driver.get("rules"))
                if (rule := self._object(raw_rule)).get("id")
            }
            for raw_result in self._list(run.get("results")):
                if seen_results >= artifact.max_results:
                    bundle.summary.truncated = True
                    bundle.summary.warnings.append(
                        f"SARIF results capped at {artifact.max_results}: {artifact.path}"
                    )
                    return bundle
                result = self._object(raw_result)
                rule_id = str(
                    result.get("ruleId") or self._object(result.get("rule")).get("id") or "external"
                )
                rule = rules.get(rule_id, {})
                location = self._first_location(result)
                normalized = self._normalize_location(location, repository.path)
                if normalized is None:
                    bundle.summary.warnings.append(
                        f"ignored SARIF result outside repository {repository.id}: {rule_id}"
                    )
                    continue
                file_path, line_start, line_end = normalized
                message = self._message(result.get("message"))
                fingerprint = self._fingerprint_value(result)
                evidence_id = self._evidence_id(
                    digest, fingerprint or rule_id, file_path, line_start
                )
                chain, chain_edges, was_truncated = self._sarif_code_flow(
                    result,
                    repository,
                    tool,
                    artifact.max_path_locations,
                    evidence_id,
                )
                if was_truncated:
                    bundle.summary.truncated = True
                    bundle.summary.warnings.append(
                        f"SARIF code flow capped at {artifact.max_path_locations}: {rule_id}"
                    )
                properties = self._object(rule.get("properties"))
                finding = Finding(
                    id=evidence_id,
                    rule_id=rule_id,
                    rule_name=str(
                        rule.get("name") or self._message(rule.get("shortDescription")) or rule_id
                    ),
                    severity=self._sarif_severity(result, rule),
                    confidence=self._precision(properties.get("precision")),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    message=message,
                    call_chain=chain,
                    cwe_id=self._cwe(properties.get("tags")),
                    remediation=self._message(rule.get("help")) or None,
                    provenance=self._provenance(
                        tool,
                        version,
                        "sarif-result",
                        repository.id,
                        file_path,
                        digest,
                        evidence_id,
                    ),
                )
                bundle.findings.append(finding)
                bundle.relationships.extend(chain_edges)
                seen_results += 1
        bundle.summary.tools = sorted(set(bundle.summary.tools))
        return bundle

    def _load_semgrep(
        self,
        artifact: AnalysisArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> ExternalAnalysisBundle:
        payload = self._object(json.loads(artifact.path.read_text(encoding="utf-8")))
        bundle = ExternalAnalysisBundle()
        tool = artifact.tool or "semgrep"
        version = artifact.version or str(
            self._object(payload.get("version")).get("version") or payload.get("version") or ""
        )
        bundle.summary.tools = [self._tool_label(tool, version)]
        results = self._list(payload.get("results"))
        if len(results) > artifact.max_results:
            bundle.summary.truncated = True
            bundle.summary.warnings.append(
                f"Semgrep results capped at {artifact.max_results}: {artifact.path}"
            )
        for raw_result in results[: artifact.max_results]:
            result = self._object(raw_result)
            relative_path = str(result.get("path") or "")
            normalized_path = self._normalize_path(relative_path, repository.path)
            if normalized_path is None:
                bundle.summary.warnings.append(
                    f"ignored Semgrep result outside repository {repository.id}: {relative_path}"
                )
                continue
            extra = self._object(result.get("extra"))
            metadata = self._object(extra.get("metadata"))
            start = self._object(result.get("start"))
            end = self._object(result.get("end"))
            line_start = self._positive_int(start.get("line"), 1)
            line_end = self._positive_int(end.get("line"), line_start)
            rule_id = str(result.get("check_id") or "semgrep.external")
            evidence_id = self._evidence_id(
                digest,
                str(extra.get("fingerprint") or rule_id),
                normalized_path,
                line_start,
            )
            bundle.findings.append(
                Finding(
                    id=evidence_id,
                    rule_id=rule_id,
                    rule_name=str(metadata.get("shortlink") or rule_id),
                    severity=self._semgrep_severity(extra.get("severity")),
                    confidence=self._precision(metadata.get("confidence")),
                    file_path=normalized_path,
                    line_start=line_start,
                    line_end=line_end,
                    message=str(extra.get("message") or "Semgrep finding"),
                    code_snippet=str(extra.get("lines") or ""),
                    cwe_id=self._cwe(metadata.get("cwe")),
                    owasp_category=self._first_string(metadata.get("owasp")),
                    remediation=str(metadata.get("fix") or "") or None,
                    provenance=self._provenance(
                        tool,
                        version,
                        "pattern-analysis",
                        repository.id,
                        normalized_path,
                        digest,
                        evidence_id,
                    ),
                )
            )
        return bundle

    def _load_joern_jsonl(
        self,
        artifact: AnalysisArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> ExternalAnalysisBundle:
        bundle = ExternalAnalysisBundle()
        tool = artifact.tool or "joern"
        version = artifact.version
        bundle.summary.tools = [self._tool_label(tool, version)]
        node_ids: set[str] = set()
        records = 0
        with artifact.path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                raw = json.loads(line)
                record = self._object(raw)
                record_type = str(record.get("record") or record.get("type") or "node")
                if record_type == "finding":
                    if len(bundle.findings) >= artifact.max_results:
                        bundle.summary.truncated = True
                        continue
                    finding = self._joern_finding(
                        record, artifact, repository, digest, tool, version
                    )
                    if finding is not None:
                        bundle.findings.append(finding)
                    continue
                if records >= artifact.max_results:
                    bundle.summary.truncated = True
                    continue
                if record_type == "edge" or {"source", "target"} <= record.keys():
                    source = self._joern_id(repository.id, record.get("source"))
                    target = self._joern_id(repository.id, record.get("target"))
                    if source and target:
                        bundle.relationships.append(
                            SemanticRelationship(
                                source=source,
                                target=target,
                                kind=str(
                                    record.get("kind") or record.get("label") or "cpg-edge"
                                ).lower(),
                                repository_id=repository.id,
                                file_path=str(artifact.path),
                                line=line_number,
                                confidence=0.95,
                                provider=tool,
                                fidelity="cpg-export",
                            )
                        )
                        records += 1
                    continue
                node_id = self._joern_id(repository.id, record.get("id"))
                if node_id:
                    node_ids.add(node_id)
                # TinkerPop GraphSON commonly nests outgoing edges by label.
                for label, raw_edges in self._object(record.get("outE")).items():
                    for raw_edge in self._list(raw_edges):
                        edge = self._object(raw_edge)
                        target = self._joern_id(
                            repository.id, edge.get("inV") or edge.get("target")
                        )
                        if node_id and target and records < artifact.max_results:
                            bundle.relationships.append(
                                SemanticRelationship(
                                    source=node_id,
                                    target=target,
                                    kind=str(label).lower(),
                                    repository_id=repository.id,
                                    file_path=str(artifact.path),
                                    line=line_number,
                                    confidence=0.95,
                                    provider=tool,
                                    fidelity="joern-graphson",
                                )
                            )
                            records += 1
        if bundle.summary.truncated:
            bundle.summary.warnings.append(
                f"Joern records capped at {artifact.max_results}: {artifact.path}"
            )
        return bundle

    def _joern_finding(
        self,
        record: dict[str, Any],
        artifact: AnalysisArtifact,
        repository: WorkspaceRepository,
        digest: str,
        tool: str,
        version: str,
    ) -> Finding | None:
        raw_path = str(record.get("file_path") or record.get("file") or "")
        file_path = self._normalize_path(raw_path, repository.path)
        if file_path is None:
            return None
        line_start = self._positive_int(record.get("line_start") or record.get("line"), 1)
        line_end = self._positive_int(record.get("line_end"), line_start)
        rule_id = str(record.get("rule_id") or record.get("ruleId") or "joern.query")
        evidence_id = self._evidence_id(digest, rule_id, file_path, line_start)
        return Finding(
            id=evidence_id,
            rule_id=rule_id,
            rule_name=str(record.get("rule_name") or record.get("name") or rule_id),
            severity=self._severity(record.get("severity")),
            confidence=self._float(record.get("confidence"), 0.9),
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            message=str(record.get("message") or "Joern query finding"),
            cwe_id=self._cwe(record.get("cwe")),
            provenance=self._provenance(
                tool,
                version,
                "cpg-query",
                repository.id,
                file_path,
                digest,
                evidence_id,
            ),
        )

    def _sarif_code_flow(
        self,
        result: dict[str, Any],
        repository: WorkspaceRepository,
        tool: str,
        limit: int,
        evidence_id: str,
    ) -> tuple[list[CallChainStep], list[SemanticRelationship], bool]:
        chain: list[CallChainStep] = []
        edges: list[SemanticRelationship] = []
        truncated = False
        for raw_code_flow in self._list(result.get("codeFlows")):
            code_flow = self._object(raw_code_flow)
            for raw_thread in self._list(code_flow.get("threadFlows")):
                thread = self._object(raw_thread)
                for raw_item in self._list(thread.get("locations")):
                    if len(chain) >= limit:
                        truncated = True
                        break
                    item = self._object(raw_item)
                    location = self._object(item.get("location")) or item
                    normalized = self._normalize_location(location, repository.path)
                    if normalized is None:
                        continue
                    file_path, line_start, _ = normalized
                    message = self._message(location.get("message"))
                    chain.append(
                        CallChainStep(
                            file_path=file_path,
                            function=message or "external-flow-step",
                            line=line_start,
                        )
                    )
        previous = f"external-finding:{repository.id}:{evidence_id}"
        for index, step in enumerate(chain):
            current = f"external-flow:{repository.id}:{evidence_id}:{index}"
            edges.append(
                SemanticRelationship(
                    source=previous,
                    target=current,
                    kind="code-flow",
                    repository_id=repository.id,
                    file_path=step.file_path,
                    line=step.line,
                    confidence=0.95,
                    provider=tool,
                    fidelity="sarif-thread-flow",
                )
            )
            previous = current
        return chain, edges, truncated

    @staticmethod
    def _first_location(result: dict[str, Any]) -> dict[str, Any]:
        locations = ExternalAnalysisImporter._list(result.get("locations"))
        return ExternalAnalysisImporter._object(locations[0]) if locations else {}

    def _normalize_location(
        self, location: dict[str, Any], root: Path
    ) -> tuple[str, int, int] | None:
        physical = self._object(location.get("physicalLocation"))
        artifact = self._object(physical.get("artifactLocation"))
        path = self._normalize_path(str(artifact.get("uri") or ""), root)
        if path is None:
            return None
        region = self._object(physical.get("region"))
        start = self._positive_int(region.get("startLine"), 1)
        end = self._positive_int(region.get("endLine"), start)
        return path, start, end

    @staticmethod
    def _normalize_path(raw: str, root: Path) -> str | None:
        if not raw:
            return None
        parsed = urlparse(raw)
        if parsed.scheme not in {"", "file"}:
            return None
        decoded = unquote(parsed.path if parsed.scheme else raw)
        candidate = Path(decoded)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            return None
        return str(resolved)

    @staticmethod
    def _sarif_severity(result: dict[str, Any], rule: dict[str, Any]) -> Severity:
        properties = ExternalAnalysisImporter._object(rule.get("properties"))
        score = properties.get("security-severity")
        try:
            numeric = float(score) if isinstance(score, (str, int, float)) else 0.0
        except (TypeError, ValueError):
            numeric = 0.0
        if numeric > 9.0:
            return Severity.CRITICAL
        if numeric >= 7.0:
            return Severity.HIGH
        if numeric >= 4.0:
            return Severity.MEDIUM
        if numeric > 0.0:
            return Severity.LOW
        default = ExternalAnalysisImporter._object(rule.get("defaultConfiguration"))
        return ExternalAnalysisImporter._severity(result.get("level") or default.get("level"))

    @staticmethod
    def _semgrep_severity(value: Any) -> Severity:
        normalized = str(value or "").lower()
        if normalized in {"critical"}:
            return Severity.CRITICAL
        if normalized in {"error", "high"}:
            return Severity.HIGH
        if normalized in {"warning", "medium"}:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _severity(value: Any) -> Severity:
        normalized = str(value or "").lower()
        if normalized == "critical":
            return Severity.CRITICAL
        if normalized in {"error", "high"}:
            return Severity.HIGH
        if normalized in {"warning", "medium"}:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _precision(value: Any) -> float:
        return {
            "very-high": 0.98,
            "very_high": 0.98,
            "high": 0.9,
            "medium": 0.75,
            "low": 0.55,
        }.get(str(value or "").lower(), 0.8)

    @staticmethod
    def _cwe(value: Any) -> int | None:
        values = value if isinstance(value, list) else [value]
        for item in values:
            match = re.search(r"CWE[-: ]?(\d+)", str(item or ""), re.IGNORECASE)
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _first_string(value: Any) -> str | None:
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value) if value else None

    @staticmethod
    def _message(value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("text") or value.get("markdown") or "")
        return str(value or "")

    @staticmethod
    def _fingerprint_value(result: dict[str, Any]) -> str:
        fingerprints = ExternalAnalysisImporter._object(result.get("partialFingerprints"))
        return "|".join(f"{key}={fingerprints[key]}" for key in sorted(fingerprints))

    @staticmethod
    def _provenance(
        tool: str,
        version: str,
        fidelity: str,
        repository_id: str,
        file_path: str,
        digest: str,
        evidence_id: str,
    ) -> EvidenceProvenance:
        return EvidenceProvenance(
            producer=tool,
            producer_version=version,
            analysis_kind="external-static-analysis",
            fidelity=fidelity,
            repository_id=repository_id,
            module_path=file_path,
            rule_digest=digest,
            evidence_id=evidence_id,
        )

    @staticmethod
    def _evidence_id(digest: str, stable: str, path: str, line: int) -> str:
        payload = f"{digest}:{stable}:{path}:{line}".encode()
        return "external-" + hashlib.sha256(payload).hexdigest()[:24]

    @staticmethod
    def _sha256(path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _tool_label(tool: str, version: str) -> str:
        return f"{tool}@{version}" if version else tool

    @staticmethod
    def _joern_id(repository_id: str, value: Any) -> str:
        if value is None or value == "":
            return ""
        if isinstance(value, dict):
            value = value.get("@value") or value.get("id")
        return f"repo:{repository_id}:joern:{value}"

    @staticmethod
    def _positive_int(value: Any, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(1, parsed)

    @staticmethod
    def _float(value: Any, default: float) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return max(0.0, min(1.0, parsed))

    @staticmethod
    def _object(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []
