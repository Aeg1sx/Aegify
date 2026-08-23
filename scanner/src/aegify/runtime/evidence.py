"""Import redacted HTTP, browser/proxy HAR, and OpenTelemetry trace facts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aegify.models import (
    EvidenceProvenance,
    RuntimeEvidenceSummary,
    RuntimeObservation,
    SemanticRelationship,
)
from aegify.scanner.workspace import RuntimeArtifact, WorkspaceRepository


@dataclass
class RuntimeEvidenceBundle:
    """Runtime observations and trace-parent relationships."""

    observations: list[RuntimeObservation] = field(default_factory=list)
    relationships: list[SemanticRelationship] = field(default_factory=list)
    summary: RuntimeEvidenceSummary = field(default_factory=RuntimeEvidenceSummary)

    def merge(self, other: RuntimeEvidenceBundle) -> None:
        self.observations.extend(other.observations)
        self.relationships.extend(other.relationships)
        self.summary.enabled = self.summary.enabled or other.summary.enabled
        self.summary.artifacts += other.summary.artifacts
        self.summary.observations += other.summary.observations
        self.summary.trace_edges += other.summary.trace_edges
        self.summary.tools = sorted(set(self.summary.tools + other.summary.tools))
        self.summary.truncated = self.summary.truncated or other.summary.truncated
        self.summary.warnings.extend(other.summary.warnings)


class RuntimeEvidenceImporter:
    """Normalize runtime artifacts without retaining headers, cookies, or bodies."""

    def load(
        self,
        artifact: RuntimeArtifact,
        repository: WorkspaceRepository,
    ) -> RuntimeEvidenceBundle:
        digest = self._sha256(artifact.path)
        payload = json.loads(artifact.path.read_text(encoding="utf-8"))
        if artifact.format in {"har", "browser-har", "proxy-har"}:
            bundle = self._load_har(payload, artifact, repository, digest)
        elif artifact.format == "otel-json":
            bundle = self._load_otel(payload, artifact, repository, digest)
        else:
            bundle = self._load_evidence(payload, artifact, repository, digest)
        bundle.summary.enabled = True
        bundle.summary.artifacts = 1
        bundle.summary.observations = len(bundle.observations)
        bundle.summary.trace_edges = len(bundle.relationships)
        return bundle

    def _load_har(
        self,
        raw_payload: Any,
        artifact: RuntimeArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> RuntimeEvidenceBundle:
        payload = self._object(raw_payload)
        log = self._object(payload.get("log"))
        creator = self._object(log.get("creator"))
        tool = artifact.tool or str(creator.get("name") or artifact.format)
        version = artifact.version or str(creator.get("version") or "")
        bundle = RuntimeEvidenceBundle()
        bundle.summary.tools = [self._tool_label(tool, version)]
        entries = self._list(log.get("entries"))
        if len(entries) > artifact.max_observations:
            bundle.summary.truncated = True
            bundle.summary.warnings.append(
                f"HAR entries capped at {artifact.max_observations}: {artifact.path}"
            )
        for index, raw_entry in enumerate(entries[: artifact.max_observations]):
            entry = self._object(raw_entry)
            request = self._object(entry.get("request"))
            response = self._object(entry.get("response"))
            method = str(request.get("method") or "GET").upper()
            path = self._url_path(str(request.get("url") or ""))
            if not path:
                continue
            external_id = str(entry.get("_requestId") or entry.get("startedDateTime") or index)
            evidence_id = self._evidence_id(digest, external_id, method, path)
            bundle.observations.append(
                RuntimeObservation(
                    id=evidence_id,
                    kind=artifact.format,
                    method=method,
                    path=path,
                    status_code=self._optional_int(response.get("status")),
                    duration_ms=self._optional_float(entry.get("time")),
                    repository_id=repository.id,
                    provenance=self._provenance(
                        tool,
                        version,
                        artifact.format,
                        repository.id,
                        digest,
                        evidence_id,
                    ),
                )
            )
        return bundle

    def _load_otel(
        self,
        raw_payload: Any,
        artifact: RuntimeArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> RuntimeEvidenceBundle:
        payload = self._object(raw_payload)
        tool = artifact.tool or "opentelemetry"
        version = artifact.version
        bundle = RuntimeEvidenceBundle()
        bundle.summary.tools = [self._tool_label(tool, version)]
        spans = self._otel_spans(payload)
        if len(spans) > artifact.max_observations:
            bundle.summary.truncated = True
            bundle.summary.warnings.append(
                f"OpenTelemetry spans capped at {artifact.max_observations}: {artifact.path}"
            )
        known: set[tuple[str, str]] = set()
        for raw_span in spans[: artifact.max_observations]:
            span = self._object(raw_span)
            trace_id = str(span.get("traceId") or span.get("trace_id") or "")
            span_id = str(span.get("spanId") or span.get("span_id") or "")
            if span_id:
                known.add((trace_id, span_id))
            attributes = self._attributes(span.get("attributes"))
            method = str(
                attributes.get("http.request.method") or attributes.get("http.method") or ""
            ).upper()
            path = self._url_path(
                str(
                    attributes.get("url.path")
                    or attributes.get("http.route")
                    or attributes.get("http.target")
                    or ""
                )
            )
            evidence_id = self._evidence_id(
                digest,
                span_id or str(span.get("name") or "span"),
                method,
                path,
            )
            bundle.observations.append(
                RuntimeObservation(
                    id=evidence_id,
                    kind="otel-span",
                    method=method,
                    path=path,
                    status_code=self._optional_int(
                        attributes.get("http.response.status_code")
                        or attributes.get("http.status_code")
                    ),
                    duration_ms=self._span_duration_ms(span),
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=str(
                        span.get("parentSpanId") or span.get("parent_span_id") or ""
                    ),
                    repository_id=repository.id,
                    provenance=self._provenance(
                        tool,
                        version,
                        "otel-trace",
                        repository.id,
                        digest,
                        evidence_id,
                    ),
                )
            )
        for observation in bundle.observations:
            if not observation.parent_span_id:
                continue
            parent = (observation.trace_id, observation.parent_span_id)
            if parent not in known:
                continue
            bundle.relationships.append(
                SemanticRelationship(
                    source=self._span_node(
                        repository.id,
                        observation.trace_id,
                        observation.parent_span_id,
                    ),
                    target=self._span_node(
                        repository.id,
                        observation.trace_id,
                        observation.span_id,
                    ),
                    kind="trace-parent",
                    repository_id=repository.id,
                    confidence=1.0,
                    provider=tool,
                    fidelity="runtime-trace",
                )
            )
        for observation in bundle.observations:
            if not observation.span_id:
                continue
            bundle.relationships.append(
                SemanticRelationship(
                    source=self._span_node(
                        repository.id,
                        observation.trace_id,
                        observation.span_id,
                    ),
                    target=f"runtime_observation:{observation.id}",
                    kind="observed-http",
                    repository_id=repository.id,
                    confidence=1.0,
                    provider=tool,
                    fidelity="runtime-trace",
                )
            )
        return bundle

    def _load_evidence(
        self,
        raw_payload: Any,
        artifact: RuntimeArtifact,
        repository: WorkspaceRepository,
        digest: str,
    ) -> RuntimeEvidenceBundle:
        payload = self._object(raw_payload)
        if payload.get("contract_version") != 1:
            raise ValueError(
                f"unsupported runtime evidence contract in {artifact.path}; expected 1"
            )
        tool = artifact.tool or str(payload.get("producer") or artifact.format)
        version = artifact.version or str(payload.get("producer_version") or "")
        key = "requests" if artifact.format == "browser-evidence-json" else "cases"
        records = self._list(payload.get(key))
        bundle = RuntimeEvidenceBundle()
        bundle.summary.tools = [self._tool_label(tool, version)]
        if len(records) > artifact.max_observations:
            bundle.summary.truncated = True
            bundle.summary.warnings.append(
                f"runtime records capped at {artifact.max_observations}: {artifact.path}"
            )
        for index, raw_record in enumerate(records[: artifact.max_observations]):
            record = self._object(raw_record)
            method = str(record.get("method") or "GET").upper()
            path = self._url_path(str(record.get("path") or record.get("url") or ""))
            if not path:
                continue
            evidence_id = self._evidence_id(
                digest,
                str(record.get("id") or index),
                method,
                path,
            )
            bundle.observations.append(
                RuntimeObservation(
                    id=evidence_id,
                    kind=artifact.format,
                    method=method,
                    path=path,
                    status_code=self._optional_int(
                        record.get("status_code") or record.get("status")
                    ),
                    duration_ms=self._optional_float(record.get("duration_ms")),
                    repository_id=repository.id,
                    passed=(bool(record.get("passed")) if "passed" in record else None),
                    provenance=self._provenance(
                        tool,
                        version,
                        artifact.format,
                        repository.id,
                        digest,
                        evidence_id,
                    ),
                )
            )
        return bundle

    @staticmethod
    def _otel_spans(payload: dict[str, Any]) -> list[Any]:
        direct = RuntimeEvidenceImporter._list(payload.get("spans"))
        if direct:
            return direct
        spans: list[Any] = []
        resources = payload.get("resourceSpans", payload.get("resource_spans"))
        for raw_resource in RuntimeEvidenceImporter._list(resources):
            resource = RuntimeEvidenceImporter._object(raw_resource)
            scopes = resource.get("scopeSpans", resource.get("scope_spans"))
            for raw_scope in RuntimeEvidenceImporter._list(scopes):
                scope = RuntimeEvidenceImporter._object(raw_scope)
                spans.extend(RuntimeEvidenceImporter._list(scope.get("spans")))
        return spans

    @staticmethod
    def _attributes(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        result: dict[str, Any] = {}
        for raw_item in RuntimeEvidenceImporter._list(raw):
            item = RuntimeEvidenceImporter._object(raw_item)
            key = str(item.get("key") or "")
            value = RuntimeEvidenceImporter._object(item.get("value"))
            if key:
                result[key] = next(iter(value.values()), None)
        return result

    @staticmethod
    def _span_duration_ms(span: dict[str, Any]) -> float | None:
        start = RuntimeEvidenceImporter._optional_int(
            span.get("startTimeUnixNano") or span.get("start_time_unix_nano")
        )
        end = RuntimeEvidenceImporter._optional_int(
            span.get("endTimeUnixNano") or span.get("end_time_unix_nano")
        )
        if start is None or end is None or end < start:
            return None
        return (end - start) / 1_000_000

    @staticmethod
    def _url_path(raw: str) -> str:
        if not raw:
            return ""
        value = urlsplit(raw).path if "://" in raw else raw.split("?", 1)[0]
        return value if value.startswith("/") else f"/{value}"

    @staticmethod
    def _provenance(
        tool: str,
        version: str,
        fidelity: str,
        repository_id: str,
        digest: str,
        evidence_id: str,
    ) -> EvidenceProvenance:
        return EvidenceProvenance(
            producer=tool,
            producer_version=version,
            analysis_kind="dynamic-evidence",
            fidelity=fidelity,
            repository_id=repository_id,
            rule_digest=digest,
            evidence_id=evidence_id,
        )

    @staticmethod
    def _evidence_id(digest: str, external_id: str, method: str, path: str) -> str:
        payload = f"{digest}:{external_id}:{method}:{path}".encode()
        return "runtime-" + hashlib.sha256(payload).hexdigest()[:24]

    @staticmethod
    def _span_node(repository_id: str, trace_id: str, span_id: str) -> str:
        return f"runtime-span:{repository_id}:{trace_id}:{span_id}"

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _tool_label(tool: str, version: str) -> str:
        return f"{tool}@{version}" if version else tool

    @staticmethod
    def _optional_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except TypeError, ValueError:
            return None

    @staticmethod
    def _optional_float(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except TypeError, ValueError:
            return None

    @staticmethod
    def _object(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []
