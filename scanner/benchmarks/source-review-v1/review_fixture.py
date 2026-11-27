"""Run an optional live Codex review of three owned receipt projections."""

import argparse
import ast
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from aegify.agents.backends import CommandAgentBackend, CommandBackendConfig
from aegify.agents.catalog import AGENT_CATALOG
from aegify.agents.models import AgentRole
from aegify.llm.orchestrator import AISTASTOrchestrator
from aegify.llm.sources import SourceCatalog
from aegify.models import (
    AnalyzedSource,
    EvidenceProvenance,
    Finding,
    Language,
    ScanResult,
    Severity,
)
from aegify.quality.artifacts import write_report


class ReadRange(BaseModel, extra="forbid"):
    repository_id: str
    path: str
    line_start: int
    line_end: int


class ReadRequest(BaseModel, extra="forbid"):
    name: Literal["source_read"]
    arguments: ReadRange


class SourceTurn(BaseModel, extra="forbid"):
    tool_requests: list[ReadRequest]


class ReviewTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["likely_true_positive", "likely_false_positive", "needs_review"]
    confidence: float
    reasoning: str
    evidence_for: list[str]
    evidence_against: list[str]
    evidence_gaps: list[str]
    citations: list[str]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--model", default="")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    if args.output.resolve().is_relative_to(here):
        parser.error("choose an output file outside the frozen fixture")
    path = here / "sources" / "receipts.py"
    material = path.read_bytes()
    repository = "receipts"
    scan = ScanResult(
        id="owned-receipt-projections-v1",
        analyzed_sources=[
            AnalyzedSource(
                repository_id=repository,
                file_path=path.name,
                module_path=path.name,
                language=Language.PYTHON,
                source_digest=hashlib.sha256(material).hexdigest(),
            )
        ],
        files_scanned=1,
    )
    sources = SourceCatalog.from_scan(scan, {repository: path.parent})
    reviewer = AISTASTOrchestrator(max_rounds=2, max_tool_calls=1)
    spec = AGENT_CATALOG[AgentRole.STATIC].model_copy(
        update={
            "mission": (
                "Assess only the stated property of the supplied return value. Request the entire "
                "reported function range with one source_read. Then return your verdict, reasons, "
                "missing evidence and issued citation IDs. Use no native tools."
            )
        }
    )
    # Codex runs in an empty directory. The orchestrator supplies the source excerpt.
    with tempfile.TemporaryDirectory(prefix="aegify-receipt-review-") as empty:
        backend = CommandAgentBackend(
            CommandBackendConfig(
                kind="codex",
                executable="codex",
                model=args.model,
                timeout_seconds=90,
                ignore_user_config=True,
            ),
            Path(empty),
        )

        def respond(system: str, prompt: str) -> dict[str, Any]:
            request = json.loads(prompt)
            schema = ReviewTurn if request["tool_results"] else SourceTurn
            return backend.invoke_turn(
                spec, {"policy": system, "review": request}, schema.model_json_schema()
            )

        for function in ast.parse(material).body:
            if not isinstance(function, ast.FunctionDef) or function.end_lineno is None:
                continue
            finding = Finding(
                id=function.name,
                rule_id="FIXTURE-EMAIL-PROJECTION",
                rule_name="Customer email in returned mapping",
                severity=Severity.LOW,
                confidence=0.5,
                file_path=path.name,
                line_start=function.lineno,
                line_end=function.end_lineno,
                message=(
                    "The returned mapping includes a top-level customer_email field. "
                    "Assess this field projection using the supplied source."
                ),
                provenance=EvidenceProvenance(repository_id=repository, module_path=path.name),
            )
            finding.ai_review = reviewer.review_finding(
                finding, respond, sources=sources, model=args.model or "codex-cli-default"
            )
            scan.findings.append(finding)
    write_report(args.output, scan.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
