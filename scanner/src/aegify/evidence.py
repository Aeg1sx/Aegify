"""Shared checks for supplied static evidence; these do not prove runtime impact."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from aegify.models import EndpointInfo, Finding

MAX_CALL_PATH_STEPS = 100


@dataclass(frozen=True)
class CallPathCheck:
    endpoint: EndpointInfo | None
    gaps: tuple[str, ...]
    truncated: bool = False

    @property
    def complete(self) -> bool:
        return not self.gaps


def inspect_call_path(finding: Finding, endpoints: Sequence[EndpointInfo]) -> CallPathCheck:
    """Require directed symbol links, repository identity and full source bounds."""
    chain = finding.call_chain
    if not chain:
        return CallPathCheck(None, ("No entry-to-sink call chain was produced",))
    if len(chain) > MAX_CALL_PATH_STEPS:
        return CallPathCheck(None, ("Call chain exceeds the evidence step limit",), True)

    first, last = chain[0], chain[-1]
    endpoint = next(
        (
            item
            for item in endpoints
            if item.file_path == first.file_path
            and item.handler_function == first.function
            and item.repository_id == first.repository_id
            and item.line_start >= 1
            and item.line_start <= first.line <= item.line_end
        ),
        None,
    )
    gaps: list[str] = []
    if endpoint is None:
        gaps.append("No endpoint with matching handler, repository and source range was produced")
    if not all(
        step.symbol_id
        and step.file_path
        and step.function
        and step.line >= 1
        and step.line_end is not None
        and step.line_end >= step.line
        for step in chain
    ):
        gaps.append("Call-chain symbols or source ranges are missing or invalid")
    if (
        any(
            step.next_symbol_id != following.symbol_id
            for step, following in zip(chain, chain[1:], strict=False)
        )
        or last.next_symbol_id
    ):
        gaps.append("Call-chain edges do not form a complete directed path")
    if not (
        last.file_path == finding.file_path
        and last.line_end is not None
        and 1 <= finding.line_start <= finding.line_end
        and last.line <= finding.line_start <= finding.line_end <= last.line_end
        and (
            not finding.provenance.repository_id
            or last.repository_id == finding.provenance.repository_id
        )
    ):
        gaps.append("The full finding range is not bound to the sink in its repository")
    return CallPathCheck(endpoint, tuple(gaps))
