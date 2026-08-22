"""GitHub PR comment reporter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegify.models import Finding, ScanResult, Severity, TokenUsage

SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}


class GitHubReporter:
    """Generates GitHub PR comment markdown from scan results."""

    def generate_comment(self, scan_result: ScanResult) -> str:
        """Generate a PR comment summary."""
        findings = scan_result.findings
        if not findings:
            return self._no_findings_comment(scan_result)

        lines: list[str] = []
        lines.append("## 🔒 Aegify Results\n")
        lines.append(self._summary_table(scan_result))
        lines.append("")

        # Group by severity
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            severity_findings = [f for f in findings if f.severity == severity]
            if not severity_findings:
                continue

            emoji = SEVERITY_EMOJI[severity]
            lines.append(f"### {emoji} {severity.value.upper()} ({len(severity_findings)})\n")

            for finding in severity_findings:
                lines.append(self._format_finding(finding))
                lines.append("")

        lines.append(
            f"---\n*Scanned {scan_result.files_scanned} files "
            f"in {scan_result.duration_seconds:.1f}s*"
        )
        return "\n".join(lines)

    def generate_inline_annotations(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Generate GitHub inline review comments for findings."""
        annotations: list[dict[str, Any]] = []
        for finding in findings:
            body = (
                f"**{finding.severity.value.upper()} / "
                f"{finding.disposition.value.upper()}**: {finding.message}"
            )
            if finding.remediation:
                body += f"\n\n**Suggested fix**:\n{finding.remediation}"

            annotations.append(
                {
                    "path": finding.file_path,
                    "start_line": finding.line_start,
                    "end_line": finding.line_end,
                    "annotation_level": (
                        "warning"
                        if not finding.blocks_ci
                        or finding.severity in (Severity.MEDIUM, Severity.LOW)
                        else "failure"
                    ),
                    "message": finding.message,
                    "title": f"{finding.rule_id}: {finding.rule_name}",
                    "body": body,
                }
            )

        return annotations

    def _summary_table(self, scan_result: ScanResult) -> str:
        counts = scan_result.findings_count
        return (
            "| Severity | Count |\n"
            "|----------|-------|\n"
            f"| 🔴 Critical | {counts.get('critical', 0)} |\n"
            f"| 🟠 High | {counts.get('high', 0)} |\n"
            f"| 🟡 Medium | {counts.get('medium', 0)} |\n"
            f"| 🔵 Low | {counts.get('low', 0)} |\n"
            f"| **Total** | **{len(scan_result.findings)}** |"
        )

    def _format_finding(self, finding: Finding) -> str:
        lines: list[str] = []
        lines.append(
            f"<details>\n<summary><b>{finding.rule_id}</b>: {finding.rule_name} "
            f"- <code>{finding.file_path}:{finding.line_start}</code></summary>\n"
        )
        lines.append(f"> {finding.message}\n")
        lines.append(
            f"**Evidence**: `{finding.evidence_state.value}` · "
            f"**Gate**: `{finding.disposition.value}`\n"
        )

        if finding.code_snippet:
            lines.append(f"```\n{finding.code_snippet}\n```\n")

        if finding.remediation:
            lines.append(f"**Remediation**:\n{finding.remediation}\n")

        lines.append("</details>")
        return "\n".join(lines)

    def _no_findings_comment(self, scan_result: ScanResult) -> str:
        return (
            "## ✅ Aegify Results\n\n"
            "No security findings detected.\n\n"
            f"*Scanned {scan_result.files_scanned} files in {scan_result.duration_seconds:.1f}s*"
        )


# PR comment marker for upsert logic in GitHub Actions
PR_COMMENT_MARKER = "<!-- aegify-pr-comment -->"


def generate_pr_comment(
    result: ScanResult,
    changed_files: list[Path],
    related_files: list[Path],
    token_usage: TokenUsage | None = None,
) -> str:
    """Generate a PR-focused markdown comment with LLM analysis.

    Includes:
    - Summary table of findings by severity
    - Collapsible changed/related files list
    - Findings grouped by severity with LLM analysis and remediation
    - Token usage footer
    """
    lines: list[str] = [PR_COMMENT_MARKER]

    findings = result.findings
    if not findings:
        lines.append("## :white_check_mark: Aegify — No Issues Found\n")
        lines.append(f"Scanned **{len(changed_files)}** changed files")
        if related_files:
            lines.append(f" + **{len(related_files)}** related files")
        lines.append(f" in {result.duration_seconds:.1f}s.\n")
        return "\n".join(lines)

    lines.append("## :lock: Aegify — PR Scan Results\n")

    # Summary table
    counts = result.findings_count
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, emoji in SEVERITY_EMOJI.items():
        count = counts.get(sev.value, 0)
        if count > 0:
            lines.append(f"| {emoji} {sev.value.upper()} | {count} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    # Changed / related files (collapsible)
    lines.append("<details>")
    lines.append(
        f"<summary>Scanned {len(changed_files)} changed + "
        f"{len(related_files)} related files</summary>\n"
    )
    if changed_files:
        lines.append("**Changed:**")
        for f in changed_files[:50]:
            lines.append(f"- `{f}`")
    if related_files:
        lines.append("\n**Related (imported by/imports changed):**")
        for f in related_files[:50]:
            lines.append(f"- `{f}`")
        if len(related_files) > 50:
            lines.append(f"- ... and {len(related_files) - 50} more")
    lines.append("</details>\n")

    # Findings by severity
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        sev_findings = [f for f in findings if f.severity == severity]
        if not sev_findings:
            continue

        emoji = SEVERITY_EMOJI[severity]
        lines.append(f"### {emoji} {severity.value.upper()} ({len(sev_findings)})\n")

        for finding in sev_findings:
            lines.append(
                f"<details>\n<summary><b>{finding.rule_id}</b>: "
                f"{finding.rule_name} — "
                f"<code>{finding.file_path}:{finding.line_start}</code></summary>\n"
            )
            lines.append(f"> {finding.message}\n")

            if finding.code_snippet:
                lines.append(f"```\n{finding.code_snippet}\n```\n")

            if finding.llm_analysis:
                lines.append(f"**LLM Analysis**: {finding.llm_analysis}\n")

            if finding.remediation:
                lines.append(f"**Remediation**:\n{finding.remediation}\n")

            lines.append("</details>\n")

    # Footer
    lines.append("---")
    footer_parts = [
        f"Scanned {result.files_scanned} files in {result.duration_seconds:.1f}s",
    ]
    usage = token_usage or result.token_usage
    if usage.total_cost_usd > 0:
        total_tokens = usage.input_tokens + usage.output_tokens
        footer_parts.append(f"LLM: {total_tokens:,} tokens (${usage.total_cost_usd:.4f})")
    lines.append(" | ".join(footer_parts))

    return "\n".join(lines)
