"""Source-backed configuration review for Cloudflare Workers."""

from collections import defaultdict
from typing import Any

from aegify.graph_types import CodeGraph
from aegify.models import (
    WRANGLER_PREVIEW_FIELDS,
    WRANGLER_STORAGE_FIELDS,
    FileAST,
    Finding,
    Language,
    Severity,
    TaintFlow,
    WranglerRuleKind,
    WranglerSetting,
)
from aegify.rules.base import RuleDefinition, SecurityRule, register_rule


class WranglerRule(SecurityRule):
    def __init__(
        self,
        kind: WranglerRuleKind,
        definition: RuleDefinition,
        remediation: str,
    ) -> None:
        self.kind = kind
        self.definition = definition
        self.remediation = remediation

    def get_detection_metadata(self) -> dict[str, Any]:
        return {"detection_method": "configuration", "setting": self.kind}

    def evaluate(
        self, file_asts: list[FileAST], call_graph: CodeGraph, taint_flows: list[TaintFlow]
    ) -> list[Finding]:
        findings = []
        for ast in file_asts:
            by_line: dict[int, list[WranglerSetting]] = defaultdict(list)
            for setting in ast.wrangler_settings:
                if setting.kind == self.kind:
                    by_line[setting.line].append(setting)
            for line, observations in sorted(by_line.items()):
                # Minified JSON can put multiple bindings/environments at one location.
                statements = []
                for setting in observations[:16]:
                    if self.kind == "plaintext_binding":
                        statements.append(f"{setting.scope}.vars.{setting.binding} = [withheld]")
                    elif self.kind == "version_urls":
                        statements.append(
                            f"{setting.scope}: workers_dev = false "
                            f"(line {setting.workers_dev_line})"
                            f", preview_urls = true (line {setting.preview_urls_line})"
                        )
                    elif match := setting.storage_match:
                        primary, preview = WRANGLER_STORAGE_FIELDS[match.collection]
                        selector = preview if match.uses_preview else primary
                        statements.append(
                            f"{setting.scope}.{match.collection}[{match.index}].remote = true "
                            f"(line {setting.line}), {selector} (line {match.selector_line}) "
                            f"matches "
                            f"{match.peer_scope}.{match.collection}[{match.peer_index}].{primary} "
                            f"(line {match.peer_line})"
                        )
                    elif target := setting.preview_match:
                        field = WRANGLER_PREVIEW_FIELDS[target.collection]
                        statements.append(
                            f"{setting.scope}.previews.{target.collection}[{target.index}].{field} "
                            f"(line {setting.line}) matches "
                            f"{target.peer_scope}.{target.collection}[{target.peer_index}].{field} "
                            f"(line {target.peer_line})"
                        )
                if len(observations) > len(statements):
                    statements.append(f"{len(observations) - len(statements)} more at this line")
                finding = self._create_finding(
                    ast.file_path, line, line, " · ".join(statements), self.definition.description
                )
                finding.code_snippet_start_line = line
                finding.remediation = self.remediation
                findings.append(finding)
        return findings


register_rule(
    WranglerRule(
        "plaintext_binding",
        RuleDefinition(
            id="AEG-CF-001",
            name="Possible secret in Wrangler variables",
            description="A credential-named variable contains a literal string in this "
            "configuration. Confirm the binding holds sensitive material and review its history.",
            severity=Severity.HIGH,
            default_confidence=0.8,
            languages=[Language.WRANGLER],
            cwe_id=312,
            requires_taint_path=False,
        ),
        "If the value is a credential, move it to an encrypted secret in the same environment, "
        "rotate it and remove the plaintext assignment. Check the repository history for copies.",
    )
)
register_rule(
    WranglerRule(
        "version_urls",
        RuleDefinition(
            id="AEG-CF-002",
            name="Worker version URLs enabled with workers.dev disabled",
            description="This configuration requests version URLs and disables the main "
            "workers.dev route. Review the intended audience and the Cloudflare Access policy.",
            severity=Severity.MEDIUM,
            default_confidence=0.8,
            languages=[Language.WRANGLER],
            requires_taint_path=False,
        ),
        "For private deployments, disable preview_urls or confirm an appropriate Cloudflare Access "
        "policy covers version URLs. Verify the environment and effective deployment settings.",
    )
)

register_rule(
    WranglerRule(
        "shared_remote_storage",
        RuleDefinition(
            id="AEG-CF-003",
            name="Remote development binding shares a storage target across environments",
            description="A remote development binding selects the same storage identifier as "
            "a deployment binding in another environment. Confirm whether sharing is intended.",
            severity=Severity.MEDIUM,
            default_confidence=0.85,
            languages=[Language.WRANGLER],
            requires_taint_path=False,
        ),
        "For local development, use local storage or select a dedicated preview resource. "
        "Confirm the account and environment used for the deployment.",
    )
)

register_rule(
    WranglerRule(
        "shared_preview_resource",
        RuleDefinition(
            id="AEG-CF-004",
            name="Worker Preview shares a deployment resource",
            description="A Worker Preview and its selected Worker reference the same resource "
            "in this manifest. Check whether branch code should use its data or queue.",
            severity=Severity.MEDIUM,
            default_confidence=0.85,
            languages=[Language.WRANGLER],
            requires_taint_path=False,
        ),
        "If branch workloads need isolation, assign a dedicated resource in the previews "
        "block. Confirm the target Worker and its effective bindings in Cloudflare.",
    )
)
