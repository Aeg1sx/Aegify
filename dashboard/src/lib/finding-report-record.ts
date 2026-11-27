import { createHash } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { AuthEnvironment } from "./auth-policy.ts";
import { isConfigurationEvidence, parseEvidenceSteps, parseRecord, sourceLine } from "./code-evidence.ts";
import { parseConfigurationSettings } from "./configuration-evidence.ts";
import { findingWorkflow, readObservationDecision } from "./finding-workflow.ts";
import { findingScope, resolvePrincipal } from "./project-access.ts";
import type { ReportDecision, ReportFinding } from "./finding-report.ts";
import type { ScanCoverage } from "./sarif-evidence.ts";

export function reportETag(markdown: string): string {
  return '"' + createHash("sha256").update(markdown).digest("hex") + '"';
}

function recordedCoverage(details?: string): ScanCoverage | null {
  const { scope, files, rules, gaps } = parseRecord(parseRecord(details).coverage);
  const count = (value: unknown): value is number | null =>
    value === null || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
  if (scope !== "repository" && scope !== "workspace" && scope !== "files" && scope !== "unknown") return null;
  return count(files) && count(rules) && count(gaps) ? { scope, files, rules, gaps } : null;
}

export async function readFindingReport(db: PrismaClient, id: string, userId: string | null, env: AuthEnvironment) {
  if (!id || id.length > 128) return null;
  return db.$transaction(async (tx): Promise<ReportFinding | null> => {
    const viewer = await resolvePrincipal(tx, userId ?? undefined, env);
    const finding = await tx.finding.findFirst({
      where: { id, ...findingScope(viewer) },
      include: { scan: { select: { projectId: true, repository: true, branch: true, commitSha: true, createdAt: true, status: true } } },
    });
    if (!finding) return null;
    const { projectId } = finding.scan;
    const identity = finding.identityId && projectId
      ? await tx.findingIdentity.findFirst({
        where: { id: finding.identityId, projectId },
        include: { triageEvents: { orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 1 } },
      }) : null;
    let decision: ReportDecision | null = null;
    if (identity || !finding.identityId) {
      const observation = identity ? undefined : await readObservationDecision(tx, finding, projectId);
      const state = findingWorkflow(finding, identity, observation);
      const latest = identity?.triageEvents[0];
      const automatic = latest?.actor === "aegify-system" && latest.toStatus === state.status;
      const aligned = latest && latest.toStatus === state.status &&
        latest.actor === state.actor && latest.reason === state.reason;
      const observationEvent = observation
        ? await tx.auditEvent.findUnique({ where: { id: observation.id }, select: { createdAt: true } }) : null;
      decision = {
        scope: identity ? "identity" : "observation", status: state.status, owner: state.owner,
        reason: automatic ? latest.reason : state.reason, actor: automatic ? latest.actor : state.actor,
        recordedAt: (automatic || aligned ? latest.createdAt : observationEvent?.createdAt)?.toISOString() ?? null,
        expiresAt: automatic ? null : state.expiresAt?.toISOString() ?? null,
        needsReview: state.needsReview,
      };
    }
    const provenance = parseRecord(finding.provenance);
    const configuration = isConfigurationEvidence(provenance);
    const snippet = configuration ? parseConfigurationSettings(finding.codeSnippet) : null;
    const flow = configuration ? null : parseEvidenceSteps(finding.taintFlow);
    const receipt = await tx.auditEvent.findFirst({
      where: { projectId, targetId: finding.scanId, action: "scan.import.finished" },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }], select: { details: true },
    });
    return {
      id: finding.id, scanId: finding.scanId, ruleId: finding.ruleId, ruleName: finding.ruleName,
      source: finding.source, severity: finding.severity, status: finding.status, owner: finding.owner,
      evidenceState: finding.evidenceState, disposition: finding.disposition, message: finding.message,
      filePath: finding.filePath, lineStart: finding.lineStart, lineEnd: finding.lineEnd,
      codeSnippet: configuration ? (snippet ?? []).map((entry) => entry.text).join(" · ") : finding.codeSnippet,
      taintFlow: flow?.steps.length ? JSON.stringify(flow.steps) : null, flowWarning: flow?.warning ?? null, remediation: finding.remediation,
      provenance: JSON.stringify({
        ...(configuration ? { analysis_kind: "configuration", fidelity: "parsed-settings" } : {}),
        ...("snippet_start_line" in provenance ? { snippet_start_line: sourceLine(provenance.snippet_start_line) } : {}),
      }),
      repositoryId: finding.repositoryId, evidenceId: finding.evidenceId, isCurrent: finding.isCurrent,
      scan: { repository: finding.scan.repository, branch: finding.scan.branch,
        commitSha: finding.scan.commitSha, createdAt: finding.scan.createdAt.toISOString(),
        status: finding.scan.status, coverage: recordedCoverage(receipt?.details) },
      decision,
    };
  });
}
