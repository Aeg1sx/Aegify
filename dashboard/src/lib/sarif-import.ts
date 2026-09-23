import type { Prisma, PrismaClient } from "@prisma/client";
import { normalizeFindingClassification, normalizeFindingEvidence, normalizeSourceSnippet, scanHealthForRun, workspaceSnapshotForRun } from "./sarif-evidence.ts";
import { classifyFindingBaseline, findingMessageDigest, stableFindingFingerprint } from "./finding-lifecycle.ts";
import { publishScanImport } from "./scan-reconciliation.ts";
import { writeTransaction } from "./database-runtime.ts";

interface SARIFResult {
  ruleId: string;
  level: string;
  message: { text: string };
  partialFingerprints?: Record<string, string>;
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri: string };
      region?: { startLine: number; endLine?: number; snippet?: { text: string } };
      contextRegion?: { startLine: number; endLine?: number; snippet?: { text: string } };
    };
  }>;
  properties?: {
    confidence?: number;
    severity?: string;
    evidenceState?: string;
    disposition?: string;
    blocksCi?: boolean;
    status?: string;
    remediation?: string;
    llmAnalysis?: string;
    aiReview?: {
      verdict?: string;
      confidence?: number;
      proof?: Record<string, unknown>;
      [key: string]: unknown;
    };
    aiProof?: Record<string, unknown>;
    callChain?: Array<{
      function: string;
      filePath: string;
      line: number;
      snippet?: string;
    }>;
    defenseContext?: {
      authPresent?: boolean;
      authDecorator?: string | null;
      sanitizerPresent?: boolean;
      sanitizerFunction?: string | null;
      parameterizedQuery?: boolean;
      inputValidation?: boolean;
      endpoint?: string | null;
    };
    provenance?: {
      contract_version?: number;
      producer?: string;
      producer_version?: string;
      analysis_kind?: string;
      fidelity?: string;
      repository_id?: string;
      module_path?: string;
      workspace_snapshot?: string;
      rule_digest?: string;
      evidence_id?: string;
    };
  };
  codeFlows?: Array<{
    threadFlows: Array<{
      locations: Array<{
        location: {
          physicalLocation?: {
            artifactLocation?: { uri: string };
            region?: { startLine: number };
          };
          message?: { text: string };
        };
      }>;
    }>;
  }>;
}

interface SARIFRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration?: { level: string };
  properties?: {
    tags?: string[];
    cwe?: string;
    description?: string;
    yamlContent?: string;
  };
  relationships?: Array<{
    target: { id: string };
    kinds: string[];
  }>;
}

interface CallGraphData {
  nodes: Array<{
    qualifiedName: string;
    filePath?: string;
    lineStart?: number;
    lineEnd?: number;
    isEntryPoint?: boolean;
    isSink?: boolean;
  }>;
  edges: Array<{
    source: string;
    target: string;
    callSiteLine?: number;
  }>;
}

interface FrontendCallData {
  id: string;
  path: string;
  method: string;
  filePath: string;
  line: number;
  client: string;
  repositoryId?: string;
  dynamic?: boolean;
  confidence?: number;
}

interface GatewayRouteData {
  id: string;
  uri: string;
  path_patterns?: string[];
  methods?: string[];
  filters?: string[];
  file_path: string;
  line?: number;
  repository_id?: string;
}

interface RuntimeObservationData {
  id: string;
  kind: string;
  method: string;
  path: string;
  statusCode?: number | null;
  durationMs?: number | null;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  repositoryId?: string;
  passed?: boolean | null;
  provenance?: Record<string, unknown>;
}

interface AttackSurfaceLinkData {
  source_kind: "frontend_call" | "gateway_route" | "runtime_observation";
  source_id: string;
  endpoint_path: string;
  endpoint_method: string;
  endpoint_file_path: string;
  endpoint_repository_id?: string;
  match_kind: string;
  confidence: number;
  provenance?: Record<string, unknown>;
}

interface SARIFReport {
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        rules?: SARIFRule[];
      };
    };
    results: SARIFResult[];
    invocations?: Array<{
      executionSuccessful: boolean;
      properties?: {
        filesScanned?: number;
        durationSeconds?: number;
        workspaceSnapshot?: string;
      };
    }>;
    properties?: {
      analysisStatus?: unknown;
      analysisGaps?: unknown;
      analysisScope?: unknown;
      evaluatedRules?: unknown;
      analyzedFiles?: unknown;
      callGraph?: CallGraphData;
      endpoints?: Array<{
        path: string;
        method: string;
        handlerFunction: string;
        filePath: string;
        lineStart?: number;
        lineEnd?: number;
        framework?: string;
        authRequired?: boolean;
        parameters?: Array<{ name: string; location: string; paramType: string }>;
        middleware?: string[];
        repositoryId?: string;
        calledByFrontend?: boolean;
        frontendCallCount?: number;
        exposedViaGateway?: boolean;
        gatewayRouteIds?: string[];
        runtimeObserved?: boolean;
        runtimeObservationCount?: number;
      }>;
      frontendCalls?: FrontendCallData[];
      gatewayRoutes?: GatewayRouteData[];
      runtimeObservations?: RuntimeObservationData[];
      attackSurfaceLinks?: AttackSurfaceLinkData[];
      evidenceContractVersion?: number;
      workspaceSnapshot?: string;
    };
  }>;
}

const LEVEL_TO_SEVERITY: Record<string, string> = {
  error: "high",
  warning: "medium",
  note: "low",
  none: "low",
};

export class SarifValidationError extends Error {}
export interface ImportReceipt {
  scanId: string;
  findingsCount: number;
  status: "completed" | "partial" | "failed";
  baseline: Record<string, number>;
}
export interface ImportContext {
  projectId: string | null;
  repository: string;
  branch: string;
  commitSha: string;
  actorId: string;
  canManageWorkspace?: boolean;
  scanId?: string;
  // Checked inside the publication transaction, including worker fencing or
  // session/service-credential revocation. Every caller must supply this guard.
  authorize: (tx: Prisma.TransactionClient) => Promise<void>;
  onPublished?: (tx: Prisma.TransactionClient, receipt: ImportReceipt) => Promise<void>;
}

export function validateSarifReport(value: unknown): SARIFReport {
  if (!value || typeof value !== "object") throw new SarifValidationError("Upload a SARIF 2.1.0 report.");
  const report = value as SARIFReport;
  if (report.version !== "2.1.0" || !Array.isArray(report.runs) || report.runs.length !== 1 || !report.runs[0]?.tool?.driver || !Array.isArray(report.runs[0].results)) throw new SarifValidationError("Upload one SARIF 2.1.0 run with a driver and results array.");
  const run = report.runs[0];
  if (run.results.length > 50_000) throw new SarifValidationError("Report exceeds 50,000 results; split the scan scope.");
  for (const result of run.results) {
    if (!result || typeof result.ruleId !== "string" || !result.ruleId || result.ruleId.length > 128 || typeof result.message?.text !== "string" || result.message.text.length > 100_000) throw new SarifValidationError("Every result needs a bounded rule ID and message.");
    const region = result.locations?.[0]?.physicalLocation?.region;
    if (region && (!Number.isSafeInteger(region.startLine) || region.startLine < 1 || (region.endLine !== undefined && (!Number.isSafeInteger(region.endLine) || region.endLine < region.startLine)))) throw new SarifValidationError("Invalid source range.");
  }
  const bounded = (value: unknown, limit: number) => value === undefined || (Array.isArray(value) && value.length <= limit);
  if (!bounded(run.tool.driver.rules, 10_000) || !bounded(run.properties?.callGraph?.nodes, 50_000) || !bounded(run.properties?.callGraph?.edges, 200_000) || !bounded(run.properties?.endpoints, 10_000)) throw new SarifValidationError("Report graph, rule or endpoint limits exceeded.");
  return report;
}

/** All findings, identities, graphs, absence, audit and job completion publish together. */
export async function importSarif(db: PrismaClient, report: unknown, context: ImportContext): Promise<ImportReceipt> {
  const sarif = validateSarifReport(report);
  const { projectId, repository, branch, commitSha, actorId, canManageWorkspace = false } = context;
  if (repository.length > 2048 || branch.length > 255 || commitSha.length > 128) throw new SarifValidationError("Scan metadata exceeds the size limit.");
  return writeTransaction(db, async (tx) => {
    await context.authorize(tx);
    const run = sarif.runs[0];
    const invocation = run.invocations?.[0];
    const scanHealth = scanHealthForRun(run.properties, invocation);
    const workspaceSnapshot = workspaceSnapshotForRun(
      run.properties,
      invocation?.properties,
    );

    // Build rule lookup
    const ruleMap = new Map<string, SARIFRule>();
    for (const rule of run.tool.driver.rules || []) {
      ruleMap.set(rule.id, rule);
    }


    const project = projectId ? await tx.project.findUnique({ where: { id: projectId } }) : null;
    if (projectId && (!project || project.archived)) throw new SarifValidationError("Select an active project.");
    const isDefaultBranch = Boolean(branch && branch === project?.defaultBranch);
    const metadata = {
      repository, branch, commitSha, status: "running", progressPhaseName: "Importing evidence",
      filesScanned: invocation?.properties?.filesScanned || 0,
      duration: invocation?.properties?.durationSeconds || 0, workspaceSnapshot, projectId,
    };
    if (context.scanId) {
      const reserved = await tx.scan.findUnique({ where: { id: context.scanId } });
      if (!reserved || reserved.projectId !== projectId || reserved.status !== "running") throw new Error("Reserved scan is not available for publication.");
    }
    const scan = context.scanId
      ? await tx.scan.update({ where: { id: context.scanId }, data: metadata })
      : await tx.scan.create({ data: metadata });
    // A slow queued scan cannot supersede a newer completed scan request.
    const newer = projectId ? await tx.scan.findFirst({
      where: { projectId, branch, status: { in: ["completed", "partial"] }, createdAt: { gt: scan.createdAt } }, select: { id: true },
    }) : null;
    const publishBaseline = !newer && scanHealth.status !== "failed";
    await tx.auditEvent.create({ data: { projectId, actorId, action: "scan.import.started", targetId: scan.id } });
    // Insert findings
    const parsedFindings = run.results.map((result) => {
      const rule = ruleMap.get(result.ruleId);
      const loc = result.locations?.[0]?.physicalLocation;
      const severity =
        result.properties?.severity ||
        LEVEL_TO_SEVERITY[result.level] ||
        "medium";
      const evidence = normalizeFindingEvidence(result.properties);
      const sourceSnippet = normalizeSourceSnippet(loc);
      const classification = normalizeFindingClassification(result.properties);

      // Extract CWE from rule
      let cweId: number | null = null;
      if (rule?.properties?.cwe) {
        const match = rule.properties.cwe.match(/CWE-(\d+)/);
        if (match) cweId = parseInt(match[1], 10);
      } else if (rule?.relationships?.[0]?.target?.id) {
        const match = rule.relationships[0].target.id.match(/CWE-(\d+)/);
        if (match) cweId = parseInt(match[1], 10);
      }

      // Extract OWASP from tags
      let owaspCategory: string | null = null;
      const owaspTag = rule?.properties?.tags?.find((t: string) =>
        t.startsWith("OWASP:")
      );
      if (owaspTag) owaspCategory = owaspTag.replace("OWASP:", "");

      // Serialize taint flow from codeFlows
      let taintFlow: string | null = null;
      if (result.codeFlows?.[0]?.threadFlows?.[0]?.locations) {
        taintFlow = JSON.stringify(
          result.codeFlows[0].threadFlows[0].locations.map((loc) => ({
            file: loc.location.physicalLocation?.artifactLocation?.uri || "",
            line: loc.location.physicalLocation?.region?.startLine || 0,
            message: loc.location.message?.text || "",
          }))
        );
      }

      return {
        scanId: scan.id,
        ruleId: result.ruleId,
        ruleName: rule?.name || rule?.shortDescription?.text || result.ruleId,
        severity,
        confidence: result.properties?.confidence ?? 0.8,
        evidenceState: classification.evidenceState,
        disposition: classification.disposition,
        status: "open",
        isCurrent: publishBaseline,
        filePath: loc?.artifactLocation?.uri || "",
        lineStart: loc?.region?.startLine || 0,
        lineEnd: loc?.region?.endLine || loc?.region?.startLine || 0,
        codeSnippet: sourceSnippet.codeSnippet,
        message: result.message.text,
        cweId,
        owaspCategory,
        taintFlow,
        remediation: result.properties?.remediation || null,
        llmAnalysis: result.properties?.aiReview
          ? JSON.stringify(result.properties.aiReview)
          : result.properties?.llmAnalysis || null,
        callChain: result.properties?.callChain
          ? JSON.stringify(result.properties.callChain) : null,
        defenseContext: result.properties?.defenseContext
          ? JSON.stringify(result.properties.defenseContext) : null,
        evidenceId: evidence.evidenceId,
        repositoryId: evidence.repositoryId,
        modulePath: evidence.modulePath,
        provenance: JSON.stringify({ ...JSON.parse(evidence.provenance), snippet_start_line: sourceSnippet.snippetStartLine }),
        fingerprint: stableFindingFingerprint({
          ruleId: result.ruleId,
          filePath: loc?.artifactLocation?.uri || "",
          message: result.message.text,
          codeSnippet: loc?.region?.snippet?.text || "",
          partialFingerprints: result.partialFingerprints,
        }),
        baselineState: "new",
        identityId: "",
        aiVerdict: result.properties?.aiReview?.verdict || "",
        aiConfidence: result.properties?.aiReview?.confidence ?? null,
        aiReviewStatus: result.properties?.aiReview ? "suggested" : "unreviewed",
        aiProof: JSON.stringify(
          result.properties?.aiReview?.proof || result.properties?.aiProof || {},
        ),
      };
    });

    let findings = parsedFindings;
    if (publishBaseline && projectId && isDefaultBranch && parsedFindings.length > 0) {
      const uniqueFindings = new Map(
        parsedFindings.map((finding) => [finding.fingerprint, finding]),
      );
      const fingerprints = [...uniqueFindings.keys()];
      const existingIdentities = await tx.findingIdentity.findMany({
        where: { projectId, fingerprint: { in: fingerprints } },
      });
      const existingByFingerprint = new Map(
        existingIdentities.map((identity) => [identity.fingerprint, identity]),
      );
      const baselineByFingerprint = new Map(
        [...uniqueFindings].map(([fingerprint, finding]) => [
          fingerprint,
          classifyFindingBaseline(existingByFingerprint.get(fingerprint), finding),
        ]),
      );

      const identityWrites = [...uniqueFindings].map(([fingerprint, finding]) => {
        const existing = existingByFingerprint.get(fingerprint);
        const baselineState = baselineByFingerprint.get(fingerprint) || "new";
        const triageExpired = Boolean(
          existing?.triageExpiresAt && existing.triageExpiresAt <= new Date(),
        );
        const reopened = baselineState === "regressed" &&
          ["fixed", "false_positive"].includes(existing?.status || "");
        const status =
          reopened || triageExpired
            ? "open"
            : existing?.status || "open";
        return tx.findingIdentity.upsert({
          where: { projectId_fingerprint: { projectId, fingerprint } },
          create: {
            projectId,
            fingerprint,
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            status,
            lastSeenScanId: scan.id,
            lastSeverity: finding.severity,
            lastEvidenceState: finding.evidenceState,
            lastMessageDigest: findingMessageDigest(finding.message),
          },
          update: {
            ruleId: finding.ruleId,
            filePath: finding.filePath,
            status,
            lastSeenAt: new Date(),
            lastSeenScanId: scan.id,
            occurrenceCount: { increment: 1 },
            absentAt: null,
            lastSeverity: finding.severity,
            lastEvidenceState: finding.evidenceState,
            lastMessageDigest: findingMessageDigest(finding.message),
          },
        });
      });

      const IDENTITY_WRITE_CHUNK = 200;
      for (let i = 0; i < identityWrites.length; i += IDENTITY_WRITE_CHUNK) {
        for (const write of identityWrites.slice(i, i + IDENTITY_WRITE_CHUNK)) await write;
      }
      const systemTriageEvents = [...uniqueFindings].flatMap(([fingerprint]) => {
        const existing = existingByFingerprint.get(fingerprint);
        if (!existing) return [];
        const baselineState = baselineByFingerprint.get(fingerprint);
        const triageExpired = Boolean(
          existing.triageExpiresAt && existing.triageExpiresAt <= new Date(),
        );
        const regressed = baselineState === "regressed" &&
          ["fixed", "false_positive"].includes(existing.status);
        if (!triageExpired && !regressed) return [];
        return [tx.findingTriageEvent.create({
          data: {
            identityId: existing.id,
            fromStatus: existing.status,
            toStatus: "open",
            reason: triageExpired
              ? "Time-bounded triage decision expired"
              : "Finding reappeared after being absent",
            actor: "aegify-system",
          },
        })];
      });
      for (let i = 0; i < systemTriageEvents.length; i += IDENTITY_WRITE_CHUNK) {
        for (const write of systemTriageEvents.slice(i, i + IDENTITY_WRITE_CHUNK)) await write;
      }
      const persistedIdentities = await tx.findingIdentity.findMany({
        where: { projectId, fingerprint: { in: fingerprints } },
        select: { id: true, fingerprint: true, status: true },
      });
      const identityByFingerprint = new Map(
        persistedIdentities.map((identity) => [identity.fingerprint, identity]),
      );

      findings = parsedFindings.map((finding) => {
        const identity = identityByFingerprint.get(finding.fingerprint);
        return {
          ...finding,
          status: identity?.status || "open",
          identityId: identity?.id || "",
          baselineState: baselineByFingerprint.get(finding.fingerprint) || "new",
        };
      });
    }

    if (findings.length > 0) {
      await tx.finding.createMany({ data: findings });
    }
    // Store call graph if present
    const callGraphData = run.properties?.callGraph;
    if (callGraphData && callGraphData.nodes && callGraphData.nodes.length > 0) {
      // Build a set of file paths with findings for node highlighting
      const findingFiles = new Map<string, string>();
      for (const f of findings) {
        const existing = findingFiles.get(f.filePath);
        const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        if (!existing || (sevOrder[f.severity] ?? 9) < (sevOrder[existing] ?? 9)) {
          findingFiles.set(f.filePath, f.severity);
        }
      }

      // Determine node types based on flags
      const nodeTypeFor = (n: { isEntryPoint?: boolean; isSink?: boolean; qualifiedName?: string }) => {
        if (n.isEntryPoint) return "entry_point";
        if (n.isSink) return "sink";
        if (n.qualifiedName?.startsWith("<module:")) return "module";
        return "function";
      };

      // Create nodes in batches (createMany for performance on large graphs)
      const nodeRecords = callGraphData.nodes.map(
        (n: { qualifiedName: string; filePath?: string; lineStart?: number; lineEnd?: number; isEntryPoint?: boolean; isSink?: boolean }) => ({
          scanId: scan.id,
          qualifiedName: n.qualifiedName,
          filePath: n.filePath || "",
          lineStart: n.lineStart || 0,
          lineEnd: n.lineEnd || 0,
          nodeType: nodeTypeFor(n),
          hasFinding: findingFiles.has(n.filePath || ""),
          findingSeverity: findingFiles.get(n.filePath || "") || null,
        })
      );

      // Batch insert in chunks to avoid DB limits
      const CHUNK_SIZE = 500;
      for (let i = 0; i < nodeRecords.length; i += CHUNK_SIZE) {
        await tx.callGraphNode.createMany({
          data: nodeRecords.slice(i, i + CHUNK_SIZE),
        });
      }

      // Build name -> id map for edges by querying back
      const createdNodes = await tx.callGraphNode.findMany({
        where: { scanId: scan.id },
        select: { id: true, qualifiedName: true },
      });
      const nodeIdMap = new Map<string, string>();
      for (const node of createdNodes) {
        nodeIdMap.set(node.qualifiedName, node.id);
      }

      // Create edges (only for nodes that exist)
      const edgeData = callGraphData.edges
        .filter((e: { source: string; target: string }) =>
          nodeIdMap.has(e.source) && nodeIdMap.has(e.target)
        )
        .map((e: { source: string; target: string; callSiteLine?: number }) => ({
          scanId: scan.id,
          sourceNodeId: nodeIdMap.get(e.source)!,
          targetNodeId: nodeIdMap.get(e.target)!,
          callSiteLine: e.callSiteLine || 0,
        }));

      if (edgeData.length > 0) {
        await tx.callGraphEdge.createMany({ data: edgeData });
      }
    }

    // Store endpoints if present
    const endpointsData = run.properties?.endpoints;

    if (endpointsData && endpointsData.length > 0) {
      const frontendCalls = new Map(
        (run.properties?.frontendCalls || []).map((call) => [call.id, call]),
      );
      const gatewayRoutes = new Map(
        (run.properties?.gatewayRoutes || []).map((route) => [route.id, route]),
      );
      const runtimeObservations = new Map(
        (run.properties?.runtimeObservations || []).map((observation) => [
          observation.id,
          observation,
        ]),
      );
      const links = run.properties?.attackSurfaceLinks || [];
      const epRecords = endpointsData.map((ep) => {
        const endpointLinks = links.filter(
          (link) =>
            link.endpoint_path === ep.path &&
            link.endpoint_method === ep.method &&
            link.endpoint_file_path === ep.filePath &&
            (!link.endpoint_repository_id ||
              link.endpoint_repository_id === (ep.repositoryId || "")),
        );
        const frontendEvidence = endpointLinks
          .filter((link) => link.source_kind === "frontend_call")
          .map((link) => ({
            ...frontendCalls.get(link.source_id),
            matchKind: link.match_kind,
            linkConfidence: link.confidence,
            provenance: link.provenance,
          }));
        const gatewayEvidence = endpointLinks
          .filter((link) => link.source_kind === "gateway_route")
          .map((link) => ({
            ...gatewayRoutes.get(link.source_id),
            matchKind: link.match_kind,
            linkConfidence: link.confidence,
            provenance: link.provenance,
          }));
        const runtimeEvidence = endpointLinks
          .filter((link) => link.source_kind === "runtime_observation")
          .map((link) => ({
            ...runtimeObservations.get(link.source_id),
            matchKind: link.match_kind,
            linkConfidence: link.confidence,
            provenance: link.provenance,
          }));

        return {
          scanId: scan.id,
          path: ep.path,
          method: ep.method,
          handlerFunction: ep.handlerFunction,
          filePath: ep.filePath || "",
          lineStart: ep.lineStart || 0,
          lineEnd: ep.lineEnd || 0,
          framework: ep.framework || "",
          authRequired: ep.authRequired || false,
          parameters: JSON.stringify(ep.parameters || []),
          middleware: JSON.stringify(ep.middleware || []),
          repositoryId: ep.repositoryId || "",
          calledByFrontend: ep.calledByFrontend || frontendEvidence.length > 0,
          frontendCallCount:
            ep.frontendCallCount || frontendEvidence.length,
          frontendEvidence: JSON.stringify(frontendEvidence),
          exposedViaGateway: ep.exposedViaGateway || gatewayEvidence.length > 0,
          gatewayRouteIds: JSON.stringify(ep.gatewayRouteIds || []),
          gatewayEvidence: JSON.stringify(gatewayEvidence),
          runtimeObserved: ep.runtimeObserved || runtimeEvidence.length > 0,
          runtimeObservationCount:
            ep.runtimeObservationCount || runtimeEvidence.length,
          runtimeEvidence: JSON.stringify(runtimeEvidence),
        };
      });
      await tx.endpoint.createMany({ data: epRecords });
    }

    // Upsert rules
    for (const [ruleId, rule] of canManageWorkspace ? ruleMap : []) {
      const count = await tx.finding.count({
        where: { ruleId, isCurrent: true },
      });
      let cweId: number | null = null;
      if (rule.properties?.cwe) {
        const m = rule.properties.cwe.match(/CWE-(\d+)/);
        if (m) cweId = parseInt(m[1], 10);
      }
      const owaspTag = rule.properties?.tags?.find((t: string) =>
        t.startsWith("OWASP:")
      );

      await tx.rule.upsert({
        where: { id: ruleId },
        create: {
          id: ruleId,
          name: rule.name || rule.shortDescription?.text || ruleId,
          severity:
            LEVEL_TO_SEVERITY[rule.defaultConfiguration?.level || "warning"] ||
            "medium",
          cweId,
          owaspCategory: owaspTag?.replace("OWASP:", "") || null,
          findingCount: count,
          description: rule.properties?.description || rule.fullDescription?.text || "",
          yamlContent: rule.properties?.yamlContent || "",
        },
        update: {
          findingCount: count,
          description: rule.properties?.description || rule.fullDescription?.text || undefined,
          yamlContent: rule.properties?.yamlContent || undefined,
        },
      });
    }

    await publishScanImport(tx, {
      scanId: scan.id, projectId, branch, publishBaseline,
      defaultBranch: project?.defaultBranch || "", health: scanHealth,
      audit: { actorId: actorId, findings: findings.length },
    });


    const receipt: ImportReceipt = {
      scanId: scan.id, findingsCount: findings.length, status: scanHealth.status,
      baseline: findings.reduce<Record<string, number>>((counts, finding) => {
        counts[finding.baselineState] = (counts[finding.baselineState] || 0) + 1;
        return counts;
      }, {}),
    };
    await context.onPublished?.(tx, receipt);
    return receipt;
  }, { timeout: 60_000, maxWait: 10_000 });
}
