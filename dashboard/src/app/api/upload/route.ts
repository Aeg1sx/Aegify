import { NextRequest, NextResponse } from "next/server";
import { timingSafeEqual } from "crypto";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import {
  normalizeFindingClassification,
  normalizeFindingEvidence,
  workspaceSnapshotForRun,
} from "@/lib/sarif-evidence";
import {
  classifyFindingBaseline,
  findingMessageDigest,
  stableFindingFingerprint,
} from "@/lib/finding-lifecycle";
import { anonymousUploadAllowed } from "@/lib/security-config";
import { sendSlackNotification } from "@/lib/slack";
import { uploadValidationError } from "@/lib/upload-validation";

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

async function isAuthorizedUpload(request: NextRequest): Promise<boolean> {
  const session = await auth();
  if (session?.user) return true;

  const configuredToken = process.env.AEGIFY_UPLOAD_TOKEN;
  const authorization = request.headers.get("authorization") || "";
  const suppliedToken = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : request.headers.get("x-aegify-token") || "";

  if (configuredToken && suppliedToken) {
    const expected = Buffer.from(configuredToken);
    const actual = Buffer.from(suppliedToken);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }

  // Preserve zero-configuration development only. Production is fail-closed.
  return anonymousUploadAllowed(process.env);
}

interface SARIFResult {
  ruleId: string;
  level: string;
  message: { text: string };
  partialFingerprints?: Record<string, string>;
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri: string };
      region?: { startLine: number; endLine?: number; snippet?: { text: string } };
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

export async function POST(request: NextRequest) {
  try {
    if (!(await isAuthorizedUpload(request))) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > MAX_UPLOAD_BYTES) {
      return NextResponse.json(
        { error: "SARIF upload exceeds the 100 MB limit" },
        { status: 413 },
      );
    }

    const contentType = request.headers.get("content-type") || "";

    let sarif: SARIFReport;
    let formProjectName: string | null = null;

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file") as File;
      if (!file) {
        return NextResponse.json({ error: "No file provided" }, { status: 400 });
      }
      const uploadError = uploadValidationError(file, "sarif");
      if (uploadError) {
        const status = uploadError.includes("exceeds") ? 413 : 415;
        return NextResponse.json({ error: uploadError }, { status });
      }
      const text = await file.text();
      sarif = JSON.parse(text);
      formProjectName = (formData.get("projectName") as string) || null;
    } else {
      const text = await request.text();
      if (Buffer.byteLength(text, "utf8") > MAX_UPLOAD_BYTES) {
        return NextResponse.json(
          { error: "SARIF upload exceeds the 100 MB limit" },
          { status: 413 },
        );
      }
      sarif = JSON.parse(text);
    }

    if (!sarif.runs || sarif.runs.length === 0) {
      return NextResponse.json({ error: "Invalid SARIF: no runs" }, { status: 400 });
    }

    const run = sarif.runs[0];
    const invocation = run.invocations?.[0];
    const workspaceSnapshot = workspaceSnapshotForRun(
      run.properties,
      invocation?.properties,
    );

    // Build rule lookup
    const ruleMap = new Map<string, SARIFRule>();
    for (const rule of run.tool.driver.rules || []) {
      ruleMap.set(rule.id, rule);
    }

    // Check for projectId query param or auto-match by repository/projectName
    const reqUrl = new URL(request.url);
    const repository = reqUrl.searchParams.get("repository") || "";
    let projectId = reqUrl.searchParams.get("projectId") || null;

    // Auto-link to project by repository URL if not explicitly provided
    if (!projectId && repository) {
      const matchedProject = await prisma.project.findFirst({
        where: { repositoryUrl: repository },
      });
      if (matchedProject) projectId = matchedProject.id;
    }

    // Auto-create/link project from multipart projectName field or query param
    if (!projectId) {
      const projectName = formProjectName || reqUrl.searchParams.get("projectName");
      if (projectName) {
        const existing = await prisma.project.findFirst({
          where: { name: projectName },
        });
        if (existing) {
          projectId = existing.id;
        } else {
          const created = await prisma.project.create({
            data: { name: projectName, repositoryUrl: repository },
          });
          projectId = created.id;
        }
      }
    }

    // Create scan
    const scan = await prisma.scan.create({
      data: {
        repository,
        branch: reqUrl.searchParams.get("branch") || "",
        commitSha: reqUrl.searchParams.get("commit") || "",
        status: invocation?.executionSuccessful ? "completed" : "failed",
        filesScanned: invocation?.properties?.filesScanned || 0,
        duration: invocation?.properties?.durationSeconds || 0,
        workspaceSnapshot,
        projectId,
      },
    });

    // Insert findings
    const parsedFindings = run.results.map((result) => {
      const rule = ruleMap.get(result.ruleId);
      const loc = result.locations?.[0]?.physicalLocation;
      const severity =
        result.properties?.severity ||
        LEVEL_TO_SEVERITY[result.level] ||
        "medium";
      const evidence = normalizeFindingEvidence(result.properties);
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
        confidence: result.properties?.confidence || 0.8,
        evidenceState: classification.evidenceState,
        disposition: classification.disposition,
        status: "open",
        filePath: loc?.artifactLocation?.uri || "",
        lineStart: loc?.region?.startLine || 0,
        lineEnd: loc?.region?.endLine || loc?.region?.startLine || 0,
        codeSnippet: loc?.region?.snippet?.text || "",
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
        provenance: evidence.provenance,
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
    if (projectId && parsedFindings.length === 0) {
      await prisma.findingIdentity.updateMany({
        where: { projectId, absentAt: null },
        data: { absentAt: new Date() },
      });
    }
    if (projectId && parsedFindings.length > 0) {
      const uniqueFindings = new Map(
        parsedFindings.map((finding) => [finding.fingerprint, finding]),
      );
      const fingerprints = [...uniqueFindings.keys()];
      const existingIdentities = await prisma.findingIdentity.findMany({
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

      await prisma.findingIdentity.updateMany({
        where: {
          projectId,
          absentAt: null,
          fingerprint: { notIn: fingerprints },
        },
        data: { absentAt: new Date() },
      });

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
        return prisma.findingIdentity.upsert({
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
        await prisma.$transaction(identityWrites.slice(i, i + IDENTITY_WRITE_CHUNK));
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
        return [prisma.findingTriageEvent.create({
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
        await prisma.$transaction(systemTriageEvents.slice(i, i + IDENTITY_WRITE_CHUNK));
      }
      const persistedIdentities = await prisma.findingIdentity.findMany({
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
      await prisma.finding.createMany({ data: findings });
    }
    if (projectId) {
      await prisma.finding.updateMany({
        where: {
          scanId: { not: scan.id },
          scan: { projectId },
          isCurrent: true,
        },
        data: { isCurrent: false },
      });
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
        await prisma.callGraphNode.createMany({
          data: nodeRecords.slice(i, i + CHUNK_SIZE),
        });
      }

      // Build name -> id map for edges by querying back
      const createdNodes = await prisma.callGraphNode.findMany({
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
        await prisma.callGraphEdge.createMany({ data: edgeData });
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
      await prisma.endpoint.createMany({ data: epRecords });
    }

    // Upsert rules
    for (const [ruleId, rule] of ruleMap) {
      const count = await prisma.finding.count({
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

      await prisma.rule.upsert({
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

    // Send Slack notification for new findings (non-blocking)
    const actionableFindings = findings.filter((finding) =>
      finding.baselineState === "new" || finding.baselineState === "regressed"
    );
    if (actionableFindings.length > 0) {
      sendSlackNotification({
        scanId: scan.id,
        repository: new URL(request.url).searchParams.get("repository") || "",
        branch: new URL(request.url).searchParams.get("branch") || "",
        totalFindings: actionableFindings.length,
        findings: actionableFindings.map((f) => ({
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          filePath: f.filePath,
          lineStart: f.lineStart,
          message: f.message,
        })),
      }).catch((err) => console.error("Slack notification error:", err));
    }

    return NextResponse.json({
      scanId: scan.id,
      findingsCount: findings.length,
      baseline: findings.reduce<Record<string, number>>((counts, finding) => {
        counts[finding.baselineState] = (counts[finding.baselineState] || 0) + 1;
        return counts;
      }, {}),
    });
  } catch (error) {
    console.error("Upload error:", error);
    return NextResponse.json(
      { error: "Upload failed" },
      { status: 500 }
    );
  }
}
