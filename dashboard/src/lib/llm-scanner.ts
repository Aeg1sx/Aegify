import { getLLMConfig } from "@/lib/settings";
import { prisma } from "@/lib/prisma";

interface LLMReviewResult {
  findingId: string;
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  remediation: string;
  adjustedSeverity?: string;
}

export async function callLLM(
  systemPrompt: string,
  userPrompt: string,
): Promise<string> {
  const config = await getLLMConfig();

  if (!config.enabled) {
    throw new Error("LLM analysis is not enabled. Configure it in Settings.");
  }

  const hasCustomEndpoint = !!config.customEndpoint;
  const hasCustomHeaders = Object.keys(config.customHeaders).length > 0;

  if (config.provider === "anthropic") {
    if (!config.anthropicApiKey && !hasCustomEndpoint) {
      throw new Error("Anthropic API key not configured.");
    }
    const baseUrl = (config.customEndpoint || "https://api.anthropic.com").replace(/\/+$/, "");
    const url = baseUrl.endsWith("/v1/messages") ? baseUrl : `${baseUrl}/v1/messages`;

    const reqHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      "anthropic-version": "2023-06-01",
    };
    if (config.anthropicApiKey) reqHeaders["x-api-key"] = config.anthropicApiKey;

    const res = await fetch(url, {
      method: "POST",
      headers: { ...reqHeaders, ...(hasCustomHeaders ? config.customHeaders : {}) },
      body: JSON.stringify({
        model: config.model,
        max_tokens: 4096,
        system: systemPrompt,
        messages: [{ role: "user", content: userPrompt }],
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${body}`);
    }

    const data = await res.json();
    return data.content?.[0]?.text || "";
  } else if (config.provider === "openai") {
    if (!config.openaiApiKey && !hasCustomEndpoint) {
      throw new Error("OpenAI API key not configured.");
    }
    const baseUrl = (config.customEndpoint || "https://api.openai.com").replace(/\/+$/, "");
    const url = baseUrl.endsWith("/v1/chat/completions") ? baseUrl : `${baseUrl}/v1/chat/completions`;

    const reqHeaders: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (config.openaiApiKey) reqHeaders["Authorization"] = `Bearer ${config.openaiApiKey}`;

    const res = await fetch(url, {
      method: "POST",
      headers: { ...reqHeaders, ...(hasCustomHeaders ? config.customHeaders : {}) },
      body: JSON.stringify({
        model: config.model,
        max_tokens: 4096,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
      }),
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`OpenAI API error ${res.status}: ${body}`);
    }

    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  }

  throw new Error(`Unsupported provider: ${config.provider}`);
}

function getQuickReviewPrompt(): string {
  return `You are an expert application security engineer reviewing SAST findings for false positives.

For each finding, determine:
1. Is this a true positive or false positive?
2. What is your confidence level?
3. Brief reasoning for your assessment
4. If true positive: suggest specific remediation
5. If the severity should be adjusted, recommend a new severity

Respond with a JSON array:
[
  {
    "findingId": "<the finding ID>",
    "isFalsePositive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "Why this is/isn't a real vulnerability",
    "remediation": "Specific fix if true positive, empty string if false positive",
    "adjustedSeverity": "critical|high|medium|low or null to keep current"
  }
]

Guidelines:
- Consider context: Is the input actually user-controlled?
- Check for existing defenses in the code snippet
- Consider framework-level protections
- Be conservative: when unsure, mark as true positive with lower confidence`;
}

function getDeepReviewPrompt(): string {
  return `You are an expert application security engineer performing deep context-aware analysis of SAST findings.

You have access to:
- The SAST findings with code snippets
- Call graph data showing function relationships
- Entry points and security-sensitive sinks

Analyze each finding considering:
1. **Data flow**: Can tainted data actually reach the sink?
2. **Call chain**: Are there sanitizers or validators in the path?
3. **Cross-function issues**: Are there vulnerabilities that span multiple functions?
4. **Missing findings**: Based on the call graph, are there additional vulnerabilities not caught by SAST?

Respond with a JSON array:
[
  {
    "findingId": "<the finding ID or 'NEW' for newly discovered issues>",
    "isFalsePositive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "Detailed analysis including data flow path",
    "remediation": "Specific fix with code example",
    "adjustedSeverity": "critical|high|medium|low or null"
  }
]

For NEW findings (discovered via call graph analysis), use findingId "NEW-1", "NEW-2", etc.
and include additional fields: ruleName, severity, filePath, lineStart, message.`;
}

function parseReviewResults(raw: string): LLMReviewResult[] {
  let jsonStr = raw.trim();

  const blockMatch = jsonStr.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (blockMatch) {
    jsonStr = blockMatch[1].trim();
  }

  if (!jsonStr.startsWith("[")) {
    const first = jsonStr.indexOf("[");
    const last = jsonStr.lastIndexOf("]");
    if (first !== -1 && last > first) {
      jsonStr = jsonStr.slice(first, last + 1);
    }
  }

  try {
    const parsed = JSON.parse(jsonStr);
    if (!Array.isArray(parsed)) return [];

    return parsed.map((r: Record<string, unknown>) => ({
      findingId: (r.findingId as string) || "",
      isFalsePositive: !!r.isFalsePositive,
      confidence: typeof r.confidence === "number" ? r.confidence : 0.7,
      reasoning: (r.reasoning as string) || "",
      remediation: (r.remediation as string) || "",
      adjustedSeverity: (r.adjustedSeverity as string) || undefined,
    }));
  } catch {
    return [];
  }
}

export async function reviewScanFindings(
  scanId: string,
  mode: "quick" | "deep",
  jobId?: string,
): Promise<{ reviewed: number; falsePositives: number; errors: string[] }> {
  let reviewed = 0;
  let falsePositives = 0;
  const errors: string[] = [];

  // Helper to update job progress
  async function updateJob(data: Record<string, unknown>) {
    if (!jobId) return;
    await prisma.llmJob.update({ where: { id: jobId }, data });
  }

  // Update scan type to reflect the LLM review
  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "running" },
  });

  await updateJob({ status: "running", startedAt: new Date() });

  try {
    // Fetch all findings for this scan
    const findings = await prisma.finding.findMany({
      where: { scanId },
      orderBy: { severity: "asc" },
    });

    if (findings.length === 0) {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: "completed" },
      });
      await updateJob({ status: "completed", completedAt: new Date(), errorMessage: "No findings to review" });
      return { reviewed: 0, falsePositives: 0, errors: ["No findings to review"] };
    }

    const batchSize = 50;
    const totalBatches = Math.ceil(findings.length / batchSize);
    await updateJob({ totalFindings: findings.length, totalBatches });

    // Build call graph context for deep mode
    let graphContext = "";
    if (mode === "deep") {
      const nodes = await prisma.callGraphNode.findMany({
        where: { scanId },
        include: {
          outEdges: { include: { targetNode: true } },
          inEdges: { include: { sourceNode: true } },
        },
      });

      if (nodes.length > 0) {
        graphContext = "\n\n## Call Graph Context\n\n";

        const entryPoints = nodes.filter((n) => n.nodeType === "entry_point");
        if (entryPoints.length > 0) {
          graphContext += "### Entry Points\n";
          for (const ep of entryPoints) {
            graphContext += `- ${ep.qualifiedName} (${ep.filePath}:${ep.lineStart})`;
            if (ep.hasFinding) graphContext += ` [has ${ep.findingSeverity} finding]`;
            graphContext += "\n";
            for (const edge of ep.outEdges.slice(0, 10)) {
              graphContext += `  → calls ${edge.targetNode.qualifiedName}\n`;
            }
          }
        }

        const sinks = nodes.filter((n) => n.nodeType === "sink");
        if (sinks.length > 0) {
          graphContext += "\n### Security-Sensitive Sinks\n";
          for (const sink of sinks) {
            graphContext += `- ${sink.qualifiedName} (${sink.filePath}:${sink.lineStart})`;
            if (sink.inEdges.length > 0) {
              graphContext += ` ← called by: ${sink.inEdges.map((e) => e.sourceNode.qualifiedName).join(", ")}`;
            }
            graphContext += "\n";
          }
        }

        graphContext += "\n### Call Relationships\n";
        for (const node of nodes.slice(0, 50)) {
          for (const edge of node.outEdges) {
            graphContext += `${node.qualifiedName} → ${edge.targetNode.qualifiedName}`;
            if (edge.callSiteLine > 0) graphContext += ` (line ${edge.callSiteLine})`;
            graphContext += "\n";
          }
        }
      }
    }

    const systemPrompt = mode === "quick" ? getQuickReviewPrompt() : getDeepReviewPrompt();

    // Process findings in batches of 50
    for (let i = 0; i < findings.length; i += batchSize) {
      const batch = findings.slice(i, i + batchSize);
      const batchNum = Math.floor(i / batchSize) + 1;

      // Update job progress before each batch
      await updateJob({ currentBatch: batchNum, reviewedCount: reviewed });

      // Build the user prompt with finding details
      let userPrompt = `## Findings to Review (batch ${Math.floor(i / batchSize) + 1})\n\n`;
      for (const f of batch) {
        userPrompt += `### Finding: ${f.id}\n`;
        userPrompt += `- **Rule**: ${f.ruleId} - ${f.ruleName}\n`;
        userPrompt += `- **Severity**: ${f.severity}\n`;
        userPrompt += `- **File**: ${f.filePath}:${f.lineStart}-${f.lineEnd}\n`;
        userPrompt += `- **Message**: ${f.message}\n`;
        if (f.codeSnippet) {
          userPrompt += `- **Code**:\n\`\`\`\n${f.codeSnippet}\n\`\`\`\n`;
        }
        if (f.taintFlow) {
          userPrompt += `- **Taint Flow**: ${f.taintFlow}\n`;
        }
        userPrompt += "\n";
      }

      if (graphContext) {
        userPrompt += graphContext;
      }

      try {
        const raw = await callLLM(systemPrompt, userPrompt);
        const results = parseReviewResults(raw);

        // Update findings with LLM analysis
        for (const result of results) {
          if (result.findingId.startsWith("NEW")) continue; // Skip new findings for now

          const finding = batch.find((f) => f.id === result.findingId);
          if (!finding) continue;

          const llmAnalysis = JSON.stringify({
            isFalsePositive: result.isFalsePositive,
            confidence: result.confidence,
            reasoning: result.reasoning,
            remediation: result.remediation,
            adjustedSeverity: result.adjustedSeverity,
            mode,
            reviewedAt: new Date().toISOString(),
          });

          const updateData: Record<string, unknown> = {
            llmAnalysis,
          };

          // Auto-triage false positives with high confidence
          if (result.isFalsePositive && result.confidence >= 0.85) {
            updateData.status = "false_positive";
          }

          // Update remediation if provided
          if (result.remediation) {
            updateData.remediation = result.remediation;
          }

          await prisma.finding.update({
            where: { id: finding.id },
            data: updateData,
          });

          reviewed++;
          if (result.isFalsePositive) falsePositives++;
        }
      } catch (e) {
        errors.push(`Batch ${Math.floor(i / batchSize) + 1}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "completed" },
    });

    await updateJob({
      status: "completed",
      completedAt: new Date(),
      reviewedCount: reviewed,
      falsePositives,
      errorMessage: errors.length > 0 ? errors.join("; ") : "",
    });
  } catch (error) {
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "failed" },
    });
    await updateJob({
      status: "failed",
      completedAt: new Date(),
      errorMessage: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }

  return { reviewed, falsePositives, errors };
}
