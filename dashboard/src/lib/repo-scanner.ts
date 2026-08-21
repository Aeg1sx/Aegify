import { prisma } from "@/lib/prisma";
import { getGitHubToken } from "@/lib/github";
import { getGitLabToken } from "@/lib/gitlab";
import { fetchRepoCode, CodeBundle } from "@/lib/repo-fetcher";
import { callLLM } from "@/lib/llm-scanner";

interface RepoScanFinding {
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: number;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  message: string;
  cweId?: number;
  owaspCategory?: string;
  remediation?: string;
}

function getRepoScanSystemPrompt(): string {
  return `You are an expert application security engineer performing a code security review.
Analyze the provided source code files for security vulnerabilities.

For each vulnerability found, provide:
1. A rule identifier (e.g. "REPO-SQL-INJECTION", "REPO-XSS", "REPO-HARDCODED-SECRET")
2. A human-readable rule name
3. Severity: critical, high, medium, or low
4. Confidence: 0.0-1.0
5. The exact file path and approximate line numbers
6. A relevant code snippet (the vulnerable lines)
7. A clear description of the vulnerability
8. CWE ID if applicable
9. OWASP category if applicable
10. Specific remediation advice

Focus on real, exploitable vulnerabilities:
- SQL injection, XSS, command injection, path traversal
- Hardcoded secrets/credentials/API keys
- Insecure cryptographic usage
- Authentication/authorization bypasses
- SSRF, open redirects
- Insecure deserialization
- Missing input validation at trust boundaries

Do NOT flag:
- Style issues or code quality
- Missing error handling (unless it creates a security issue)
- Framework-managed security (e.g. CSRF tokens in Rails/Django)

Respond with a JSON array:
[
  {
    "ruleId": "REPO-XXX",
    "ruleName": "Human Readable Name",
    "severity": "critical|high|medium|low",
    "confidence": 0.0-1.0,
    "filePath": "path/to/file.ts",
    "lineStart": 10,
    "lineEnd": 15,
    "codeSnippet": "vulnerable code here",
    "message": "Description of the vulnerability",
    "cweId": 89,
    "owaspCategory": "A03:2021-Injection",
    "remediation": "How to fix this"
  }
]

If no vulnerabilities are found, return an empty array: []`;
}

function parseScanResults(raw: string): RepoScanFinding[] {
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
      ruleId: (r.ruleId as string) || "REPO-UNKNOWN",
      ruleName: (r.ruleName as string) || "Unknown Finding",
      severity: ["critical", "high", "medium", "low"].includes(r.severity as string)
        ? (r.severity as string)
        : "medium",
      confidence: typeof r.confidence === "number" ? r.confidence : 0.7,
      filePath: (r.filePath as string) || "",
      lineStart: typeof r.lineStart === "number" ? r.lineStart : 0,
      lineEnd: typeof r.lineEnd === "number" ? r.lineEnd : 0,
      codeSnippet: (r.codeSnippet as string) || "",
      message: (r.message as string) || "",
      cweId: typeof r.cweId === "number" ? r.cweId : undefined,
      owaspCategory: (r.owaspCategory as string) || undefined,
      remediation: (r.remediation as string) || undefined,
    }));
  } catch {
    return [];
  }
}

function buildBatchPrompt(
  files: { path: string; content: string }[],
): string {
  let prompt = "## Source Code Files to Review\n\n";
  for (const file of files) {
    prompt += `### ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n\n`;
  }
  return prompt;
}

export async function scanRepoCode(
  projectId: string,
  userId: string,
  branch?: string,
): Promise<{ scanId: string }> {
  // 1. Load project
  const project = await prisma.project.findUnique({ where: { id: projectId } });
  if (!project) throw new Error("Project not found");
  if (!project.provider || !project.ownerSlug) {
    throw new Error("No repository connected to this project");
  }

  const provider = project.provider as "github" | "gitlab";
  const ref = branch || project.defaultBranch || "main";

  // 2. Get OAuth token
  let accessToken: string | null = null;
  if (provider === "github") {
    accessToken = await getGitHubToken(userId);
  } else {
    accessToken = await getGitLabToken(userId);
  }
  if (!accessToken) {
    throw new Error(`No ${provider} OAuth token found. Please connect your ${provider} account.`);
  }

  // 3. Create scan record
  const scan = await prisma.scan.create({
    data: {
      repository: project.ownerSlug,
      branch: ref,
      status: "running",
      scanType: "repo-scan",
      projectId: project.id,
    },
  });

  try {
    // 4. Fetch code (in-memory only)
    const bundle: CodeBundle = await fetchRepoCode({
      provider,
      accessToken,
      ownerSlug: project.ownerSlug,
      providerRepoId: project.providerRepoId,
      ref,
    });

    if (bundle.files.length === 0) {
      await prisma.scan.update({
        where: { id: scan.id },
        data: { status: "completed", filesScanned: 0 },
      });
      return { scanId: scan.id };
    }

    // 5. Split into batches (~100K chars each)
    const MAX_BATCH_CHARS = 100_000;
    const batches: { path: string; content: string }[][] = [];
    let currentBatch: { path: string; content: string }[] = [];
    let currentChars = 0;

    for (const file of bundle.files) {
      const fileChars = file.path.length + file.content.length + 20; // overhead
      if (currentChars + fileChars > MAX_BATCH_CHARS && currentBatch.length > 0) {
        batches.push(currentBatch);
        currentBatch = [];
        currentChars = 0;
      }
      currentBatch.push({ path: file.path, content: file.content });
      currentChars += fileChars;
    }
    if (currentBatch.length > 0) {
      batches.push(currentBatch);
    }

    // 6. Process each batch through LLM
    const systemPrompt = getRepoScanSystemPrompt();
    const allFindings: RepoScanFinding[] = [];
    const startTime = Date.now();

    for (const batch of batches) {
      try {
        const userPrompt = buildBatchPrompt(batch);
        const raw = await callLLM(systemPrompt, userPrompt);
        const findings = parseScanResults(raw);
        allFindings.push(...findings);
      } catch (e) {
        console.error(`Repo scan batch error:`, e);
      }
    }

    const duration = (Date.now() - startTime) / 1000;

    // 7. Create Finding records
    if (allFindings.length > 0) {
      await prisma.finding.createMany({
        data: allFindings.map((f) => ({
          scanId: scan.id,
          ruleId: f.ruleId,
          ruleName: f.ruleName,
          severity: f.severity,
          confidence: f.confidence,
          source: "llm",
          filePath: f.filePath,
          lineStart: f.lineStart,
          lineEnd: f.lineEnd,
          codeSnippet: f.codeSnippet,
          message: f.message,
          cweId: f.cweId,
          owaspCategory: f.owaspCategory,
          remediation: f.remediation,
        })),
      });
    }

    // 8. Update scan record
    await prisma.scan.update({
      where: { id: scan.id },
      data: {
        status: "completed",
        filesScanned: bundle.files.length,
        duration,
      },
    });
  } catch (error) {
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: "failed" },
    });
    throw error;
  }

  return { scanId: scan.id };
}
