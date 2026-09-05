import { getJiraConfig } from "@/lib/settings";
import { validateJiraBaseUrl } from "@/lib/url-validator";

interface JiraFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: number;
  evidenceState: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  message: string;
  remediation: string | null;
  ticketKey: string;
  scan: { repository: string; branch: string; commitSha: string };
}

interface JiraIssueResult {
  key: string;
  url: string;
}

export async function createJiraFindingIssue(finding: JiraFinding): Promise<JiraIssueResult> {
  const config = await getJiraConfig();
  if (!config.enabled) throw new Error("Jira integration is disabled");
  if (!config.baseUrl || !config.email || !config.apiToken || !config.projectKey) {
    throw new Error("Jira integration is incomplete");
  }
  const validation = validateJiraBaseUrl(config.baseUrl);
  if (!validation.valid) throw new Error(validation.error || "Invalid Jira URL");
  if (finding.ticketKey) throw new Error(`Finding already has Jira ticket ${finding.ticketKey}`);

  const summary = `[Aegify][${finding.severity.toUpperCase()}] ${finding.ruleName}`.slice(0, 255);
  const description = jiraDocument([
    `Repository: ${finding.scan.repository}`,
    `Revision: ${finding.scan.branch} @ ${finding.scan.commitSha || "unknown"}`,
    `Location: ${finding.filePath}:${finding.lineStart}-${finding.lineEnd}`,
    `Rule: ${finding.ruleId}`,
    `Evidence: ${finding.evidenceState}; confidence ${(finding.confidence * 100).toFixed(0)}%`,
    "",
    finding.message,
    "",
    `Remediation: ${finding.remediation || "Review the Aegify evidence and apply a framework-specific fix."}`,
    "",
    `Aegify finding ID: ${finding.id}`,
  ]);
  const response = await fetch(`${config.baseUrl}/rest/api/3/issue`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
    headers: {
      "Authorization": `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString("base64")}`,
      "Accept": "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fields: {
        project: { key: config.projectKey },
        issuetype: { name: config.issueType },
        summary,
        description,
        labels: ["aegify", `severity-${finding.severity}`],
      },
    }),
  });
  const body = await readBounded(response);
  if (!response.ok) throw new Error(`Jira returned ${response.status}: ${safeMessage(body)}`);
  const parsed = JSON.parse(body) as { key?: string };
  if (!parsed.key || !/^[A-Z][A-Z0-9_]{1,19}-\d+$/.test(parsed.key)) {
    throw new Error("Jira response did not contain a valid issue key");
  }
  return { key: parsed.key, url: `${config.baseUrl}/browse/${parsed.key}` };
}

export async function testJiraConnection(): Promise<string> {
  const config = await getJiraConfig();
  if (!config.baseUrl || !config.email || !config.apiToken) {
    throw new Error("Jira URL, email, and API token are required");
  }
  const validation = validateJiraBaseUrl(config.baseUrl);
  if (!validation.valid) throw new Error(validation.error || "Invalid Jira URL");
  const response = await fetch(`${config.baseUrl}/rest/api/3/myself`, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    headers: {
      "Authorization": `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString("base64")}`,
      "Accept": "application/json",
    },
  });
  const body = await readBounded(response);
  if (!response.ok) throw new Error(`Jira returned ${response.status}: ${safeMessage(body)}`);
  const parsed = JSON.parse(body) as { displayName?: string };
  return parsed.displayName || "Jira account";
}

function jiraDocument(lines: string[]) {
  return {
    type: "doc",
    version: 1,
    content: lines.map((line) => ({
      type: "paragraph",
      content: line ? [{ type: "text", text: line.slice(0, 10_000) }] : [],
    })),
  };
}

async function readBounded(response: Response): Promise<string> {
  const length = Number(response.headers.get("content-length") || "0");
  if (length > 1_000_000) throw new Error("Jira response exceeds 1 MB");
  const value = await response.text();
  if (value.length > 1_000_000) throw new Error("Jira response exceeds 1 MB");
  return value;
}

function safeMessage(value: string): string {
  return value.replace(/(?:token|password|secret|authorization)[^\s,}]*/gi, "[REDACTED]").slice(0, 500);
}
