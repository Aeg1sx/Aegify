import { getSlackConfig } from "@/lib/settings";

interface FindingSummary {
  ruleId: string;
  ruleName: string;
  severity: string;
  filePath: string;
  lineStart: number;
  message: string;
}

interface SlackNotificationPayload {
  scanId: string;
  repository: string;
  branch: string;
  totalFindings: number;
  findings: FindingSummary[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const SEVERITY_EMOJI: Record<string, string> = {
  critical: ":red_circle:",
  high: ":large_orange_circle:",
  medium: ":large_yellow_circle:",
  low: ":large_blue_circle:",
};

export async function sendSlackNotification(
  payload: SlackNotificationPayload
): Promise<boolean> {
  const config = await getSlackConfig();

  if (!config.enabled || !config.webhookUrl) {
    return false;
  }

  // Filter findings by configured minimum severity
  const minSeverity = SEVERITY_ORDER[config.notifySeverity] ?? 1;
  const filtered = payload.findings.filter(
    (f) => (SEVERITY_ORDER[f.severity] ?? 3) <= minSeverity
  );

  if (filtered.length === 0) {
    return false;
  }

  // Count by severity
  const counts: Record<string, number> = {};
  for (const f of filtered) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const countSummary = Object.entries(counts)
    .sort((a, b) => (SEVERITY_ORDER[a[0]] ?? 9) - (SEVERITY_ORDER[b[0]] ?? 9))
    .map(([sev, cnt]) => `${SEVERITY_EMOJI[sev] || ":white_circle:"} ${sev}: ${cnt}`)
    .join("  ");

  // Build finding details (max 10 lines)
  const topFindings = filtered
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
    .slice(0, 10);

  const findingLines = topFindings
    .map(
      (f) =>
        `${SEVERITY_EMOJI[f.severity] || ""} \`${f.filePath}:${f.lineStart}\` - ${f.ruleName}`
    )
    .join("\n");

  const remainingCount = filtered.length - topFindings.length;
  const moreText = remainingCount > 0 ? `\n_...and ${remainingCount} more_` : "";

  const repoName = payload.repository || "Unknown";
  const branchName = payload.branch || "main";

  const message = {
    channel: config.channel,
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `:shield: CodeGuard SAST - ${filtered.length} New Findings`,
        },
      },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*Repository:*\n${repoName}` },
          { type: "mrkdwn", text: `*Branch:*\n${branchName}` },
          { type: "mrkdwn", text: `*Total Findings:*\n${payload.totalFindings}` },
          { type: "mrkdwn", text: `*Notified:*\n${filtered.length}` },
        ],
      },
      {
        type: "section",
        text: { type: "mrkdwn", text: `*Severity Breakdown:*\n${countSummary}` },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Top Findings:*\n${findingLines}${moreText}`,
        },
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `Scan ID: \`${payload.scanId}\``,
          },
        ],
      },
    ],
  };

  try {
    const res = await fetch(config.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });

    return res.ok;
  } catch (error) {
    console.error("Slack notification failed:", error);
    return false;
  }
}
