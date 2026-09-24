import { prisma } from "./prisma.ts";
import { decrypt } from "./crypto.ts";
import type { Prisma } from "@prisma/client";

export async function getSetting(key: string, db: Pick<Prisma.TransactionClient, "setting"> = prisma): Promise<string> {
  const setting = await db.setting.findUnique({ where: { key } });
  if (!setting) return "";
  if (setting.encrypted) {
    try {
      return decrypt(setting.value);
    } catch {
      return "";
    }
  }
  return setting.value;
}

export async function getLLMConfig(db: Pick<Prisma.TransactionClient, "setting"> = prisma) {
  const [
    provider, model, anthropicKey, openaiKey, googleKey,
    enabled, autoVerify, threshold,
    customEndpoint, customHeaders, language, maxOutputTokens, timeoutSeconds, chatTokenParameter,
  ] = await Promise.all([
    "llm.provider", "llm.model", "llm.anthropic_api_key", "llm.openai_api_key", "llm.google_api_key",
    "llm.enabled", "llm.auto_verify", "llm.verify_threshold", "llm.custom_endpoint", "llm.custom_headers",
    "llm.language", "llm.max_output_tokens", "llm.timeout_seconds", "llm.chat_token_parameter",
  ].map((key) => getSetting(key, db)));

  let parsedHeaders: Record<string, string> = {};
  if (customHeaders) {
    try {
      parsedHeaders = JSON.parse(customHeaders);
    } catch {
      // ignore invalid JSON
    }
  }

  return {
    provider: provider || "anthropic",
    model,
    anthropicApiKey: anthropicKey,
    openaiApiKey: openaiKey,
    googleApiKey: googleKey,
    enabled: enabled === "true",
    autoVerify: autoVerify === "true",
    verifyThreshold: threshold.trim() && Number.isFinite(Number(threshold)) && Number(threshold) >= 0 && Number(threshold) <= 1 ? Number(threshold) : 0.7,
    customEndpoint: customEndpoint || "",
    customHeaders: parsedHeaders,
    language: language || "en",
    maxOutputTokens: maxOutputTokens ? Number(maxOutputTokens) : 4096,
    timeoutSeconds: timeoutSeconds ? Number(timeoutSeconds) : Number(process.env.AEGIFY_LLM_REQUEST_TIMEOUT_MS || 60_000) / 1000,
    chatTokenParameter: chatTokenParameter || "max_tokens",
  };
}

export async function getSlackConfig(db = prisma) {
  const [webhookUrl, enabled, channel, severity] = await Promise.all([
    getSetting("slack.webhook_url", db),
    getSetting("slack.enabled", db),
    getSetting("slack.channel", db),
    getSetting("slack.notify_severity", db),
  ]);

  return {
    webhookUrl,
    enabled: enabled === "true",
    channel: channel || "#security-alerts",
    notifySeverity: severity || "high",
  };
}

export async function getJiraConfig() {
  const [baseUrl, email, apiToken, projectKey, issueType, enabled] = await Promise.all([
    getSetting("jira.base_url"),
    getSetting("jira.email"),
    getSetting("jira.api_token"),
    getSetting("jira.project_key"),
    getSetting("jira.issue_type"),
    getSetting("jira.enabled"),
  ]);
  return {
    baseUrl: baseUrl.replace(/\/+$/, ""),
    email,
    apiToken,
    projectKey,
    issueType: issueType || "Bug",
    enabled: enabled === "true",
  };
}
