import { prisma } from "@/lib/prisma";
import { decrypt } from "@/lib/crypto";

export async function getSetting(key: string): Promise<string> {
  const setting = await prisma.setting.findUnique({ where: { key } });
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

export async function getLLMConfig() {
  const [
    provider, model, anthropicKey, openaiKey, googleKey,
    enabled, autoVerify, threshold,
    customEndpoint, customHeaders, language, maxOutputTokens, timeoutSeconds, chatTokenParameter,
  ] = await Promise.all([
    getSetting("llm.provider"),
    getSetting("llm.model"),
    getSetting("llm.anthropic_api_key"),
    getSetting("llm.openai_api_key"),
    getSetting("llm.google_api_key"),
    getSetting("llm.enabled"),
    getSetting("llm.auto_verify"),
    getSetting("llm.verify_threshold"),
    getSetting("llm.custom_endpoint"),
    getSetting("llm.custom_headers"),
    getSetting("llm.language"),
    getSetting("llm.max_output_tokens"),
    getSetting("llm.timeout_seconds"),
    getSetting("llm.chat_token_parameter"),
  ]);

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

export async function getSlackConfig() {
  const [webhookUrl, enabled, channel, severity] = await Promise.all([
    getSetting("slack.webhook_url"),
    getSetting("slack.enabled"),
    getSetting("slack.channel"),
    getSetting("slack.notify_severity"),
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
