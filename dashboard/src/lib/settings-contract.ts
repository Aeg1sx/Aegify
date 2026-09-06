import { providerProtocol } from "./provider-catalog.ts";

export const SECRET_SETTINGS = new Set([
  "llm.anthropic_api_key", "llm.openai_api_key", "llm.google_api_key", "llm.custom_headers",
  "slack.webhook_url", "jira.api_token", "jira.email",
]);
export const SETTING_DEFAULTS: Record<string, string> = {
  "llm.provider": "anthropic", "llm.model": "", "llm.enabled": "false", "llm.auto_verify": "false",
  "llm.verify_threshold": "0.7", "llm.custom_endpoint": "", "llm.language": "en",
  "llm.max_output_tokens": "4096", "llm.timeout_seconds": "60", "llm.chat_token_parameter": "max_tokens",
  "slack.enabled": "false", "slack.channel": "#security-alerts", "slack.notify_severity": "high",
  "jira.base_url": "", "jira.project_key": "", "jira.issue_type": "Bug", "jira.enabled": "false",
};
export const ALLOWED_SETTINGS = new Set([...Object.keys(SETTING_DEFAULTS), ...SECRET_SETTINGS]);
export interface SettingView { value: string; masked?: string; encrypted?: boolean; unreadable?: boolean }
export type SettingsView = Record<string, SettingView>;
export function settingsDraft(settings: SettingsView): Record<string, string> {
  return Object.fromEntries([...ALLOWED_SETTINGS].map((key) => [key, SECRET_SETTINGS.has(key) ? "" : settings[key]?.value ?? SETTING_DEFAULTS[key] ?? ""]));
}
export function settingsChanges(draft: Record<string, string>, saved: SettingsView, removed: ReadonlySet<string>, section: string): Record<string, string> {
  const defaults = settingsDraft(saved);
  return Object.fromEntries([...ALLOWED_SETTINGS].filter((key) => key.startsWith(section + ".")).flatMap((key) => {
    if (SECRET_SETTINGS.has(key)) {
      if (removed.has(key)) return [[key, ""]];
      return draft[key] ? [[key, draft[key]]] : [];
    }
    return draft[key] !== defaults[key] ? [[key, draft[key]]] : [];
  }));
}
export function settingTypeError(key: string, value: unknown): string | null {
  if (!ALLOWED_SETTINGS.has(key)) return "Unknown setting key.";
  if (typeof value !== "string") return "Setting values must be strings.";
  if (value.length > (SECRET_SETTINGS.has(key) ? 32_768 : 2048)) return "Setting value exceeds the size limit.";
  if (["llm.enabled", "llm.auto_verify", "slack.enabled", "jira.enabled"].includes(key) && !["true", "false"].includes(value)) return "Expected true or false.";
  if (key === "llm.provider" && !providerProtocol(value)) return "Choose Anthropic, OpenAI Chat, OpenAI Responses, or Google Gemini.";
  if (key === "llm.max_output_tokens" && (!/^\d+$/.test(value) || Number(value) < 128 || Number(value) > 32768)) return "Output token limit must be between 128 and 32768.";
  if (key === "llm.timeout_seconds" && (!/^\d+$/.test(value) || Number(value) < 5 || Number(value) > 300)) return "Timeout must be between 5 and 300 seconds.";
  if (key === "llm.chat_token_parameter" && !["max_tokens", "max_completion_tokens"].includes(value)) return "Choose a supported Chat Completions token parameter.";
  if (key === "llm.verify_threshold" && (!value.trim() || !Number.isFinite(Number(value)) || Number(value) < 0 || Number(value) > 1)) return "Threshold must be a number between 0 and 1.";
  if (key === "llm.language" && !["en", "ko", "ja", "zh", "es", "de", "fr", "pt"].includes(value)) return "Unsupported report language.";
  if (key === "slack.notify_severity" && !["critical", "high", "medium", "low"].includes(value)) return "Choose a valid severity threshold.";
  if (key === "llm.model" && value && !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/.test(value)) return "Use a valid provider model identifier.";
  if (key === "jira.project_key" && value && !/^[A-Z][A-Z0-9_]{1,19}$/.test(value)) return "Use an uppercase Jira project key.";
  if (key === "jira.email" && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "Enter a valid Jira account email.";
  if (key === "jira.issue_type" && !value.trim()) return "Issue type is required.";
  return null;
}

/** Never serialize secret values back to a settings client, including legacy header JSON. */
export function publicSetting(key: string, value: string, encrypted: boolean, unreadable = false): SettingView {
  if (!SECRET_SETTINGS.has(key)) return { value };
  return { value: value ? "configured" : "", masked: value ? "••••••••" : "", encrypted, unreadable };
}
