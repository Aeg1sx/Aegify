import { requireAccess } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { encrypt, decrypt } from "@/lib/crypto";
import { validateEndpointUrl, validateCustomHeaders, validateJiraBaseUrl, validateSlackWebhookUrl } from "@/lib/url-validator";
import { ALLOWED_SETTINGS, SECRET_SETTINGS, SETTING_DEFAULTS, publicSetting, settingTypeError } from "@/lib/settings-contract";
import { dashboardAuthConfigured } from "@/lib/security-config";
import { providerProtocol, providerUrl } from "@/lib/provider-catalog";
import { accessPolicyConfigured, authOrigin, localAuthEnabled, mailConfigured } from "@/lib/auth-policy";

export async function GET(request: Request) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  const settings = await prisma.setting.findMany();
  const result: Record<string, ReturnType<typeof publicSetting>> = {};
  for (const item of settings) {
    if (!ALLOWED_SETTINGS.has(item.key)) continue;
    let value = item.value;
    let unreadable = false;
    if (item.encrypted && SECRET_SETTINGS.has(item.key)) {
      try { value = decrypt(item.value); }
      catch { value = ""; unreadable = Boolean(item.value); }
    }
    result[item.key] = publicSetting(item.key, value, item.encrypted, unreadable);
  }
  return NextResponse.json({ settings: result, security: {
    encryptionConfigured: Boolean(process.env.ENCRYPTION_SECRET),
    authenticationConfigured: dashboardAuthConfigured(process.env),
    accessPolicyConfigured: accessPolicyConfigured(process.env),
    localAuthentication: localAuthEnabled(process.env),
    emailConfigured: mailConfigured(process.env),
    authOrigin: authOrigin(process.env),
    production: process.env.NODE_ENV === "production",
  } }, { headers: { "Cache-Control": "no-store" } });
}

function validateValue(key: string, value: unknown): string | null {
  const typeError = settingTypeError(key, value);
  if (typeError || typeof value !== "string") return typeError || "Expected a string";
  if (key === "llm.custom_endpoint" && value) {
    const invalid = validateEndpointUrl(value).error;
    if (invalid) return invalid;
    const url = new URL(value);
    return url.search || url.hash ? "Provider endpoints cannot contain query strings or fragments. Put credentials in custom headers." : null;
  }
  if (key === "slack.webhook_url" && value) return validateSlackWebhookUrl(value).error || null;
  if (key === "jira.base_url" && value) return validateJiraBaseUrl(value).error || null;
  if (key === "llm.custom_headers" && value) {
    try {
      const headers: unknown = JSON.parse(value);
      if (!headers || typeof headers !== "object" || Array.isArray(headers)) return "Headers must be a JSON object.";
      const entries = Object.entries(headers);
      if (entries.length > 20) return "At most 20 custom headers are allowed.";
      if (entries.some(([name, val]) => typeof val !== "string" || !/^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$/.test(name))) return "Headers require valid names and string values.";
      if (new Set(entries.map(([name]) => name.toLowerCase())).size !== entries.length) return "Duplicate header names are not allowed.";
      return validateCustomHeaders(headers as Record<string, string>).error || null;
    } catch { return "Headers must be valid JSON."; }
  }
  return null;
}

async function updateSettings(request: NextRequest, single: boolean) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 }); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return NextResponse.json({ error: "Expected a JSON object." }, { status: 400 });
  const record = body as Record<string, unknown>;
  const updates = single && typeof record.key === "string" ? { [record.key]: record.value } : single ? null : record.settings;
  if (!updates || typeof updates !== "object" || Array.isArray(updates)) return NextResponse.json({ error: "A settings object is required." }, { status: 400 });
  const entries = Object.entries(updates);
  if (!entries.length || entries.length > ALLOWED_SETTINGS.size) return NextResponse.json({ error: "Provide a non-empty, bounded settings update." }, { status: 400 });
  const fields = Object.fromEntries(entries.map(([key, value]) => [key, validateValue(key, value)]).filter(([, error]) => error));
  if (Object.keys(fields).length) return NextResponse.json({ error: "Review the highlighted settings.", fields }, { status: 422 });
  if (entries.some(([key, value]) => SECRET_SETTINGS.has(key) && value) && !process.env.ENCRYPTION_SECRET) {
    return NextResponse.json({ error: "Configure ENCRYPTION_SECRET on the server before storing credentials or custom headers." }, { status: 503 });
  }
  const prepared = entries.map(([key, raw]) => {
    const value = raw as string;
    const encrypted = SECRET_SETTINGS.has(key);
    return { key, value: encrypted && value ? encrypt(value) : value, encrypted };
  });
  const error = await prisma.$transaction(async (tx) => {
    const current = await tx.setting.findMany();
    const effective = { ...SETTING_DEFAULTS, ...Object.fromEntries(current.map((item) => [item.key, item.value])), ...updates } as Record<string, string>;
    const currentValues = { ...SETTING_DEFAULTS, ...Object.fromEntries(current.map((item) => [item.key, item.value])) };
    if (currentValues["llm.custom_headers"] && !Object.hasOwn(updates, "llm.custom_headers") && (effective["llm.custom_endpoint"] !== currentValues["llm.custom_endpoint"] || effective["llm.provider"] !== currentValues["llm.provider"])) return "When changing endpoint or protocol, explicitly replace or remove stored custom headers to prevent credential forwarding to a different service.";
    if (entries.some(([key]) => key.startsWith("llm.")) && effective["llm.enabled"] === "true") {
      if (!providerProtocol(effective["llm.provider"])) return "Choose a supported AI provider before enabling review.";
      if (!effective["llm.model"]?.trim()) return "A provider model ID is required before enabling AI review.";
      try { providerUrl(effective["llm.provider"], effective["llm.custom_endpoint"], effective["llm.model"]); } catch (error) { return error instanceof Error ? error.message : "Invalid provider configuration."; }
    }
    for (const item of prepared) await tx.setting.upsert({ where: { key: item.key }, create: item, update: { value: item.value, encrypted: item.encrypted } });
    await tx.auditEvent.create({ data: { actorId: access.userId || "development", action: "workspace.settings.update", targetId: "settings", details: JSON.stringify({ keys: entries.map(([key]) => key) }) } });
    return null;
  });
  if (error) return NextResponse.json({ error }, { status: 422 });
  return NextResponse.json({ success: true });
}
export async function PUT(request: NextRequest) { return updateSettings(request, true); }
export async function PATCH(request: NextRequest) { return updateSettings(request, false); }
