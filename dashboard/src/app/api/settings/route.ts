import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { encrypt, decrypt, maskApiKey } from "@/lib/crypto";
import {
  validateEndpointUrl,
  validateCustomHeaders,
} from "@/lib/url-validator";

// Keys that should be encrypted
const ENCRYPTED_KEYS = new Set([
  "llm.anthropic_api_key",
  "llm.openai_api_key",
  "llm.google_api_key",
  "slack.webhook_url",
]);

// Keys that should be masked in GET responses
const MASKED_KEYS = new Set([
  "llm.anthropic_api_key",
  "llm.openai_api_key",
  "llm.google_api_key",
  "slack.webhook_url",
]);

// Keys that contain URLs requiring SSRF validation
const URL_KEYS = new Set([
  "llm.custom_endpoint",
]);

// Keys that contain JSON headers requiring validation
const HEADER_KEYS = new Set([
  "llm.custom_headers",
]);

// All allowed setting keys
const ALLOWED_KEYS = new Set([
  "llm.provider",
  "llm.model",
  "llm.anthropic_api_key",
  "llm.openai_api_key",
  "llm.google_api_key",
  "llm.enabled",
  "llm.auto_verify",
  "llm.verify_threshold",
  "llm.custom_endpoint",
  "llm.custom_headers",
  "llm.language",
  "slack.webhook_url",
  "slack.enabled",
  "slack.channel",
  "slack.notify_severity",
]);

export async function GET() {
  const settings = await prisma.setting.findMany();

  const result: Record<string, { value: string; masked?: string }> = {};
  for (const s of settings) {
    if (MASKED_KEYS.has(s.key)) {
      let rawValue = s.value;
      if (s.encrypted) {
        try {
          rawValue = decrypt(s.value);
        } catch {
          rawValue = "";
        }
      }
      result[s.key] = {
        value: rawValue ? "configured" : "",
        masked: rawValue ? maskApiKey(rawValue) : "",
      };
    } else {
      result[s.key] = { value: s.value };
    }
  }

  return NextResponse.json({ settings: result });
}

function validateSettingValue(
  key: string,
  value: string
): { valid: boolean; error?: string } {
  // Validate URL keys against SSRF
  if (URL_KEYS.has(key) && value) {
    return validateEndpointUrl(value);
  }

  // Validate header keys
  if (HEADER_KEYS.has(key) && value) {
    try {
      const headers = JSON.parse(value);
      if (typeof headers !== "object" || Array.isArray(headers)) {
        return { valid: false, error: "Headers must be a JSON object" };
      }
      return validateCustomHeaders(headers);
    } catch {
      return { valid: false, error: "Invalid JSON format for headers" };
    }
  }

  return { valid: true };
}

export async function PUT(request: NextRequest) {
  const body = await request.json();
  const { key, value } = body;

  if (!key || typeof key !== "string") {
    return NextResponse.json({ error: "key is required" }, { status: 400 });
  }

  if (!ALLOWED_KEYS.has(key)) {
    return NextResponse.json(
      { error: `Invalid setting key: ${key}` },
      { status: 400 }
    );
  }

  // Validate value
  const validation = validateSettingValue(key, value || "");
  if (!validation.valid) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const shouldEncrypt = ENCRYPTED_KEYS.has(key);
  const storedValue =
    shouldEncrypt && value ? encrypt(value) : value || "";

  await prisma.setting.upsert({
    where: { key },
    create: { key, value: storedValue, encrypted: shouldEncrypt },
    update: { value: storedValue, encrypted: shouldEncrypt },
  });

  return NextResponse.json({ success: true });
}

// Bulk update
export async function PATCH(request: NextRequest) {
  const body = await request.json();
  const { settings } = body;

  if (!settings || typeof settings !== "object") {
    return NextResponse.json(
      { error: "settings object required" },
      { status: 400 }
    );
  }

  // Validate all values first before persisting any
  for (const [key, value] of Object.entries(settings)) {
    if (!ALLOWED_KEYS.has(key)) {
      return NextResponse.json(
        { error: `Invalid setting key: ${key}` },
        { status: 400 }
      );
    }
    const validation = validateSettingValue(key, (value as string) || "");
    if (!validation.valid) {
      return NextResponse.json(
        { error: `${key}: ${validation.error}` },
        { status: 400 }
      );
    }
  }

  for (const [key, value] of Object.entries(settings)) {
    const shouldEncrypt = ENCRYPTED_KEYS.has(key);
    const storedValue =
      shouldEncrypt && value
        ? encrypt(value as string)
        : (value as string) || "";

    await prisma.setting.upsert({
      where: { key },
      create: { key, value: storedValue, encrypted: shouldEncrypt },
      update: { value: storedValue, encrypted: shouldEncrypt },
    });
  }

  return NextResponse.json({ success: true });
}
