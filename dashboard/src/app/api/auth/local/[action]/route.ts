import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { createLocalAuthService, limitAuthRequest, resendAuthMailer } from "@/lib/local-auth";
import { localAuthEnabled, mailConfigured, normalizeEmail, passwordError } from "@/lib/auth-policy";
import { readAuthBody, sameAuthOrigin } from "@/lib/auth-request";

const GENERIC = "If this email is eligible, a one-time link will arrive shortly. Check your inbox and spam folder.";
function reply(data: Record<string, unknown>, status = 200) { return NextResponse.json(data, { status, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } }); }
export async function POST(request: NextRequest, { params }: { params: Promise<{ action: string }> }) {
  const { action } = await params;
  if (!["request-access", "activate", "forgot-password", "reset-password"].includes(action)) return reply({ error: "Not found." }, 404);
  if (!localAuthEnabled(process.env)) return reply({ error: "Password authentication is not configured." }, 503);
  if (!sameAuthOrigin(request, process.env)) return reply({ error: "Request origin is not allowed." }, 403);
  const body = await readAuthBody(request);
  if (!body) return reply({ error: "A bounded JSON request is required." }, 400);
  const emailing = action === "request-access" || action === "forgot-password";
  const email = normalizeEmail(body.email);
  if (emailing && !email) return reply({ error: "Enter a valid email address." }, 400);
  try {
    if (!await limitAuthRequest(prisma, process.env, request, emailing ? "email" : "complete", emailing ? email! : String(body.token || "").slice(0, 100))) return reply({ error: "Too many requests. Please try again later." }, 429);
    const service = createLocalAuthService(prisma, process.env, resendAuthMailer(process.env));
    if (emailing) {
      if (!mailConfigured(process.env)) return reply({ error: "Email delivery is not configured. Contact the workspace owner." }, 503);
      await service.requestEmail(email, action === "request-access" ? "activate" : "reset");
      return reply({ message: GENERIC }, 202);
    }
    const invalidPassword = passwordError(body.password);
    if (invalidPassword) return reply({ error: invalidPassword }, 400);
    const success = await service.complete(body.token, action === "activate" ? "activate" : "reset", body.password, body.username);
    return success ? reply({ success: true, message: action === "activate" ? "Email verified and account created. You can now sign in." : "Password updated. All existing sessions have been invalidated. Sign in again." }) : reply({ error: "This link is invalid, expired, or already used, or the username is unavailable. Request a new link or choose another username." }, 400);
  } catch { return reply({ error: "Authentication service is temporarily unavailable." }, 503); }
}
