import { createHash, createHmac, randomBytes } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import { authOrigin, emailAllowed, mailConfigured, normalizeEmail, normalizeUsername, passwordError, type AuthEnvironment } from "./auth-policy.ts";
import { hashPassword, verifyPassword } from "./password.ts";

export type MailPurpose = "activate" | "reset";
export interface AuthMail { to: string; url: string; purpose: MailPurpose; idempotencyKey: string }
export type SendAuthMail = (message: AuthMail) => Promise<void>;
export function tokenHash(token: string): string { return createHash("sha256").update(token).digest("hex"); }
const TOKEN_TTL_MS = 30 * 60_000;

export function createLocalAuthService(db: PrismaClient, environment: AuthEnvironment, send: SendAuthMail) {
  return {
    async requestEmail(rawEmail: unknown, purpose: MailPurpose) {
      const email = normalizeEmail(rawEmail);
      if (!email || !emailAllowed(email, environment)) return;
      const user = await db.user.findUnique({ where: { email } });
      // Activation never pre-creates an account or overwrites an SSO identity.
      if (purpose === "activate" ? Boolean(user) : !user?.passwordHash || !user.emailVerified || user.disabled) return;
      const token = randomBytes(32).toString("base64url");
      const digest = tokenHash(token);
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);
      await db.authActionToken.deleteMany({ where: { expiresAt: { lt: new Date() } } });
      await db.authActionToken.upsert({ where: { identifier_purpose: { identifier: email, purpose } }, create: { identifier: email, purpose, tokenHash: digest, expiresAt }, update: { tokenHash: digest, expiresAt, createdAt: new Date() } });
      const origin = authOrigin(environment);
      if (!origin) throw new Error("Authentication origin is not configured.");
      // Fragments are not sent in request URLs, access logs, or Referer headers.
      try { await send({ to: email, purpose, url: origin + "/auth/" + (purpose === "activate" ? "activate" : "reset-password") + "#token=" + token, idempotencyKey: "auth-" + digest }); }
      catch {
        await db.authActionToken.deleteMany({ where: { tokenHash: digest } });
        // Same public response as an unknown account. Do not log addresses, tokens, or provider bodies.
        console.error("Authentication email delivery failed; check mail provider configuration.");
      }
    },
    async complete(rawToken: unknown, purpose: MailPurpose, password: unknown, rawUsername?: unknown) {
      if (typeof rawToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(rawToken)) return false;
      const username = purpose === "activate" ? normalizeUsername(rawUsername) : null;
      if (passwordError(password) || (purpose === "activate" && !username)) return false;
      const digest = tokenHash(rawToken);
      const token = await db.authActionToken.findUnique({ where: { tokenHash: digest } });
      if (!token || token.purpose !== purpose || token.expiresAt <= new Date() || !emailAllowed(token.identifier, environment)) return false;
      const passwordHash = await hashPassword(password as string);
      try {
        return await db.$transaction(async (tx) => {
          const consumed = await tx.authActionToken.deleteMany({ where: { tokenHash: digest, purpose, expiresAt: { gt: new Date() } } });
          if (consumed.count !== 1) return false;
          if (purpose === "activate") {
            await tx.user.create({ data: { email: token.identifier, username, name: username, passwordHash, emailVerified: new Date() } });
          } else {
            const changed = await tx.user.updateMany({ where: { email: token.identifier, passwordHash: { not: null }, emailVerified: { not: null }, disabled: false }, data: { passwordHash, sessionVersion: { increment: 1 } } });
            if (changed.count !== 1) throw new Error("Account unavailable");
          }
          return true;
        });
      } catch { return false; } // Conflict rolls back consumption; no account identity is disclosed.
    },
    async authenticate(identifier: unknown, password: unknown) {
      const email = normalizeEmail(identifier);
      const username = normalizeUsername(identifier);
      const user = email ? await db.user.findUnique({ where: { email } }) : username ? await db.user.findUnique({ where: { username } }) : null;
      const valid = await verifyPassword(password, user?.passwordHash);
      if (!valid || !user || user.disabled || !user.emailVerified || !emailAllowed(user.email, environment)) return null;
      return { id: user.id, email: user.email, name: user.name, image: user.image };
    },
  };
}

/** Durable fixed-window counters; atomically increments across workers/restarts. */
export async function consumeAuthLimit(db: PrismaClient, environment: AuthEnvironment, scope: string, identity: string, maximum: number, windowMs: number, now = Date.now()): Promise<boolean> {
  if (!environment.AUTH_SECRET) return false;
  const window = Math.floor(now / windowMs);
  const key = createHmac("sha256", environment.AUTH_SECRET).update(scope + ":" + window + ":" + identity.slice(0, 512)).digest("hex");
  const record = await db.authRateLimit.upsert({ where: { key }, create: { key, count: 1, expiresAt: new Date((window + 1) * windowMs) }, update: { count: { increment: 1 } } });
  return record.count <= maximum;
}
export function authClientKey(request: Request, environment: AuthEnvironment): string {
  // Forwarded addresses are untrusted unless the deployment explicitly owns and sanitizes that header.
  return environment.AUTH_TRUST_PROXY === "true" ? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim().slice(0, 128) || "shared" : "shared";
}
export async function limitAuthRequest(db: PrismaClient, environment: AuthEnvironment, request: Request, action: string, identity: string): Promise<boolean> {
  const global = await consumeAuthLimit(db, environment, "global", "workspace", 1000, 3_600_000);
  if (!global) return false;
  await db.authRateLimit.deleteMany({ where: { expiresAt: { lt: new Date() } } });
  const client = await consumeAuthLimit(db, environment, action + ":client", authClientKey(request, environment), 100, 900_000);
  if (!client) return false;
  return consumeAuthLimit(db, environment, action + ":identity", identity.trim().toLowerCase(), action === "email" ? 3 : 10, action === "email" ? 3_600_000 : 900_000);
}

export function resendAuthMailer(environment: AuthEnvironment, transport: typeof fetch = fetch): SendAuthMail {
  return async (message) => {
    if (!mailConfigured(environment)) throw new Error("Authentication email is not configured.");
    const activate = message.purpose === "activate";
    const response = await transport("https://api.resend.com/emails", {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(10_000),
      headers: { Authorization: "Bearer " + environment.RESEND_API_KEY, "Content-Type": "application/json", "Idempotency-Key": message.idempotencyKey },
      body: JSON.stringify({ from: environment.AUTH_EMAIL_FROM, to: [message.to], subject: activate ? "Verify your email for Aegify" : "Reset your Aegify password", text: (activate ? "Verify your email and create your Aegify account" : "Reset your Aegify password") + ":\n\n" + message.url + "\n\nThis link expires in 30 minutes and can be used once. If you did not request this, ignore this email." }),
    });
    await response.body?.cancel();
    if (!response.ok) throw new Error("Authentication email delivery failed.");
  };
}
