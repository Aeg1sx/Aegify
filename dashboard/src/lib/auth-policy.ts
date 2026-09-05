export type AuthEnvironment = Record<string, string | undefined>;
export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(email) ? email : null;
}
export function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const username = value.trim().toLowerCase();
  return /^[a-z][a-z0-9._-]{2,31}$/.test(username) ? username : null;
}
export function emailAllowed(email: unknown, environment: AuthEnvironment): boolean {
  const normalized = normalizeEmail(email);
  if (!normalized) return false;
  const emails = (environment.AUTH_ALLOWED_EMAILS || "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  const domains = (environment.AUTH_ALLOWED_DOMAINS || "").split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  return emails.includes(normalized) || domains.includes(normalized.split("@")[1]);
}
export function accessPolicyConfigured(environment: AuthEnvironment): boolean {
  return Boolean((environment.AUTH_ALLOWED_EMAILS || "").split(",").some((email) => normalizeEmail(email)) || (environment.AUTH_ALLOWED_DOMAINS || "").split(",").some((domain) => normalizeEmail("policy@" + domain.trim())));
}
export function passwordError(value: unknown): string | null {
  if (typeof value !== "string" || [...value].length < 15 || value.length > 128) return "Use a passphrase between 15 and 128 characters.";
  if (/^(.)\1+$/.test(value) || ["passwordpassword", "123456789012345", "qwertyuiopasdfgh", "letmeinletmeinletmein"].includes(value.toLowerCase())) return "Choose a less predictable passphrase.";
  return null;
}
export function safeAuthReturn(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\\\x00-\x20]/.test(value)) return "/";
  try { const url = new URL(value, "https://workspace.invalid"); return url.origin === "https://workspace.invalid" && !url.pathname.startsWith("/auth") && !url.pathname.startsWith("/api/") ? url.pathname + url.search + url.hash : "/"; }
  catch { return "/"; }
}
export function authOrigin(environment: AuthEnvironment): string | null {
  try {
    const url = new URL(environment.AUTH_URL || "");
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    return !url.username && !url.password && !url.search && !url.hash && url.pathname === "/" && (url.protocol === "https:" || (url.protocol === "http:" && loopback)) ? url.origin : null;
  } catch { return null; }
}
export function localAuthEnabled(environment: AuthEnvironment): boolean { return environment.AUTH_LOCAL_ENABLED === "true" && Boolean(environment.AUTH_SECRET); }
export function mailConfigured(environment: AuthEnvironment): boolean { return Boolean(environment.RESEND_API_KEY && normalizeEmail(environment.AUTH_EMAIL_FROM) && authOrigin(environment)); }
export function validOktaIssuer(value: string | undefined): boolean {
  try { const url = new URL(value || ""); return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && Boolean(url.hostname.includes(".")); }
  catch { return false; }
}
