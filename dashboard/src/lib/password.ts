import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { passwordError } from "./auth-policy.ts";

// OWASP's 32 MiB scrypt profile; bounded cost is not supplied by the stored hash.
const PROFILE = "scrypt-v1";
const OPTIONS = { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 };
function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password, salt, 64, OPTIONS, (error, key) => error ? reject(error) : resolve(key)));
}
export async function hashPassword(password: string): Promise<string> {
  const error = passwordError(password);
  if (error) throw new Error(error);
  const salt = randomBytes(16);
  return [PROFILE, salt.toString("hex"), (await derive(password, salt)).toString("hex")].join("$");
}
export async function verifyPassword(password: unknown, stored: string | null | undefined): Promise<boolean> {
  if (typeof password !== "string" || password.length > 128) return false;
  const parts = stored?.split("$") || [];
  const valid = parts[0] === PROFILE && parts.length === 3 && /^[a-f0-9]{32}$/.test(parts[1]) && /^[a-f0-9]{128}$/.test(parts[2]);
  // Missing, SSO-only, and malformed accounts pay the same KDF cost.
  const actual = await derive(password, valid ? Buffer.from(parts[1], "hex") : Buffer.alloc(16));
  const expected = valid ? Buffer.from(parts[2], "hex") : Buffer.alloc(64);
  return timingSafeEqual(actual, expected) && valid;
}
