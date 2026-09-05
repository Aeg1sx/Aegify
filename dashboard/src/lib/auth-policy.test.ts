import assert from "node:assert/strict";
import test from "node:test";
import { authOrigin, emailAllowed, normalizeEmail, normalizeUsername, passwordError, safeAuthReturn, validOktaIssuer } from "./auth-policy.ts";
import { hashPassword, verifyPassword } from "./password.ts";
import { readAuthBody, sameAuthOrigin } from "./auth-request.ts";

test("workspace access is deny-by-default and uses exact normalized email/domain matches", () => {
  assert.equal(emailAllowed("owner@example.test", {}), false);
  const policy = { AUTH_ALLOWED_EMAILS: " Owner@Example.test ", AUTH_ALLOWED_DOMAINS: "staff.example.test" };
  assert.equal(emailAllowed("OWNER@example.test", policy), true);
  assert.equal(emailAllowed("someone@staff.example.test", policy), true);
  assert.equal(emailAllowed("owner@sub.example.test", policy), false);
  assert.equal(emailAllowed("someone@staff.example.test.invalid", policy), false);
  assert.equal(normalizeEmail("a@b\r\n.test"), null);
  assert.equal(normalizeUsername(" Owner_1 "), "owner_1");
  assert.equal(normalizeUsername("a@b.test"), null);
});

test("authentication origins and post-login return paths stay bounded", () => {
  assert.equal(authOrigin({ AUTH_URL: "https://aegify.example" }), "https://aegify.example");
  assert.equal(authOrigin({ AUTH_URL: "http://127.0.0.1:3038" }), "http://127.0.0.1:3038");
  for (const value of ["http://public.example", "https://user:pass@example.test", "https://example.test/path", "https://example.test?key=value"]) assert.equal(authOrigin({ AUTH_URL: value }), null);
  for (const value of ["https://other.example", "//other.example", "/\\other.example", "/auth/signin", "/api/auth/session", "/\nexample"]) assert.equal(safeAuthReturn(value), "/");
  assert.equal(safeAuthReturn("/findings?severity=high"), "/findings?severity=high");
  assert.equal(validOktaIssuer("https://tenant.okta.com/oauth2/default"), true);
  assert.equal(validOktaIssuer("http://tenant.okta.com"), false);
});

test("password hashing is salted, bounded, and timing-safe across missing accounts", async () => {
  const password = "A unique test passphrase 2026!";
  const first = await hashPassword(password); const second = await hashPassword(password);
  assert.notEqual(first, second); assert.ok(!first.includes(password));
  assert.equal(await verifyPassword(password, first), true);
  assert.equal(await verifyPassword("wrong passphrase", first), false);
  assert.equal(await verifyPassword(password, null), false);
  assert.equal(await verifyPassword(password, "scrypt-v1$broken$broken"), false);
  assert.ok(passwordError("too short")); assert.ok(passwordError("x".repeat(129)));
  assert.equal(passwordError("a very long and unique passphrase"), null);
});

test("local auth mutations require same origin and bounded JSON bodies", async () => {
  const env = { AUTH_URL: "https://aegify.example" };
  assert.equal(sameAuthOrigin(new Request("https://aegify.example", { headers: { Origin: "https://aegify.example" } }), env), true);
  assert.equal(sameAuthOrigin(new Request("https://aegify.example", { headers: { Origin: "https://other.example" } }), env), false);
  const request = (body: string) => new Request("https://aegify.example", { method: "POST", headers: { "Content-Type": "application/json" }, body });
  assert.deepEqual(await readAuthBody(request('{"email":"owner@example.test"}')), { email: "owner@example.test" });
  assert.equal(await readAuthBody(request("[]")), null);
  assert.equal(await readAuthBody(request("x".repeat(9000))), null);
});
