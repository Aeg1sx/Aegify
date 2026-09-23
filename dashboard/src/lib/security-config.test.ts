import assert from "node:assert/strict";
import test from "node:test";

import {
  anonymousUploadAllowed,
  assertProductionSecurity,
  dashboardAuthConfigured,
  productionSecurityErrors,
} from "./security-config.ts";

const secureProduction = {
  NODE_ENV: "production",
  AUTH_SECRET: "independent-auth-secret-at-least-32-characters",
  ENCRYPTION_SECRET: "independent-encryption-secret",
  AUTH_URL: "https://aegify.example",
  AUTH_GITHUB_ID: "client-id",
  AUTH_GITHUB_SECRET: "client-secret",
  AUTH_ALLOWED_EMAILS: "owner@example.test",
  AUTH_ADMIN_EMAILS: "owner@example.test",
};

test("production configuration requires auth, encryption, and an explicit access policy", () => {
  assert.deepEqual(productionSecurityErrors({ NODE_ENV: "production" }), [
    "AUTH_SECRET is required",
    "ENCRYPTION_SECRET is required",
    "at least one complete authentication method is required",
    "AUTH_URL is required",
    "AUTH_ALLOWED_EMAILS or AUTH_ALLOWED_DOMAINS is required",
    "AUTH_ADMIN_EMAILS must name at least one exact administrator email",
  ]);
  assert.doesNotThrow(() => assertProductionSecurity(secureProduction));
  assert.deepEqual(
    productionSecurityErrors({ ...secureProduction, AUTH_URL: "https://user@example.com/path" }),
    ["AUTH_URL must be an HTTP(S) origin without credentials or a path"],
  );
});

test("Google, Okta, and local authentication require complete configurations", () => {
  assert.equal(dashboardAuthConfigured({ AUTH_SECRET: "secret", AUTH_GOOGLE_ID: "id", AUTH_GOOGLE_SECRET: "secret" }), true);
  assert.equal(dashboardAuthConfigured({ AUTH_SECRET: "secret", AUTH_OKTA_ID: "id", AUTH_OKTA_SECRET: "secret" }), false);
  assert.equal(dashboardAuthConfigured({ AUTH_SECRET: "secret", AUTH_OKTA_ID: "id", AUTH_OKTA_SECRET: "secret", AUTH_OKTA_ISSUER: "https://tenant.okta.com/oauth2/default" }), true);
  assert.equal(dashboardAuthConfigured({ AUTH_SECRET: "secret", AUTH_LOCAL_ENABLED: "true" }), true);
  assert.ok(productionSecurityErrors({ ...secureProduction, AUTH_LOCAL_ENABLED: "true" }).some((error) => error.includes("RESEND_API_KEY")));
  assert.ok(productionSecurityErrors({ ...secureProduction, AUTH_URL: "http://public.example" }).some((error) => error.includes("HTTPS")));
});

test("partial OAuth credentials do not enable authentication", () => {
  assert.equal(
    dashboardAuthConfigured({
      AUTH_SECRET: "secret",
      AUTH_GITHUB_ID: "client-id",
    }),
    false,
  );
});

test("administrator bootstrap and legacy CI bindings fail closed", () => {
  assert.ok(productionSecurityErrors({ ...secureProduction, AUTH_ADMIN_EMAILS: "outsider@example.test" }).some((error) => error.includes("sign-in allowlist")));
  assert.ok(productionSecurityErrors({ ...secureProduction, AUTH_ADMIN_EMAILS: "@example.test" }).some((error) => error.includes("exact administrator")));
  assert.ok(productionSecurityErrors({ ...secureProduction, AEGIFY_UPLOAD_TOKEN: "synthetic" }).some((error) => error.includes("AEGIFY_UPLOAD_PROJECT_ID")));
  assert.ok(productionSecurityErrors({ ...secureProduction, AEGIFY_UPLOAD_PROJECT_ID: "project" }).some((error) => error.includes("AEGIFY_UPLOAD_TOKEN")));
});

test("anonymous uploads are limited to zero-configuration development", () => {
  assert.equal(anonymousUploadAllowed({ NODE_ENV: "development" }), true);
  assert.equal(anonymousUploadAllowed({ NODE_ENV: "production" }), false);
  assert.equal(
    anonymousUploadAllowed({
      NODE_ENV: "development",
      AEGIFY_UPLOAD_TOKEN: "configured",
    }),
    false,
  );
});
