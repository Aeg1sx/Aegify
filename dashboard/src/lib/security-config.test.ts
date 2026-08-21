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
  AUTH_SECRET: "independent-auth-secret",
  ENCRYPTION_SECRET: "independent-encryption-secret",
  AUTH_URL: "https://aegify.example",
  AUTH_GITHUB_ID: "client-id",
  AUTH_GITHUB_SECRET: "client-secret",
};

test("production configuration requires auth, encryption, and an OAuth provider", () => {
  assert.deepEqual(productionSecurityErrors({ NODE_ENV: "production" }), [
    "AUTH_SECRET is required",
    "ENCRYPTION_SECRET is required",
    "a complete GitHub or GitLab OAuth provider is required",
    "AUTH_URL is required",
  ]);
  assert.doesNotThrow(() => assertProductionSecurity(secureProduction));
  assert.deepEqual(
    productionSecurityErrors({ ...secureProduction, AUTH_URL: "https://user@example.com/path" }),
    ["AUTH_URL must be an HTTP(S) origin without credentials or a path"],
  );
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
