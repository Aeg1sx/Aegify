import assert from "node:assert/strict";
import test from "node:test";

import { uploadValidationError } from "./upload-validation.ts";

test("accepts supported SARIF and OpenAPI JSON uploads", () => {
  assert.equal(
    uploadValidationError(
      { name: "results.sarif", size: 1024, type: "application/sarif+json" },
      "sarif",
    ),
    null,
  );
  assert.equal(
    uploadValidationError(
      { name: "openapi.json", size: 1024, type: "application/json" },
      "openapi",
    ),
    null,
  );
});

test("rejects disguised and oversized uploads", () => {
  assert.match(
    uploadValidationError(
      { name: "payload.exe", size: 1024, type: "application/json" },
      "sarif",
    ) || "",
    /unsupported file type/,
  );
  assert.match(
    uploadValidationError(
      { name: "openapi.json", size: 11 * 1024 * 1024, type: "application/json" },
      "openapi",
    ) || "",
    /10 MB limit/,
  );
});
