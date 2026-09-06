import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createClient } from "@libsql/client";
import { parseApiContract, reconcileContract, SPEC_MAX_BYTES } from "./openapi-contract.ts";
import { fetchApiContract, importApiContract, inspectApiContract, readSpecBody, specUrl, specMutationOriginAllowed } from "./openapi-import.ts";
import { CONTRACT_REVIEW_RULES, contractReviewInput, endpointContractContext, findingContractContext } from "./openapi-context.ts";

const fixture = {
  openapi: "3.1.1", info: { title: "Owned contract fixture", version: "1" },
  servers: [{ url: "https://service.example.test/{version}", variables: { version: { default: "v1" } } }],
  security: [{ Session: [] }],
  components: { parameters: { Id: { name: "id", in: "query", required: false, schema: { type: "string" } } }, schemas: { Body: { type: "object", required: ["name"], properties: { name: { type: "string", minLength: 1, example: "DO-NOT-PERSIST" } } } }, securitySchemes: { Session: { type: "apiKey", in: "cookie", name: "session" } } },
  paths: {
    "/orders": {
      parameters: [{ $ref: "#/components/parameters/Id" }],
      get: {
        operationId: "orders",
        parameters: [{ name: "id", in: "query", required: true, schema: { type: "integer", minimum: 0 } }, { name: "id", in: "header", schema: { type: "string" } }],
        responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Body" } } } } },
      },
    },
    "/public": { get: { security: [], responses: {} } },
    "/optional": { get: { security: [{}, { Session: [] }], responses: {} } },
    "/body": { post: { requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/Body" } } } }, responses: {} } },
  },
};
test("OpenAPI extraction preserves override and OR security semantics, local references and schema constraints", () => {
  const contract = parseApiContract(JSON.stringify(fixture));
  assert.equal(contract.operations.length, 4); assert.equal(contract.digest.length, 64);
  assert.deepEqual(contract.operations.map((operation) => operation.security.state), ["required", "none", "optional", "required"]);
  const order = contract.operations[0]; assert.deepEqual(order.resolvedPaths, ["/v1/orders"]);
  assert.equal(order.parameters.length, 2); assert.equal(order.parameters[0].required, true); assert.equal(order.parameters[0].schema.minimum, 0);
  assert.equal(order.parameters[1].location, "header"); assert.equal(contract.operations[3].requestBody.required, true);
  assert.doesNotMatch(JSON.stringify(contract), /DO-NOT-PERSIST/); assert.equal(contract.warnings.length, 0);
});
test("Swagger YAML and OpenAPI 3.2 operations work without executing templates or fetching references", () => {
  const swagger = parseApiContract("swagger: '2.0'\ninfo: { title: Fixture, version: '1' }\nbasePath: /api\npaths:\n  /orders:\n    get:\n      responses: {}\n");
  assert.equal(swagger.operations[0].resolvedPaths[0], "/api/orders"); assert.equal(swagger.operations[0].security.state, "undeclared");
  const contract = parseApiContract(JSON.stringify({ openapi: "3.2.0", info: { title: "fixture" }, paths: { "/files": { query: { responses: {} }, additionalOperations: { COPY: { responses: {} } } } } }));
  assert.deepEqual(contract.operations.map((operation) => operation.method), ["QUERY", "COPY"]);
});
test("operation and path servers override root servers without inventing a route prefix", () => {
  const contract = parseApiContract(JSON.stringify({ openapi: "3.1.1", info: { title: "fixture" }, servers: [{ url: "/root" }], paths: { "/a": { servers: [{ url: "/path" }], get: { responses: {} }, post: { servers: [{ url: "/operation" }], responses: {} } }, "/b": { get: { servers: [{ url: "../relative" }], responses: {} } } } }));
  assert.deepEqual(contract.operations.map((operation) => operation.resolvedPaths), [["/path/a"], ["/operation/a"], []]); assert.ok(contract.warnings.length);
});
test("malformed, unsupported, ambiguous, oversized and alias documents fail visibly", () => {
  for (const source of ["<html>Swagger UI</html>", "[]", "openapi: [", "openapi: 3.9.0\ninfo: {title: x}\npaths: {}", "openapi: 3.1.1\ninfo: &shared {title: x}\npaths: *shared", "openapi: 3.1.1\nopenapi: 3.0.1"]) assert.throws(() => parseApiContract(source));
  assert.throws(() => parseApiContract(" ".repeat(SPEC_MAX_BYTES + 1)), /limit/);
  assert.throws(() => parseApiContract(JSON.stringify({ openapi: "3.1.1", info: { title: "fixture" }, paths: { "/a/{id}": { get: { responses: {} } }, "/a/{name}": { get: { responses: {} } } } })), /Ambiguous/);
});
test("external, missing and recursive references remain explicit extraction gaps", () => {
  const loop = { $ref: "#/components/schemas/Loop" };
  const operation = { parameters: [{ $ref: "https://private.example.test/parameters" }, { $ref: "#/absent" }], responses: { "200": { content: { "application/json": { schema: loop } } } } };
  const contract = parseApiContract(JSON.stringify({ openapi: "3.1.1", info: { title: "fixture" }, components: { schemas: { Loop: loop } }, paths: { "/a": { get: operation } } }));
  assert.match(contract.warnings.join(" "), /External/); assert.match(contract.warnings.join(" "), /Unresolved/); assert.match(contract.warnings.join(" "), /Recursive/);
});
test("route comparisons preserve source evidence and do not guess templates or implementation auth", () => {
  const contract = parseApiContract(JSON.stringify(fixture));
  const endpoint = { id: "source", path: "/v1/orders", method: "GET", filePath: "orders.py", framework: "FastAPI", lineStart: 10, lineEnd: 20, authRequired: false };
  const result = reconcileContract(contract, [endpoint, { ...endpoint, id: "other", path: "/v1/extra" }, { ...endpoint, id: "documented", framework: "OpenAPI", path: "/v1/public" }]);
  assert.equal(result.matched, 1); assert.equal(result.specOnly, 3); assert.equal(result.codeOnly.length, 1); assert.equal(result.operations[0].matches[0].authRequired, false); assert.match(result.operations[0].reviewNotes[0], /not a confirmed/);
  assert.equal(reconcileContract(contract, [endpoint, { ...endpoint, id: "duplicate" }]).ambiguous, 1);
});
test("URL imports use a bounded credential-free GET and do not follow operation servers", async () => {
  let requests = 0;
  const fetched = await fetchApiContract("https://docs.example.test/openapi.yaml", async (request) => { requests++; assert.equal(request.method, "GET"); assert.equal(request.body, ""); assert.equal(request.timeoutMs, 10_000); assert.deepEqual(Object.keys(request.headers), ["Accept"]); return { status: 200, text: JSON.stringify(fixture) }; });
  assert.equal(requests, 1); assert.equal(fetched.contract.operations.length, 4);
  for (const url of ["http://docs.example.test/a", "https://user:password@docs.example.test/a", "https://docs.example.test/a?token=secret", "https://docs.example.test/a#anchor"]) assert.throws(() => specUrl(url));
  await assert.rejects(fetchApiContract("https://127.0.0.1/openapi.json"));
  await assert.rejects(fetchApiContract("https://docs.example.test/a", async () => ({ status: 302, text: "sensitive response body" })), /Redirects/);
});
test("streamed upload limits are enforced without trusting Content-Length", async () => {
  assert.equal(new TextDecoder().decode(await readSpecBody(new Request("https://workspace.example.test", { method: "POST", body: "abc" }), 3)), "abc");
  await assert.rejects(readSpecBody(new Request("https://workspace.example.test", { method: "POST", body: "abcd" }), 3), /size limit/);
});
test("spec mutations require the configured origin or an exact loopback preview host", () => {
  const request = (origin: string, host = "127.0.0.1:3037") => new Request("http://localhost:3037/api/specs", { headers: { origin, host } });
  assert.equal(specMutationOriginAllowed(request("http://127.0.0.1:3037"), {}), true);
  assert.equal(specMutationOriginAllowed(request("https://other.example.test"), {}), false);
  assert.equal(specMutationOriginAllowed(request("http://127.0.0.1:3037"), { NODE_ENV: "production" }), false);
  assert.equal(specMutationOriginAllowed(request("https://workspace.example.test"), { AUTH_URL: "https://workspace.example.test" }), true);
  assert.equal(specMutationOriginAllowed(request("https://other.example.test"), { AUTH_URL: "https://workspace.example.test" }), false);
  const crossSite = request("http://127.0.0.1:3037"); crossSite.headers.set("sec-fetch-site", "cross-site");
  assert.equal(specMutationOriginAllowed(crossSite, {}), false);
});
test("migrated imports are idempotent and isolate code/finding associations by scan, repository and handler", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-contract-test-")); const url = "file:" + join(directory, "spec.db");
  const sql = createClient({ url }); const migrations = fileURLToPath(new URL("../../prisma/migrations/", import.meta.url));
  for (const entry of (await readdir(migrations, { withFileTypes: true })).filter((entry) => entry.isDirectory()).sort((a, b) => a.name.localeCompare(b.name))) await sql.executeMultiple(await readFile(join(migrations, entry.name, "migration.sql"), "utf8"));
  sql.close(); const db = new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  try {
    const scan = await db.scan.create({ data: { repository: "owned-fixture" } }); const other = await db.scan.create({ data: { repository: "other-fixture" } });
    const endpoint = await db.endpoint.create({ data: { scanId: scan.id, repositoryId: "service-a", path: "/v1/orders", method: "GET", handlerFunction: "orders", framework: "FastAPI", filePath: "orders.py", lineStart: 10, lineEnd: 20, authRequired: false } });
    await db.endpoint.create({ data: { scanId: scan.id, repositoryId: "service-b", path: "/v1/orders", method: "GET", handlerFunction: "orders", framework: "FastAPI", filePath: "orders.py", lineStart: 10, lineEnd: 20 } });
    const contract = parseApiContract(JSON.stringify(fixture)); const input = { scanId: scan.id, repositoryId: "service-a", sourceType: "upload", sourceName: "fixture.json", sourceUrl: "", contract };
    const first = await importApiContract(db, input); assert.equal(first.imported, 3);
    const second = await importApiContract(db, input); assert.equal(second.id, first.id); assert.equal(second.duplicate, true); assert.equal(await db.apiSpecification.count(), 1);
    assert.equal((await db.endpoint.findUnique({ where: { id: endpoint.id } }))?.authRequired, false);
    assert.equal((await inspectApiContract(db, scan.id, "service-a", contract)).matched, 1);
    assert.equal((await endpointContractContext(db, endpoint)).references.length, 1);
    const finding = { scanId: scan.id, repositoryId: "service-a", filePath: "orders.py", lineStart: 15, lineEnd: 15 };
    const contexts = await findingContractContext(db, finding);
    assert.equal(contexts.length, 1);
    const review = contractReviewInput(contexts);
    assert.equal(review.boundary, "documentation_only"); assert.equal(review.references.length, 1);
    assert.equal(review.references[0].contentHash, contract.digest);
    assert.equal(review.references[0].declaredSecurity.state, "required");
    assert.ok(Buffer.byteLength(JSON.stringify(review)) < 6500);
    assert.match(CONTRACT_REVIEW_RULES, /Do not classify a finding as false positive solely/);
    assert.doesNotMatch(JSON.stringify(review), /sourceUrl|DO-NOT-PERSIST/);
    assert.equal((await findingContractContext(db, { ...finding, scanId: other.id })).length, 0);
    assert.equal((await findingContractContext(db, { ...finding, repositoryId: "service-b" })).length, 0);
    assert.equal((await findingContractContext(db, { ...finding, lineStart: 21, lineEnd: 21 })).length, 0);
  } finally { await db.$disconnect(); }
});
