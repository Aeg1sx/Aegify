import assert from "node:assert/strict";
import test from "node:test";
import { handlerRange, parseEndpointContract, parseEndpointEvidence } from "./endpoint-evidence.ts";

test("endpoint handler bounds are explicit, positive, and ordered", () => {
  assert.deepEqual(handlerRange(20, 26), { start: 20, end: 26 });
  assert.deepEqual(handlerRange(20, 20), { start: 20, end: 20 });
  for (const [start, end] of [[0, 0], [20, 0], [20, undefined], [20, 19], [1.5, 20], [NaN, 20], ["20", 26]]) assert.equal(handlerRange(start, end), null);
});

test("endpoint evidence parsing rejects malformed records without crashing or hiding the gap", () => {
  for (const raw of ["{", "{}", "[null]", '[{"linkConfidence":"high"}]']) {
    const parsed = parseEndpointEvidence(raw, "runtime");
    assert.equal(parsed.items.length, 0); assert.ok(parsed.warnings.length);
  }
  const parsed = parseEndpointEvidence(JSON.stringify([{ id: "r1", statusCode: "200", durationMs: -1, linkConfidence: 9 }]), "runtime");
  assert.equal(parsed.items.length, 1);
  assert.equal(parsed.items[0].confidence, undefined);
  assert.deepEqual(parsed.items[0].details, { id: "r1" });
  assert.ok(parsed.warnings.length);
  const bounded = parseEndpointEvidence(JSON.stringify(Array(220).fill({ id: "r1" })), "runtime");
  assert.equal(bounded.items.length, 200); assert.equal(bounded.total, 220); assert.ok(bounded.warnings.length);
});

test("runtime metadata preserves zero and failed controls without exposing request content", () => {
  const parsed = parseEndpointEvidence(JSON.stringify([{ id: "r1", method: "GET", path: "/orders?synthetic-secret=value#fragment", statusCode: 403, durationMs: 0, passed: false, linkConfidence: 0, headers: { Authorization: "private" }, body: "private" }]), "runtime");
  assert.equal(parsed.items[0].confidence, 0);
  assert.equal(parsed.items[0].details.durationMs, 0);
  assert.equal(parsed.items[0].details.passed, false);
  assert.equal(parsed.items[0].details.statusCode, 403);
  assert.equal(parsed.items[0].label, "/orders");
  assert.ok(!JSON.stringify(parsed).includes("private"));
  assert.ok(!JSON.stringify(parsed).includes("synthetic-secret"));
});

test("gateway and frontend evidence retain source locations and imported match metadata", () => {
  const gateway = parseEndpointEvidence(JSON.stringify([{ id: "g1", path_patterns: ["/api/**"], methods: ["GET"], file_path: "gateway/routes.yml", line: 8, filters: ["Auth"], linkConfidence: 0.7 }]), "gateway");
  assert.equal(gateway.items[0].location, "gateway/routes.yml:8"); assert.equal(gateway.items[0].method, "GET");
  const frontend = parseEndpointEvidence(JSON.stringify([{ id: "f1", filePath: "web/api.ts", line: 5, path: "/api/orders", matchKind: "exact", dynamic: false }]), "frontend");
  assert.equal(frontend.items[0].location, "web/api.ts:5"); assert.equal(frontend.items[0].matchKind, "exact");
  assert.equal(frontend.items[0].details.dynamic, false);
});

test("contract parsing is bounded and treats unknown data as missing, not an empty API", () => {
  const result = parseEndpointContract('[{"name":"id","location":"query","paramType":"string"},null]', '["session",null,42]');
  assert.deepEqual(result.parameters, [{ name: "id", location: "query", type: "string" }]);
  assert.deepEqual(result.middleware, ["session"]); assert.ok(result.warnings.length);
  assert.deepEqual(parseEndpointContract("[]", "[]"), { parameters: [], middleware: [], warnings: [] });
});
