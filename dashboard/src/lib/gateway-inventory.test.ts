import assert from "node:assert/strict";
import test from "node:test";
import { gatewayStorage, parseGatewayInventory, storedGatewayReview } from "./gateway-inventory.ts";

function fixture() {
  return {
    version: 1, digest: "d".repeat(64), input_status: "partial", omitted_files: 1, omitted_routes: 0,
    files: [{ repository_id: "gitlab/group/sys", path: "deploy/kong.yaml", sha256: "e".repeat(64),
      diagnostics: [], routes: [
        { schema_path: "kong.3.0", document: 1, line: 11, route_name: "orders", status: "resolved",
          reason: "manifest_service_name", repository_ids: ["orders"], plugins: { key: "private-plugin-value" } },
        { schema_path: "kong.3.0", document: 1, line: 12, route_name: "other", status: "ambiguous",
          reason: "multiple_manifest_owners", repository_ids: ["accounts", "orders"] },
        { schema_path: "kong.3.0", document: 1, line: 13, route_name: null, status: "unresolved",
          reason: "kong_upstream_pool", repository_ids: [] as string[] },
      ] }],
  };
}

test("legacy scans have no inventory, a partial inventory preserves its evidence and owner counts", () => {
  assert.equal(parseGatewayInventory(undefined), null);
  assert.equal(storedGatewayReview(null), null);
  const review = parseGatewayInventory(fixture());
  assert.ok(review);
  const storage = gatewayStorage(review);
  assert.deepEqual(storage.summary, { inputStatus: "partial", fileCount: 1, resolved: 1, ambiguous: 1,
    unresolved: 1, omittedFiles: 1, omittedRoutes: 0 });
  assert.deepEqual(storedGatewayReview(storage.data), review);
  assert.ok(!storage.data.details.includes("private-plugin-value"));
  assert.deepEqual(review.files[0].routes[1].owners, ["accounts", "orders"]);
  assert.equal(review.files[0].routes[2].reason, "kong_upstream_pool");
});

test("rejects contradictory ownership, unsafe paths, unbounded evidence and unsupported versions", () => {
  const mutations: Array<(data: ReturnType<typeof fixture>) => void> = [
    (data) => { data.input_status = "processed"; },
    (data) => { data.files[0].path = "../kong.yaml"; },
    (data) => { data.files[0].sha256 = "wrong"; },
    (data) => { data.files[0].routes[0].status = "ambiguous"; },
    (data) => { data.files[0].routes[0].repository_ids.push("billing"); },
    (data) => { data.files[0].routes[0].reason = "unreviewed secret message"; },
    (data) => { data.files[0].routes[0].line = 0; },
    (data) => { data.files.push(data.files[0]); },
    (data) => { data.files[0].routes = Array(4097).fill(data.files[0].routes[0]); },
    (data) => { data.version = 3; },
  ];
  for (const mutate of mutations) {
    const data = fixture();
    mutate(data);
    assert.throws(() => parseGatewayInventory(data), /Invalid or unsupported gateway inventory/);
  }
});

test("full-size workspace imports preserve ambiguous owners within the detail budget", () => {
  const data = fixture();
  const owners = Array.from({ length: 32 }, (_, index) => "service-" + index);
  const route = { ...data.files[0].routes[1], repository_ids: owners };
  data.files[0].routes = Array.from({ length: 4096 }, (_, index) => ({ ...route, line: index + 1 }));
  const review = parseGatewayInventory(data);
  assert.ok(review);
  const stored = gatewayStorage(review);
  assert.equal(stored.summary.ambiguous, 4096);
  const restored = storedGatewayReview(stored.data);
  assert.deepEqual(restored?.files[0].routes.at(-1)?.owners, owners);

  owners.push("additional-owner");
  assert.throws(() => parseGatewayInventory(data), /Invalid or unsupported gateway inventory/);
  owners.pop();
  owners[0] = "a".repeat(2048);
  assert.throws(() => parseGatewayInventory(data), /Invalid or unsupported gateway inventory/);
});
