import assert from "node:assert/strict";
import { test } from "node:test";
import { repositoryPages } from "./repository-pages.ts";
import { repositoryLink, repositoryName } from "./project-view.ts";

const address = (page: number) => "https://fixture.invalid/repositories?page=" + page;

test("repository listing distinguishes an empty directory, an interrupted page and the display limit", async (t) => {
  const full = Array.from({ length: 100 }, (_, index) => ({ id: index + 1 }));
  const responses = [Response.json([]), Response.json(full), new Response(null, { status: 503 })];
  const transport = t.mock.method(globalThis, "fetch", async () => responses.shift() ?? Response.json(full));
  const list = () => repositoryPages<{ id: number }>(address, {}, new AbortController().signal);
  assert.deepEqual(await list(), { state: "complete", items: [] });
  assert.deepEqual(await list(), { state: "interrupted", items: full });
  const limited = await list();
  assert.equal(limited.state, "limited");
  assert.equal(limited.items.length, 500);
  assert.equal(transport.mock.callCount(), 8);
});

test("repository links show the host and path and use web URLs for navigation", () => {
  const source = "https://member:fixture@example.test/group/repository?ref=dev#readme";
  assert.equal(repositoryLink(source), "https://example.test/group/repository");
  assert.equal(repositoryName({ repositoryUrl: source }), "example.test/group/repository");
  assert.equal(repositoryName({ repositoryUrl: "git@example.test:team/worker" }), "example.test/team/worker");
  assert.equal(repositoryLink("git@example.test:team/worker"), undefined);
  assert.equal(repositoryLink("file:///tmp/repository"), undefined);
  assert.equal(repositoryName({ repositoryUrl: "", ownerSlug: "team/api" }), "team/api");
});
