import assert from "node:assert/strict";
import { test } from "node:test";
import { repositoryPages, repositoryWindow } from "./repository-pages.ts";
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
  assert.equal(limited.next, 6);
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

test("continues past repository 500 using trusted page addresses and provider end markers", async (t) => {
  const seen: string[] = [];
  const full = Array.from({ length: 100 }, (_, index) => ({ id: 601 + index }));
  t.mock.method(globalThis, "fetch", async (url: string | URL | Request) => {
    seen.push(String(url));
    if (seen.length === 1)
      return Response.json([{ id: 501 }], { headers: { Link: '<https://untrusted.invalid/>; rel="next"' } });
    return Response.json(full, { headers: { Link: '<https://fixture.invalid/>; rel="prev"' } });
  });
  const github = await repositoryPages<{ id: number }>(address, {}, new AbortController().signal, 6);
  assert.deepEqual(seen, [address(6), address(7)]);
  assert.equal(github.state, "complete");
  assert.deepEqual(github.items, [{ id: 501 }, ...full]);
});

test("GitLab pagination headers handle short intermediate and full terminal pages", async (t) => {
  const full = Array.from({ length: 100 }, (_, id) => ({ id }));
  const replies = [
    Response.json([], { headers: { "x-next-page": "7" } }),
    Response.json(full, { headers: { "x-next-page": "" } }),
  ];
  const transport = t.mock.method(globalThis, "fetch", async () => replies.shift()!);
  assert.deepEqual(await repositoryPages(address, {}, new AbortController().signal, 6),
    { state: "complete", items: full });
  assert.equal(transport.mock.callCount(), 2);
});

test("preserves completed pages when the next response exceeds the byte limit", async (t) => {
  const replies = [
    Response.json([{ id: 501 }], { headers: { "x-next-page": "7" } }),
    new Response(" ".repeat(4 * 1024 * 1024 + 1)),
  ];
  t.mock.method(globalThis, "fetch", async () => replies.shift()!);
  assert.deepEqual(await repositoryPages(address, {}, new AbortController().signal, 6),
    { state: "interrupted", items: [{ id: 501 }] });
});

test("directory windows accept only supported providers and aligned page numbers", () => {
  const window = (raw: string) => repositoryWindow(new URLSearchParams(raw));
  assert.deepEqual(window(""), { start: 1 });
  assert.deepEqual(window("provider=github&start=6"), { provider: "github", start: 6 });
  assert.deepEqual(window("provider=gitlab&start=11"), { provider: "gitlab", start: 11 });
  for (const raw of [
    "provider=github", "start=6", "provider=example.org&start=6", "provider=github&start=2",
    "provider=gitlab&start=-4", "provider=github&start=06", "provider=github&start=10000000000",
    "provider=gitlab&start=6&start=11", "provider=github&provider=gitlab&start=6",
  ]) assert.equal(window(raw), null);
});
