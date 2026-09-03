import assert from "node:assert/strict";
import test from "node:test";

import { fetchRepoCode } from "./repo-fetcher.ts";

test("pins GitHub tree and file reads to the resolved commit SHA", async () => {
  const originalFetch = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.includes("/commits/main")) {
      return Response.json({ sha: "commit-123", commit: { tree: { sha: "tree-123" } } });
    }
    if (url.includes("/git/trees/tree-123")) {
      return Response.json({
        truncated: false,
        tree: [{ path: "src/index.ts", mode: "100644", type: "blob", size: 18 }],
      });
    }
    if (url.includes("/contents/src%2Findex.ts?ref=commit-123")) {
      return new Response("export const ok = 1;");
    }
    return new Response("unexpected request", { status: 500 });
  };

  try {
    const bundle = await fetchRepoCode({
      provider: "github",
      accessToken: "test-token",
      ownerSlug: "owner/repo",
      providerRepoId: "",
      ref: "main",
    });
    assert.equal(bundle.ref, "commit-123");
    assert.equal(bundle.files.length, 1);
    assert.ok(urls.some((url) => url.includes("ref=commit-123")));
    assert.equal(urls.some((url) => url.includes("contents") && url.includes("ref=main")), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("reports a partial GitHub snapshot when the provider truncates its tree", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/commits/main")) {
      return Response.json({ sha: "commit-123", commit: { tree: { sha: "tree-123" } } });
    }
    if (url.includes("/git/trees/tree-123")) {
      return Response.json({ truncated: true, tree: [] });
    }
    return new Response("unexpected request", { status: 500 });
  };

  try {
    const bundle = await fetchRepoCode({
      provider: "github",
      accessToken: "test-token",
      ownerSlug: "owner/repo",
      providerRepoId: "",
      ref: "main",
    });
    assert.equal(bundle.truncated, true);
    assert.equal(bundle.ref, "commit-123");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("pins GitLab tree and file reads to the resolved commit SHA", async () => {
  const originalFetch = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.includes("/repository/commits/main")) {
      return Response.json({ id: "gitlab-commit-456" });
    }
    if (
      url.includes("/repository/tree?") &&
      new URL(url).searchParams.get("page") === "1"
    ) {
      return Response.json([
        { id: "blob", name: "app.py", type: "blob", path: "src/app.py", mode: "100644" },
      ], { headers: { "x-next-page": "" } });
    }
    if (url.includes("/repository/tree?")) return Response.json([]);
    if (url.includes("/repository/files/src%2Fapp.py/raw?ref=gitlab-commit-456")) {
      return new Response("safe = True\n");
    }
    return new Response("unexpected request", { status: 500 });
  };

  try {
    const bundle = await fetchRepoCode({
      provider: "gitlab",
      accessToken: "test-token",
      ownerSlug: "owner/repo",
      providerRepoId: "42",
      ref: "main",
    });
    assert.equal(bundle.ref, "gitlab-commit-456");
    assert.equal(bundle.files.length, 1);
    assert.ok(urls.some((url) => url.includes("ref=gitlab-commit-456")));
    assert.equal(urls.some((url) => url.includes("repository/tree") && url.includes("ref=main")), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("marks a GitLab snapshot partial when a later tree page fails", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/repository/commits/main")) {
      return Response.json({ id: "gitlab-commit-456" });
    }
    if (
      url.includes("/repository/tree?") &&
      new URL(url).searchParams.get("page") === "1"
    ) {
      return Response.json(
        [{ id: "tree", name: "src", type: "tree", path: "src", mode: "040000" }],
        { headers: { "x-next-page": "2" } },
      );
    }
    if (
      url.includes("/repository/tree?") &&
      new URL(url).searchParams.get("page") === "2"
    ) {
      return new Response("provider error", { status: 503 });
    }
    return new Response("unexpected request", { status: 500 });
  };

  try {
    const bundle = await fetchRepoCode({
      provider: "gitlab",
      accessToken: "test-token",
      ownerSlug: "owner/repo",
      providerRepoId: "42",
      ref: "main",
    });
    assert.equal(bundle.truncated, true);
    assert.equal(bundle.ref, "gitlab-commit-456");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("retains an empty source file without declaring the snapshot partial", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/commits/main")) {
      return Response.json({ sha: "commit-123", commit: { tree: { sha: "tree-123" } } });
    }
    if (url.includes("/git/trees/tree-123")) {
      return Response.json({
        truncated: false,
        tree: [{ path: "src/empty.ts", mode: "100644", type: "blob", size: 0 }],
      });
    }
    if (url.includes("/contents/src%2Fempty.ts?ref=commit-123")) {
      return new Response("");
    }
    return new Response("unexpected request", { status: 500 });
  };

  try {
    const bundle = await fetchRepoCode({
      provider: "github",
      accessToken: "test-token",
      ownerSlug: "owner/repo",
      providerRepoId: "",
      ref: "main",
    });
    assert.equal(bundle.files.length, 1);
    assert.equal(bundle.files[0].content, "");
    assert.equal(bundle.truncated, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
