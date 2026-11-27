import assert from "node:assert/strict";
import test from "node:test";

import { fetchRepoCode, isPathSafe, isScannableFile, readBoundedProviderBody } from "./repo-fetcher.ts";

test("deterministic scans read declared configuration and historical model scans skip those bodies before download", async () => {
  const original = globalThis.fetch;
  const paths = ["src/wrangler.jsonc", "wrangler.json", "app/wrangler.toml", "config/application-prod.properties", "spring/bootstrap.yml", "deploy/kong.json"];
  const reads: string[] = [];
  const sha = "a".repeat(40);
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path.includes("/commits/")) return Response.json({ sha, commit: { tree: { sha } } });
    if (path.includes("/git/trees/")) return Response.json({ tree: paths.map((p) => ({ path: p, mode: "100644", type: "blob" })) });
    reads.push(path);
    return new Response("owned-marker");
  };
  try {
    const options = { provider: "github" as const, accessToken: "owned", ownerSlug: "owner/repo", providerRepoId: "", ref: "main" };
    const scan = await fetchRepoCode(options);
    assert.equal(reads.length, paths.length);
    assert.deepEqual(scan.files.map((file) => file.path).sort(), [...paths].sort());
    reads.length = 0;
    const model = await fetchRepoCode({ ...options, withholdConfigFromModel: true });
    assert.equal(model.omittedFiles, paths.length);
    assert.equal(model.truncated, true);
    assert.equal(model.files.length, 0);
    assert.deepEqual(reads, []);
    assert.equal(isScannableFile("other.jsonc"), false);
    assert.equal(isScannableFile("node_modules/demo/wrangler.jsonc"), false);
  } finally { globalThis.fetch = original; }
});

test("pins GitHub tree and file reads to the resolved commit SHA", async () => {
  const originalFetch = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = async (input) => {
    const url = String(input);
    urls.push(url);
    if (url.includes("/commits/main")) {
      return Response.json({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", commit: { tree: { sha: "cccccccccccccccccccccccccccccccccccccccc" } } });
    }
    if (url.includes("/git/trees/cccccccccccccccccccccccccccccccccccccccc")) {
      return Response.json({
        truncated: false,
        tree: [{ path: "src/index.ts", mode: "100644", type: "blob", size: 18 }],
      });
    }
    if (url.includes("/contents/src%2Findex.ts?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {
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
    assert.equal(bundle.ref, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert.equal(bundle.files.length, 1);
    assert.ok(urls.some((url) => url.includes("ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")));
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
      return Response.json({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", commit: { tree: { sha: "cccccccccccccccccccccccccccccccccccccccc" } } });
    }
    if (url.includes("/git/trees/cccccccccccccccccccccccccccccccccccccccc")) {
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
    assert.equal(bundle.ref, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
      return Response.json({ id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" });
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
    if (url.includes("/repository/files/src%2Fapp.py/raw?ref=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")) {
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
    assert.equal(bundle.ref, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert.equal(bundle.files.length, 1);
    assert.ok(urls.some((url) => url.includes("ref=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")));
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
      return Response.json({ id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" });
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
    assert.equal(bundle.ref, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("retains an empty source file without declaring the snapshot partial", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("/commits/main")) {
      return Response.json({ sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", commit: { tree: { sha: "cccccccccccccccccccccccccccccccccccccccc" } } });
    }
    if (url.includes("/git/trees/cccccccccccccccccccccccccccccccccccccccc")) {
      return Response.json({
        truncated: false,
        tree: [{ path: "src/empty.ts", mode: "100644", type: "blob", size: 0 }],
      });
    }
    if (url.includes("/contents/src%2Fempty.ts?ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {
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

test("provider streams are bounded before decoding and cancellation stops a stalled body", async () => {
  let cancelled = false;
  const oversized = new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(10)); }, cancel() { cancelled = true; } }));
  await assert.rejects(readBoundedProviderBody(oversized, 5, new AbortController().signal), /byte limit/);
  assert.equal(cancelled, true);
  const control = new AbortController();
  const stalled = new Response(new ReadableStream({ cancel() { cancelled = true; } }));
  const reading = readBoundedProviderBody(stalled, 100, control.signal);
  control.abort(new Error("synthetic cancellation"));
  await assert.rejects(reading, /synthetic cancellation/);
});

test("a commit is pinned before tree download and provider errors omit response bodies", async () => {
  const originalFetch = globalThis.fetch;
  let pinned = "";
  globalThis.fetch = async (input, init) => {
    assert.equal(init?.redirect, "manual");
    if (String(input).includes("/commits/")) return Response.json({ sha: "a".repeat(40), commit: { tree: { sha: "c".repeat(40) } } });
    assert.equal(pinned, "a".repeat(40));
    return new Response("PRIVATE_PROVIDER_BODY", { status: 503 });
  };
  try {
    await assert.rejects(fetchRepoCode({ provider: "github", accessToken: "synthetic-token", ownerSlug: "owner/repo", providerRepoId: "", ref: "main", onResolved: async (commit) => { pinned = commit; } }), (error: unknown) => error instanceof Error && error.message.includes("503") && !error.message.includes("PRIVATE_PROVIDER_BODY"));
  } finally { globalThis.fetch = originalFetch; }
});

test("source inventory admits module extensions and rejects ambiguous writable paths", () => {
  for (const path of ["src/app.mts", "src/app.cts"]) assert.equal(isScannableFile(path), true);
  for (const path of ["../app.py", "/app.py", "src//app.py", "src/./app.py", "src/\u0001app.py", ".git/config"]) assert.equal(isPathSafe(path), false);
});

test("provider snapshots admit conventional Spring properties within source selection", () => {
  for (const name of ["application.properties", "src/main/resources/application-prod.properties", "conf/bootstrap.properties"]) {
    assert.equal(isScannableFile(name), true);
  }
  for (const name of ["credentials.properties", "node_modules/demo/application.properties", "application.properties.bak"]) {
    assert.equal(isScannableFile(name), false);
  }
});
