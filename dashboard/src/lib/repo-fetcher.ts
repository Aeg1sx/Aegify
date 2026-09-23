/**
 * Secure repo code fetcher using Tree API + individual file API.
 * Never uses git clone or tarball — all content is fetched via REST API
 * and processed in memory only (no disk writes).
 */

export interface RepoFetchConfig {
  provider: "github" | "gitlab";
  accessToken: string;
  ownerSlug: string;       // "owner/repo" (GitHub) / "group/project" (GitLab)
  providerRepoId: string;  // GitLab needs numeric project ID
  ref: string;             // branch or commit SHA
  signal?: AbortSignal;
  onResolved?: (commit: string) => Promise<void>;
  maxFiles?: number;       // default 1000
  maxFileSizeBytes?: number;  // default 102400 (100KB)
  maxTotalBytes?: number;     // default 10485760 (10MB)
}

export interface FetchedFile {
  path: string;
  content: string;
  sizeBytes: number;
}

export interface CodeBundle {
  files: FetchedFile[];
  totalBytes: number;
  skippedFiles: number;
  truncated: boolean;
  ref: string;
  fetchedAt: string;
  omittedFiles: number;
  selection: "source-and-config";
}

// ---------------------------------------------------------------------------
// Security: path validation
// ---------------------------------------------------------------------------

const PATH_TRAVERSAL_RE = /\.\./;
const NULL_BYTE_RE = /[\x00-\x1f\x7f]/;
const GIT_DIR_RE = /(?:^|\/)\.git(?:$|\/|modules|ignore|attributes|keep)/;

export function isPathSafe(path: string): boolean {
  if (!path || typeof path !== "string" || new TextEncoder().encode(path).length > 1024 || path.split("/").some((part) => !part || part === ".")) return false;
  // Block absolute paths (unix and windows)
  if (path.startsWith("/") || /^[a-zA-Z]:/.test(path)) return false;
  // Block path traversal
  if (PATH_TRAVERSAL_RE.test(path)) return false;
  // Block null bytes
  if (NULL_BYTE_RE.test(path)) return false;
  // Block backslashes (windows-style or escape attempts)
  if (path.includes("\\")) return false;
  // Block .git directories and related files
  if (GIT_DIR_RE.test(path)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Security: file type allowlist
// ---------------------------------------------------------------------------

const SCANNABLE_EXTENSIONS = new Set([
  // JavaScript / TypeScript
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts",
  // Python
  ".py", ".pyw",
  // Java / Kotlin / Scala
  ".java", ".kt", ".kts", ".scala",
  // Go
  ".go",
  // Ruby
  ".rb", ".erb",
  // PHP
  ".php",
  // C / C++ / C#
  ".c", ".h", ".cpp", ".hpp", ".cc", ".cs",
  // Rust
  ".rs",
  // Swift / Objective-C
  ".swift", ".m",
  // Shell
  ".sh", ".bash",
  // Web
  ".html", ".htm", ".vue", ".svelte",
  // Config (code-like)
  ".yaml", ".yml", ".json", ".toml",
  // SQL
  ".sql",
  // Markdown (for documentation scanning)
  ".md",
  // Solidity
  ".sol",
  // Dart
  ".dart",
  // Elixir / Erlang
  ".ex", ".exs", ".erl",
]);

const BLOCKED_DIRECTORIES = new Set([
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "__pycache__",
  ".venv",
  "venv",
  "env",
  ".tox",
  ".eggs",
  "target",        // Java/Rust
  "bin",
  "obj",
  ".gradle",
  ".idea",
  ".vscode",
  ".vs",
  "coverage",
  ".cache",
  ".turbo",
  ".output",
  "out",
]);

const LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Pipfile.lock",
  "poetry.lock",
  "Gemfile.lock",
  "composer.lock",
  "Cargo.lock",
  "go.sum",
]);

export function isScannableFile(path: string): boolean {
  const fileName = path.split("/").pop() || "";
  // Block lockfiles
  if (LOCKFILE_NAMES.has(fileName)) return false;

  // Block files in blocked directories
  const parts = path.split("/");
  for (const part of parts) {
    if (BLOCKED_DIRECTORIES.has(part)) return false;
  }

  // Check extension allowlist
  const dotIdx = fileName.lastIndexOf(".");
  if (dotIdx === -1) return false;
  const ext = fileName.slice(dotIdx).toLowerCase();
  return SCANNABLE_EXTENSIONS.has(ext);
}

// ---------------------------------------------------------------------------
// Bounded immutable provider snapshots
// ---------------------------------------------------------------------------

type TreeEntry = { path: string; mode: string; type: string; size?: number };
const COMMIT_ID = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;
const TREE_BYTES = 12 * 1024 * 1024;
const TREE_ENTRIES = 100_000;

/** Check the stream before decoding: a Content-Length header is not a bound. */
export async function readBoundedProviderBody(response: Response, maxBytes: number, signal: AbortSignal): Promise<string> {
  if (Number(response.headers.get("content-length")) > maxBytes) {
    void response.body?.cancel().catch(() => {});
    throw new Error("Provider response exceeds its byte limit.");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { abort(); throw new Error("Provider response exceeds its byte limit."); }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally { signal.removeEventListener("abort", abort); reader.releaseLock(); }
}

async function providerRequest(config: RepoFetchConfig, url: string, maxBytes: number, raw = false): Promise<{ text: string; nextPage: string }> {
  const signal = AbortSignal.any([AbortSignal.timeout(20_000), ...(config.signal ? [config.signal] : [])]);
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${config.accessToken}`, Accept: raw ? "application/vnd.github.v3.raw" : "application/json" },
    redirect: "manual", signal,
  });
  if (!response.ok) {
    void response.body?.cancel().catch(() => {});
    // Provider bodies may contain source or credentials; never copy them into diagnostics.
    throw new Error(`Repository provider returned HTTP ${response.status}.`);
  }
  return { text: await readBoundedProviderBody(response, maxBytes, signal), nextPage: response.headers.get("x-next-page") || "" };
}

function boundedLimit(value: number | undefined, fallback: number, maximum: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1 || resolved > maximum) throw new Error("Invalid source snapshot resource limit.");
  return resolved;
}

export async function fetchRepoCode(config: RepoFetchConfig): Promise<CodeBundle> {
  const maxFiles = boundedLimit(config.maxFiles, 1000, 10_000);
  const maxFileSize = boundedLimit(config.maxFileSizeBytes, 102400, 1024 * 1024);
  const maxTotal = boundedLimit(config.maxTotalBytes, 10 * 1024 * 1024, 50 * 1024 * 1024);
  if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/.test(config.ownerSlug) || config.ownerSlug.split("/").some((part) => part === "." || part === "..") || !/^[A-Za-z0-9._/-]{1,255}$/.test(config.ref) || config.ref.includes("..")) throw new Error("Invalid repository identity or ref.");
  if (config.provider === "github" && config.ownerSlug.split("/").length !== 2) throw new Error("Invalid GitHub repository identity.");
  if (config.provider === "gitlab" && !/^[0-9]{1,20}$/.test(config.providerRepoId)) throw new Error("Invalid GitLab project identity.");
  if (!["github", "gitlab"].includes(config.provider)) throw new Error("Unsupported repository provider.");
  config.signal?.throwIfAborted();
  const base = config.provider === "github"
    ? `https://api.github.com/repos/${config.ownerSlug}`
    : `https://gitlab.com/api/v4/projects/${config.providerRepoId}/repository`;
  const commit = JSON.parse((await providerRequest(config, `${base}/commits/${encodeURIComponent(config.ref)}`, 1024 * 1024)).text);
  const resolvedRef = config.provider === "github" ? commit.sha : commit.id;
  if (typeof resolvedRef !== "string" || !COMMIT_ID.test(resolvedRef)) throw new Error("Provider did not resolve an immutable commit.");
  if (COMMIT_ID.test(config.ref) && config.ref.toLowerCase() !== resolvedRef.toLowerCase()) throw new Error("Provider changed the pinned commit.");
  await config.onResolved?.(resolvedRef);
  let treeEntries: TreeEntry[] = [];
  let truncated = false;
  if (config.provider === "github") {
    const treeSha = commit.commit?.tree?.sha;
    if (typeof treeSha !== "string" || !COMMIT_ID.test(treeSha)) throw new Error("Provider did not resolve an immutable tree.");
    const data = JSON.parse((await providerRequest(config, `${base}/git/trees/${treeSha}?recursive=true`, TREE_BYTES)).text);
    if (!Array.isArray(data.tree) || data.tree.length > TREE_ENTRIES) throw new Error("Provider tree exceeds the entry limit.");
    treeEntries = data.tree;
    truncated = data.truncated === true;
  } else {
    for (let page = 1; page <= 50; page++) {
      try {
        const response = await providerRequest(config, `${base}/tree?recursive=true&per_page=100&page=${page}&ref=${resolvedRef}`, TREE_BYTES);
        const data = JSON.parse(response.text);
        if (!Array.isArray(data) || data.length > 100) throw new Error("Invalid provider tree page.");
        treeEntries.push(...data);
        if (!response.nextPage || !data.length) break;
        if (page === 50) truncated = true;
      } catch (error) {
        config.signal?.throwIfAborted();
        if (page === 1) throw error;
        truncated = true; break;
      }
    }
  }
  let skippedFiles = 0;
  let omittedFiles = 0;
  const candidates = new Set<string>();
  for (const entry of treeEntries) {
    if (!entry || typeof entry.path !== "string" || typeof entry.type !== "string") { truncated = true; omittedFiles++; continue; }
    if (entry.type !== "blob") continue;
    if (!isScannableFile(entry.path)) { skippedFiles++; continue; }
    if (entry.mode !== "100644" && entry.mode !== "100755") { omittedFiles++; skippedFiles++; truncated = true; continue; }
    if (!isPathSafe(entry.path) || (entry.size !== undefined && (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxFileSize))) { omittedFiles++; skippedFiles++; truncated = true; continue; }
    if (candidates.has(entry.path)) throw new Error("Provider tree contains duplicate paths.");
    candidates.add(entry.path);
  }
  const allPaths = [...candidates].sort();
  if (allPaths.length > maxFiles) { truncated = true; omittedFiles += allPaths.length - maxFiles; }
  const filesToFetch = allPaths.slice(0, maxFiles);
  const files: FetchedFile[] = [];
  let totalBytes = 0;
  for (let index = 0; index < filesToFetch.length; index += 10) {
    config.signal?.throwIfAborted();
    if (totalBytes >= maxTotal) { truncated = true; omittedFiles += filesToFetch.length - index; break; }
    const results = await Promise.allSettled(filesToFetch.slice(index, index + 10).map(async (path) => {
      const url = config.provider === "github"
        ? `${base}/contents/${encodeURIComponent(path)}?ref=${resolvedRef}`
        : `${base}/files/${encodeURIComponent(path)}/raw?ref=${resolvedRef}`;
      return { path, content: (await providerRequest(config, url, maxFileSize, true)).text };
    }));
    config.signal?.throwIfAborted();
    for (const result of results) {
      if (result.status !== "fulfilled") { truncated = true; skippedFiles++; omittedFiles++; continue; }
      const { path, content } = result.value;
      const sizeBytes = new TextEncoder().encode(content).length;
      if (totalBytes + sizeBytes > maxTotal) { truncated = true; skippedFiles++; omittedFiles++; continue; }
      files.push({ path, content, sizeBytes }); totalBytes += sizeBytes;
    }
  }
  return { files, totalBytes, skippedFiles, omittedFiles, truncated, ref: resolvedRef, fetchedAt: new Date().toISOString(), selection: "source-and-config" };
}
