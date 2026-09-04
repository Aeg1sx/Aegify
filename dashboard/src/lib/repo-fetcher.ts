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
}

// ---------------------------------------------------------------------------
// Security: path validation
// ---------------------------------------------------------------------------

const PATH_TRAVERSAL_RE = /\.\./;
const NULL_BYTE_RE = /\0/;
const GIT_DIR_RE = /(?:^|\/)\.git(?:$|\/|modules|ignore|attributes|keep)/;

export function isPathSafe(path: string): boolean {
  if (!path || typeof path !== "string") return false;
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
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
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
// Tree entry types from APIs
// ---------------------------------------------------------------------------

interface GitHubTreeEntry {
  path: string;
  mode: string;   // "120000" = symlink
  type: string;   // "blob" | "tree"
  sha: string;
  size?: number;
}

interface GitLabTreeEntry {
  id: string;
  name: string;
  type: string;   // "blob" | "tree"
  path: string;
  mode: string;   // "120000" = symlink
}

// ---------------------------------------------------------------------------
// GitHub: fetch tree + file content
// ---------------------------------------------------------------------------

async function fetchGitHubTree(
  accessToken: string,
  ownerSlug: string,
  ref: string,
): Promise<{ entries: GitHubTreeEntry[]; resolvedRef: string; truncated: boolean }> {
  // First resolve the ref to a commit SHA, then get the tree
  const commitRes = await fetch(
    `https://api.github.com/repos/${ownerSlug}/commits/${encodeURIComponent(ref)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github.v3+json",
      },
    },
  );

  if (!commitRes.ok) {
    throw new Error(`GitHub commit lookup failed (${commitRes.status}): ${await commitRes.text()}`);
  }

  const commit = await commitRes.json();
  const commitSha = commit.sha;
  const treeSha = commit.commit?.tree?.sha;
  if (!commitSha || !treeSha) throw new Error("Could not resolve immutable commit and tree SHA");

  const treeRes = await fetch(
    `https://api.github.com/repos/${ownerSlug}/git/trees/${treeSha}?recursive=true`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github.v3+json",
      },
    },
  );

  if (!treeRes.ok) {
    throw new Error(`GitHub tree fetch failed (${treeRes.status}): ${await treeRes.text()}`);
  }

  const treeData = await treeRes.json();
  return {
    entries: treeData.tree || [],
    resolvedRef: commitSha,
    truncated: treeData.truncated === true,
  };
}

async function fetchGitHubFileRaw(
  accessToken: string,
  ownerSlug: string,
  path: string,
  ref: string,
): Promise<string | null> {
  const url = `https://api.github.com/repos/${ownerSlug}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github.v3.raw",
    },
  });
  if (!res.ok) return null;
  return res.text();
}

// ---------------------------------------------------------------------------
// GitLab: fetch tree + file content
// ---------------------------------------------------------------------------

async function fetchGitLabTree(
  accessToken: string,
  providerRepoId: string,
  ref: string,
): Promise<{ entries: GitLabTreeEntry[]; truncated: boolean }> {
  const entries: GitLabTreeEntry[] = [];
  let page = 1;

  while (page <= 50) { // Safety cap at 50 pages (5000 entries)
    const url = `https://gitlab.com/api/v4/projects/${encodeURIComponent(providerRepoId)}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(ref)}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      if (page === 1) {
        throw new Error(`GitLab tree fetch failed (${res.status}): ${await res.text()}`);
      }
      return { entries, truncated: true };
    }

    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;
    entries.push(...data);
    const nextPage = res.headers.get("x-next-page");
    if (!nextPage) return { entries, truncated: false };
    page++;
  }

  return { entries, truncated: true };
}

async function resolveGitLabRef(
  accessToken: string,
  providerRepoId: string,
  ref: string,
): Promise<string> {
  const url = `https://gitlab.com/api/v4/projects/${encodeURIComponent(providerRepoId)}/repository/commits/${encodeURIComponent(ref)}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(`GitLab commit lookup failed (${response.status}): ${await response.text()}`);
  }
  const commit = await response.json();
  if (!commit.id || typeof commit.id !== "string") {
    throw new Error("Could not resolve immutable GitLab commit SHA");
  }
  return commit.id;
}

async function fetchGitLabFileRaw(
  accessToken: string,
  providerRepoId: string,
  filePath: string,
  ref: string,
): Promise<string | null> {
  const encodedPath = encodeURIComponent(filePath);
  const url = `https://gitlab.com/api/v4/projects/${encodeURIComponent(providerRepoId)}/repository/files/${encodedPath}/raw?ref=${encodeURIComponent(ref)}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  return res.text();
}

// ---------------------------------------------------------------------------
// Main: fetchRepoCode
// ---------------------------------------------------------------------------

export async function fetchRepoCode(config: RepoFetchConfig): Promise<CodeBundle> {
  const maxFiles = config.maxFiles ?? 1000;
  const maxFileSize = config.maxFileSizeBytes ?? 102400;   // 100KB
  const maxTotal = config.maxTotalBytes ?? 10485760;       // 10MB

  // Step 1: Get tree listing
  type TreeEntry = { path: string; mode: string; type: string; size?: number };
  let treeEntries: TreeEntry[];
  let resolvedRef: string;
  let truncated: boolean;

  if (config.provider === "github") {
    const resolved = await fetchGitHubTree(config.accessToken, config.ownerSlug, config.ref);
    treeEntries = resolved.entries;
    resolvedRef = resolved.resolvedRef;
    truncated = resolved.truncated;
  } else {
    resolvedRef = await resolveGitLabRef(
      config.accessToken,
      config.providerRepoId,
      config.ref,
    );
    const gitLabTree = await fetchGitLabTree(
      config.accessToken,
      config.providerRepoId,
      resolvedRef,
    );
    truncated = gitLabTree.truncated;
    treeEntries = gitLabTree.entries.map((e) => ({
      path: e.path,
      mode: e.mode,
      type: e.type,
      size: undefined, // GitLab tree doesn't return size
    }));
  }

  // Step 2: Filter entries
  let skippedFiles = 0;
  const candidates: string[] = [];

  for (const entry of treeEntries) {
    // Only process blobs (files), not trees (directories)
    if (entry.type !== "blob") continue;

    // Reject symlinks (mode "120000")
    if (entry.mode === "120000") {
      skippedFiles++;
      continue;
    }

    // Path safety check
    if (!isPathSafe(entry.path)) {
      skippedFiles++;
      continue;
    }

    // File type check
    if (!isScannableFile(entry.path)) {
      skippedFiles++;
      continue;
    }

    // Pre-filter by size if available (GitHub provides size in tree)
    if (entry.size !== undefined && entry.size > maxFileSize) {
      skippedFiles++;
      truncated = true;
      continue;
    }

    candidates.push(entry.path);
  }

  // Enforce max file count
  truncated ||= candidates.length > maxFiles;
  const filesToFetch = candidates.slice(0, maxFiles);

  // Step 3: Fetch file contents with concurrency control
  const files: FetchedFile[] = [];
  let totalBytes = 0;
  const concurrency = 10;

  for (let i = 0; i < filesToFetch.length; i += concurrency) {
    if (totalBytes >= maxTotal) {
      truncated = true;
      break;
    }

    const batch = filesToFetch.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (filePath) => {
        let content: string | null;
        if (config.provider === "github") {
          content = await fetchGitHubFileRaw(
            config.accessToken,
            config.ownerSlug,
            filePath,
            resolvedRef,
          );
        } else {
          content = await fetchGitLabFileRaw(
            config.accessToken,
            config.providerRepoId,
            filePath,
            resolvedRef,
          );
        }
        return { filePath, content };
      }),
    );

    for (const result of results) {
      if (result.status !== "fulfilled" || result.value.content === null) {
        skippedFiles++;
        truncated = true;
        continue;
      }

      const { filePath, content } = result.value;
      const sizeBytes = new TextEncoder().encode(content).length;

      // Enforce per-file size limit
      if (sizeBytes > maxFileSize) {
        skippedFiles++;
        truncated = true;
        continue;
      }

      // Enforce total size limit
      if (totalBytes + sizeBytes > maxTotal) {
        skippedFiles++;
        truncated = true;
        continue;
      }

      files.push({ path: filePath, content, sizeBytes });
      totalBytes += sizeBytes;
    }
  }

  return {
    files,
    totalBytes,
    skippedFiles,
    truncated,
    ref: resolvedRef,
    fetchedAt: new Date().toISOString(),
  };
}
