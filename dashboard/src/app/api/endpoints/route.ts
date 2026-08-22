import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const STATIC_PATH_PATTERNS = [
  "/static/", "/public/", "/assets/", "/css/", "/js/", "/images/",
  "/fonts/", "/media/", "/uploads/", "/dist/", "/build/", "/vendor/",
  "/node_modules/", "/.git/", "/.next/", "/bower_components/",
];
const FILE_EXTENSIONS = [
  ".html", ".css", ".js", ".jsx", ".ts", ".tsx", ".map",
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".pdf", ".zip", ".gz", ".tar", ".json", ".xml", ".yaml", ".yml",
  ".md", ".txt", ".csv", ".log",
];
const INTERNAL_PREFIXES = [
  "/health", "/healthz", "/ready", "/readyz", "/alive",
  "/status", "/ping", "/metrics", "/prometheus",
  "/actuator", "/__", "/_internal", "/_debug",
  "/_next/", "/_nuxt/", "/.well-known/",
];
const WILDCARD_SUFFIXES = [
  "/*", "/**", "/*path", "/{*path}", "/<path:path>",
  "/:splat*", "/(.*)", "/{path:.*}", "/{**}",
];

function isApiEndpoint(path: string): boolean {
  // Must start with / — reject field names, property keys, relative paths
  if (!path.startsWith("/")) return false;

  // Reject empty, root, or wildcard-only
  if (path === "/" || path === "/*" || path === "/**" || path === "*") return false;

  // Reject very short single-segment paths that are just a param: /{id}, /:id
  // These are too generic without a prefix (e.g. /users/{id} is fine)
  if (/^\/[{:<][\w:.>}]+$/.test(path)) return false;
  if (/^\/:[\w]+$/.test(path)) return false;

  const lower = path.toLowerCase();

  // Reject static asset paths
  if (STATIC_PATH_PATTERNS.some((p) => lower.includes(p))) return false;

  // Reject file extension endpoints. A final path parameter is not a file.
  const finalSegment = path.slice(path.lastIndexOf("/") + 1);
  const finalSegmentIsParameter =
    /^\{[A-Za-z_][\w:.]*\}$/.test(finalSegment) ||
    /^<[A-Za-z_][\w:]*>$/.test(finalSegment) ||
    /^:[A-Za-z_][\w]*$/.test(finalSegment);
  if (!finalSegmentIsParameter && FILE_EXTENSIONS.some((ext) => finalSegment.endsWith(ext))) {
    return false;
  }

  // Reject catch-all / wildcard routes
  if (WILDCARD_SUFFIXES.some((s) => path.endsWith(s))) return false;

  // Reject internal/monitoring endpoints
  if (INTERNAL_PREFIXES.some((p) => lower.startsWith(p))) return false;

  // Reject paths that look like relative file paths
  if (path.startsWith("./") || path.startsWith("../")) return false;

  return true;
}

const TEST_PATH_SEGMENTS = [
  "/test/", "/tests/", "/Test/", "/__tests__/", "/spec/", "/specs/",
  "/test-", "/testFixtures/", "/testdata/", "/testing/",
  "/src/test/", "/src/androidTest/",
];
const TEST_FILE_SUFFIXES = [
  "Test.kt", "Test.java", "Test.py", "Test.ts", "Test.js",
  "Tests.kt", "Tests.java", "Tests.py",
  ".test.ts", ".test.js", ".test.tsx", ".test.jsx",
  ".spec.ts", ".spec.js", ".spec.tsx", ".spec.jsx",
  "_test.py", "_test.go",
];

function isTestFile(filePath: string): boolean {
  if (TEST_PATH_SEGMENTS.some((seg) => filePath.includes(seg))) return true;
  if (TEST_FILE_SUFFIXES.some((suf) => filePath.endsWith(suf))) return true;
  return false;
}

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const scanId = url.searchParams.get("scanId");
  const projectId = url.searchParams.get("projectId");
  const framework = url.searchParams.get("framework");
  const method = url.searchParams.get("method");
  const authOnly = url.searchParams.get("authOnly");
  const quality = url.searchParams.get("quality");

  const where: Record<string, unknown> = {};
  if (scanId) where.scanId = scanId;
  if (framework) where.framework = framework;
  if (method) where.method = method;
  if (authOnly === "true") where.authRequired = true;
  if (authOnly === "false") where.authRequired = false;
  if (projectId) where.scan = { projectId };

  const allEndpoints = await prisma.endpoint.findMany({
    where,
    orderBy: { path: "asc" },
    include: {
      scan: {
        select: { id: true, repository: true, createdAt: true },
      },
    },
  });

  // Apply quality filter + dedup
  let endpoints = quality === "api"
    ? allEndpoints.filter((ep) => isApiEndpoint(ep.path) && !isTestFile(ep.filePath))
    : allEndpoints;

  // Deduplicate within a repository. The same route in two services is a
  // distinct attack-surface node and must not be collapsed.
  // Keep the most metadata-rich entry (prefer auth, params, latest scan)
  if (quality === "api") {
    const bestByKey = new Map<string, typeof endpoints[number]>();
    for (const ep of endpoints) {
      const key = `${ep.repositoryId}:${ep.method}:${ep.path}`;
      const existing = bestByKey.get(key);
      if (!existing) {
        bestByKey.set(key, ep);
      } else {
        // Prefer: auth > params > newer scan
        const newScore =
          (ep.authRequired ? 4 : 0) +
          (ep.calledByFrontend ? 3 : 0) +
          (ep.exposedViaGateway ? 3 : 0) +
          (ep.runtimeObserved ? 4 : 0) +
          (ep.parameters ? 2 : 0) +
          (ep.framework ? 1 : 0);
        const oldScore =
          (existing.authRequired ? 4 : 0) +
          (existing.calledByFrontend ? 3 : 0) +
          (existing.exposedViaGateway ? 3 : 0) +
          (existing.runtimeObserved ? 4 : 0) +
          (existing.parameters ? 2 : 0) +
          (existing.framework ? 1 : 0);
        if (newScore > oldScore || (newScore === oldScore && ep.scan.createdAt > existing.scan.createdAt)) {
          bestByKey.set(key, ep);
        }
      }
    }
    endpoints = Array.from(bestByKey.values());
  }

  // Get unique frameworks for filter
  const frameworks = await prisma.endpoint.groupBy({
    by: ["framework"],
    where: { framework: { not: "" } },
  });

  return NextResponse.json({
    endpoints,
    total: endpoints.length,
    totalUnfiltered: allEndpoints.length,
    frameworks: frameworks.map((f) => f.framework),
  });
}
