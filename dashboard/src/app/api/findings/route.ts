import { requireAccess, findingScope, scanScope } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { boundedInteger, invalidFindingScope, queueConditions } from "@/lib/finding-view";

export async function GET(request: NextRequest) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  const url = new URL(request.url);
  if (invalidFindingScope(url.searchParams)) {
    return NextResponse.json({ error: "Invalid scan or repository filter." }, { status: 400 });
  }
  const page = boundedInteger(url.searchParams.get("page"), 1, 100_000);
  const limit = boundedInteger(url.searchParams.get("limit"), 50, 100);
  const skip = (page - 1) * limit;

  const scanId = url.searchParams.get("scanId");
  const severity = url.searchParams.get("severity");
  const status = url.searchParams.get("status");
  const ruleId = url.searchParams.get("ruleId");
  const search = url.searchParams.get("search");
  const language = url.searchParams.get("language");
  const projectId = url.searchParams.get("projectId");
  const source = url.searchParams.get("source");
  const disposition = url.searchParams.get("disposition");
  const history = url.searchParams.get("history") === "true";

  const LANG_EXT_MAP: Record<string, string[]> = {
    Python: [".py"],
    JavaScript: [".js", ".jsx"],
    TypeScript: [".ts", ".tsx"],
    Java: [".java"],
    Go: [".go"],
    Rust: [".rs"],
    Kotlin: [".kt"],
    Swift: [".swift"],
    Ruby: [".rb"],
    PHP: [".php"],
    C: [".c"],
    "C++": [".cpp"],
    "C#": [".cs"],
  };

  const where: Record<string, unknown> = {};
  if (scanId) where.scanId = scanId;
  const repositoryId = url.searchParams.get("repositoryId");
  if (repositoryId) where.repositoryId = repositoryId;
  if (!scanId && !history) where.isCurrent = true;
  if (severity) where.severity = severity;
  if (status) where.status = status;
  const evidenceState = url.searchParams.get("evidenceState");
  if (["candidate", "reachable", "observed", "impact_proven"].includes(evidenceState || "")) where.evidenceState = evidenceState;
  const baselineState = url.searchParams.get("baselineState");
  if (["new", "regressed", "updated", "unchanged"].includes(baselineState || "")) where.baselineState = baselineState;
  if (ruleId) where.ruleId = ruleId;
  if (source) where.source = source;
  if (disposition === "blocking" || disposition === "advisory") {
    where.disposition = disposition;
  }
  if (projectId) where.scan = { projectId };
  if (language && LANG_EXT_MAP[language]) {
    where.OR = LANG_EXT_MAP[language].map((ext) => ({
      filePath: { endsWith: ext },
    }));
  }
  if (search) {
    const searchConditions = [
      { message: { contains: search } },
      { filePath: { contains: search } },
      { ruleName: { contains: search } },
    ];
    if (where.OR) {
      // Combine language filter with search using AND
      where.AND = [{ OR: where.OR }, { OR: searchConditions }];
      delete where.OR;
    } else {
      where.OR = searchConditions;
    }
  }

  const scoped = { AND: [where, findingScope(access), queueConditions(url.searchParams.get("queue"))] };
  const [findings, total, scan] = await Promise.all([
    prisma.finding.findMany({
      where: scoped,
      include: { scan: { select: { projectId: true } } },
      orderBy: url.searchParams.get("sort") === "file" ? [{ filePath: "asc" }, { lineStart: "asc" }, { id: "asc" }]
        : url.searchParams.get("sort") === "rule" ? [{ ruleName: "asc" }, { id: "asc" }]
        : [{ createdAt: url.searchParams.get("sort") === "oldest" ? "asc" : "desc" }, { id: "asc" }],
      skip,
      take: limit,
    }),
    prisma.finding.count({ where: scoped }),
    scanId ? prisma.scan.findFirst({
      where: { id: scanId, ...(projectId && { projectId }), ...scanScope(access) },
      select: { id: true, repository: true, branch: true, commitSha: true, createdAt: true, status: true },
    }) : null,
  ]);

  return NextResponse.json({ findings, total, page, limit, ...(scanId && { scan }) });
}
