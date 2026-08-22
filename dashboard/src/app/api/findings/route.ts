import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  const url = new URL(request.url);
  const page = parseInt(url.searchParams.get("page") || "1", 10);
  const limit = parseInt(url.searchParams.get("limit") || "50", 10);
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
  if (severity) where.severity = severity;
  if (status) where.status = status;
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

  const [findings, total] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy: [{ severity: "asc" }, { createdAt: "desc" }],
      skip,
      take: limit,
    }),
    prisma.finding.count({ where }),
  ]);

  return NextResponse.json({ findings, total, page, limit });
}
