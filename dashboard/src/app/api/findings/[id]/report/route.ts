import { NextResponse } from "next/server";
import { accessError, requireAccess } from "@/lib/access";
import { buildFindingReport } from "@/lib/finding-report";
import { readFindingReport, reportETag } from "@/lib/finding-report-record";
import { prisma } from "@/lib/prisma";

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  try {
    const report = await readFindingReport(prisma, id, access.userId, process.env);
    const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
    if (!report) return NextResponse.json({ error: "Report not found." }, { status: 404, headers });
    const markdown = buildFindingReport(report);
    const etag = reportETag(markdown);
    if (new URL(request.url).searchParams.get("format") === "json") {
      return NextResponse.json(report, { headers: { ...headers, "X-Aegify-Markdown-ETag": etag } });
    }
    const expected = request.headers.get("If-Match");
    if (expected && expected !== "*" && !expected.split(",").some((token) => token.trim() === etag)) {
      return NextResponse.json({ error: "This report changed. Reload to see the latest decision." }, { status: 412, headers });
    }
    return new Response(markdown, { headers: {
      ...headers, ETag: etag, "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": 'attachment; filename="aegify-finding-report.md"',
    } });
  } catch (error) { return accessError(error); }
}
