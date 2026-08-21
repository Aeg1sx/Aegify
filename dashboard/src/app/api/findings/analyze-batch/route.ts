import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { analyzeFinding } from "@/lib/llm";

export async function POST(request: NextRequest) {
  const body = await request.json();
  const ids: string[] = body.ids;

  if (!Array.isArray(ids) || ids.length === 0) {
    return NextResponse.json({ error: "No finding IDs provided" }, { status: 400 });
  }

  if (ids.length > 100) {
    return NextResponse.json({ error: "Maximum 100 findings per batch" }, { status: 400 });
  }

  const findings = await prisma.finding.findMany({
    where: { id: { in: ids } },
  });

  if (findings.length === 0) {
    return NextResponse.json({ error: "No findings found" }, { status: 404 });
  }

  // Process concurrently with concurrency limit of 3
  const results: Record<string, { success: boolean; data?: unknown; error?: string }> = {};
  const CONCURRENCY = 3;

  const queue = [...findings];
  const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
    while (queue.length > 0) {
      const finding = queue.shift()!;
      try {
        const result = await analyzeFinding({
          ruleId: finding.ruleId,
          ruleName: finding.ruleName,
          severity: finding.severity,
          message: finding.message,
          filePath: finding.filePath,
          lineStart: finding.lineStart,
          lineEnd: finding.lineEnd,
          codeSnippet: finding.codeSnippet,
          cweId: finding.cweId,
          owaspCategory: finding.owaspCategory,
          taintFlow: finding.taintFlow,
          callChain: finding.callChain,
          defenseContext: (finding as Record<string, unknown>).defenseContext as string | null ?? null,
        });

        await prisma.finding.update({
          where: { id: finding.id },
          data: { llmAnalysis: JSON.stringify(result) },
        });

        results[finding.id] = { success: true, data: result };
      } catch (err) {
        results[finding.id] = {
          success: false,
          error: err instanceof Error ? err.message : "Analysis failed",
        };
      }
    }
  });

  await Promise.all(workers);

  const successCount = Object.values(results).filter((r) => r.success).length;
  const failCount = Object.values(results).filter((r) => !r.success).length;

  return NextResponse.json({
    results,
    summary: {
      total: findings.length,
      success: successCount,
      failed: failCount,
    },
  });
}
