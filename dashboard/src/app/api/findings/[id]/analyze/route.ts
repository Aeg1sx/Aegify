import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { analyzeFinding } from "@/lib/llm";
import { reviewFindingSelect } from "@/lib/ai-review-contract";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const access = await requireResource(request, "finding", id, "maintainer");
  if (access instanceof Response) return access;

  let language: string | undefined;
  try {
    const body = await request.json();
    language = body.language;
  } catch {
    // no body is fine, will use default from settings
  }

  const finding = await prisma.finding.findUnique({
    where: { id },
    select: reviewFindingSelect,
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  // Query related call graph nodes for cross-file context
  let callGraphContext: string | null = null;
  try {
    const relatedNodes = await prisma.callGraphNode.findMany({
      where: {
        scanId: finding.scanId,
        filePath: finding.filePath,
        lineStart: { lte: finding.lineStart },
        lineEnd: { gte: finding.lineEnd },
      },
      take: 5,
      orderBy: [{ lineStart: "desc" }, { lineEnd: "asc" }, { id: "asc" }],
      select: {
        qualifiedName: true,
        filePath: true,
        lineStart: true,
        lineEnd: true,
        nodeType: true,
        outEdges: {
          take: 13,
          where: { scanId: finding.scanId, targetNode: { scanId: finding.scanId } },
          orderBy: [{ callSiteLine: "asc" }, { id: "asc" }],
          select: {
            targetNode: {
              select: {
                qualifiedName: true,
                filePath: true,
                lineStart: true,
                nodeType: true,
              },
            },
            callSiteLine: true,
          },
        },
        inEdges: {
          take: 13,
          where: { scanId: finding.scanId, sourceNode: { scanId: finding.scanId } },
          orderBy: [{ callSiteLine: "asc" }, { id: "asc" }],
          select: {
            sourceNode: {
              select: {
                qualifiedName: true,
                filePath: true,
                lineStart: true,
                nodeType: true,
              },
            },
            callSiteLine: true,
          },
        },
      },
    });

    if (relatedNodes.length > 0) {
      callGraphContext = JSON.stringify(
        relatedNodes.slice(0, 4).map((n) => ({
          file: n.filePath, lineStart: n.lineStart, lineEnd: n.lineEnd,
          contextLimited: relatedNodes.length > 4 || n.outEdges.length > 12 || n.inEdges.length > 12,
          name: n.qualifiedName,
          type: n.nodeType,
          callsTo: n.outEdges.slice(0, 12).map((e) => ({
            target: e.targetNode.qualifiedName,
            targetFile: e.targetNode.filePath,
            targetLine: e.targetNode.lineStart,
            callSiteLine: e.callSiteLine,
          })),
          calledBy: n.inEdges.slice(0, 12).map((e) => ({
            source: e.sourceNode.qualifiedName,
            sourceFile: e.sourceNode.filePath,
            sourceLine: e.sourceNode.lineStart,
            callSiteLine: e.callSiteLine,
          })),
        }))
      );
    }
  } catch {
    // call graph query is best-effort
  }

  try {
    const result = await analyzeFinding(finding, language, callGraphContext);

    // Store the analysis as JSON in the llmAnalysis field
    await prisma.finding.update({
      where: { id },
      data: {
        llmAnalysis: JSON.stringify(result),
        aiVerdict: result.verdict,
        aiConfidence: result.confidence,
        aiReviewStatus: "suggested",
        aiProof: JSON.stringify(result.proof),
      },
    });

    return NextResponse.json(result);
  } catch (err) {
    console.error("Finding analysis error:", err);
    return NextResponse.json(
      { error: "Analysis failed" },
      { status: 500 }
    );
  }
}
