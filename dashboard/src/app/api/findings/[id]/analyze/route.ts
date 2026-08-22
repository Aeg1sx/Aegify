import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { analyzeFinding } from "@/lib/llm";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  let language: string | undefined;
  try {
    const body = await request.json();
    language = body.language;
  } catch {
    // no body is fine, will use default from settings
  }

  const finding = await prisma.finding.findUnique({
    where: { id },
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
      },
      select: {
        qualifiedName: true,
        filePath: true,
        lineStart: true,
        lineEnd: true,
        nodeType: true,
        outEdges: {
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
        relatedNodes.map((n) => ({
          name: n.qualifiedName,
          type: n.nodeType,
          callsTo: n.outEdges.map((e) => ({
            target: e.targetNode.qualifiedName,
            targetFile: e.targetNode.filePath,
            line: e.callSiteLine,
          })),
          calledBy: n.inEdges.map((e) => ({
            source: e.sourceNode.qualifiedName,
            sourceFile: e.sourceNode.filePath,
            line: e.callSiteLine,
          })),
        }))
      );
    }
  } catch {
    // call graph query is best-effort
  }

  try {
    // Build enriched call chain by merging DB callChain + graph context
    let enrichedCallChain = finding.callChain;
    if (!enrichedCallChain && callGraphContext) {
      enrichedCallChain = callGraphContext;
    }

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
      callChain: enrichedCallChain,
      defenseContext: (finding as Record<string, unknown>).defenseContext as string | null ?? null,
    }, language);

    // Store the analysis as JSON in the llmAnalysis field
    await prisma.finding.update({
      where: { id },
      data: { llmAnalysis: JSON.stringify(result) },
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
