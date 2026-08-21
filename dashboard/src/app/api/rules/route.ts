import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  const rules = await prisma.rule.findMany({
    orderBy: [{ findingCount: "desc" }, { id: "asc" }],
  });

  return NextResponse.json({ rules });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    if (!body.id || !body.name || !body.severity) {
      return NextResponse.json(
        { error: "id, name, and severity are required" },
        { status: 400 }
      );
    }

    // Validate severity
    if (!["critical", "high", "medium", "low"].includes(body.severity)) {
      return NextResponse.json(
        { error: "severity must be critical, high, medium, or low" },
        { status: 400 }
      );
    }

    const rule = await prisma.rule.create({
      data: {
        id: body.id,
        name: body.name,
        severity: body.severity,
        cweId: body.cweId || null,
        owaspCategory: body.owaspCategory || null,
        languages: body.languages || "",
        enabled: body.enabled ?? true,
        findingCount: 0,
        description: body.description || "",
        yamlContent: body.yamlContent || "",
      },
    });

    return NextResponse.json({ rule }, { status: 201 });
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes("Unique constraint")
    ) {
      return NextResponse.json(
        { error: "Rule with this ID already exists" },
        { status: 409 }
      );
    }
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to create rule" },
      { status: 500 }
    );
  }
}
