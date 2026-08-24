import { NextRequest, NextResponse } from "next/server";

import { validateRuleYaml } from "@/lib/rule-validation";

export async function POST(request: NextRequest) {
  const body = await request.json();
  if (typeof body.yamlContent !== "string") {
    return NextResponse.json({ error: "yamlContent must be a string" }, { status: 400 });
  }
  if (body.expectedRuleId !== undefined && typeof body.expectedRuleId !== "string") {
    return NextResponse.json({ error: "expectedRuleId must be a string" }, { status: 400 });
  }
  const result = validateRuleYaml(body.yamlContent, body.expectedRuleId);
  return NextResponse.json(result, { status: result.valid ? 200 : 422 });
}
