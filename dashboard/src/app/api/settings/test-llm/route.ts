import { requireAccess } from "@/lib/access";
import { NextResponse } from "next/server";
import { testLLMConnection } from "@/lib/llm";

export async function POST(request: Request) {
  const access = await requireAccess(request, true);
  if (access instanceof Response) return access;
  const result = await testLLMConnection();
  return NextResponse.json(result, {
    status: result.success ? 200 : 400,
  });
}
