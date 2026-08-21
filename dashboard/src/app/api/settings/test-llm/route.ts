import { NextResponse } from "next/server";
import { testLLMConnection } from "@/lib/llm";

export async function POST() {
  const result = await testLLMConnection();
  return NextResponse.json(result, {
    status: result.success ? 200 : 400,
  });
}
