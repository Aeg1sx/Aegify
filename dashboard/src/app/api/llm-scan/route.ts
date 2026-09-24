import { queueLlmReview } from "@/lib/llm-job-http";

// Compatibility endpoint; both review entry points use the same durable queue.
export async function POST(request: Request) { return queueLlmReview(request, true); }
