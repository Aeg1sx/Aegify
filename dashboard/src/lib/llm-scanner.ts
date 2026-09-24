import { callProvider } from "./provider-client.ts";
import { getLLMConfig } from "./settings.ts";

// Repository analysis keeps its explicit request API. Finding review jobs run in llm-worker.ts.
export async function callLLM(systemPrompt: string, userPrompt: string, configured?: Awaited<ReturnType<typeof getLLMConfig>>): Promise<string> {
  return callProvider(configured || await getLLMConfig(), systemPrompt, userPrompt);
}
