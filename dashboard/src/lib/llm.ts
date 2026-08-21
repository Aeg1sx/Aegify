import { getLLMConfig } from "@/lib/settings";

interface FindingContext {
  ruleId: string;
  ruleName: string;
  severity: string;
  message: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  cweId: number | null;
  owaspCategory: string | null;
  taintFlow: string | null;
  callChain: string | null;
  defenseContext: string | null;
}

interface LLMResponse {
  analysis: string;
  remediation: string;
  riskAssessment: string;
  confidence: number;
}

const LANGUAGE_INSTRUCTIONS: Record<string, string> = {
  en: "Write your entire response (analysis and remediation) in English.",
  ko: "analysis와 remediation 필드를 한국어로 작성하세요. riskAssessment는 반드시 영어(CRITICAL, HIGH, MEDIUM, LOW, FALSE_POSITIVE)로 유지하세요.",
  ja: "analysisとremediationフィールドは日本語で記述してください。riskAssessmentは必ず英語（CRITICAL, HIGH, MEDIUM, LOW, FALSE_POSITIVE）で維持してください。",
  zh: "请用中文撰写analysis和remediation字段。riskAssessment必须保持英文（CRITICAL, HIGH, MEDIUM, LOW, FALSE_POSITIVE）。",
};

function getSystemPrompt(language: string): string {
  const langInstruction = LANGUAGE_INSTRUCTIONS[language] || LANGUAGE_INSTRUCTIONS.en;

  return `You are a senior application security engineer performing code review. Analyze security findings from a SAST (Static Application Security Testing) scanner and provide actionable remediation guidance.

Your response must be in the following JSON format:
{
  "analysis": "Detailed explanation of the vulnerability, attack vectors, and potential impact",
  "remediation": "Specific, actionable code-level fix with examples",
  "riskAssessment": "One of: CRITICAL, HIGH, MEDIUM, LOW, FALSE_POSITIVE - your independent assessment",
  "confidence": 0.0-1.0
}

Guidelines:
- Be precise and technical. Reference CWE/OWASP where relevant.
- Provide concrete code examples for the fix, not generic advice.
- If the taint flow is provided, trace the data path and explain each step.
- If the code snippet shows proper sanitization or the finding appears to be a false positive, say so clearly.
- Consider the language and framework context when suggesting fixes.
- Keep analysis concise but thorough (max 3-4 paragraphs for analysis, max 2-3 paragraphs with code for remediation).
- If defense context is provided, use it to assess whether the vulnerability is mitigated.
- If a structured call chain with file paths and code snippets is provided, trace the full data flow.
- DO NOT say "cannot determine without more context" if call chain, taint flow, or defense context IS provided.
- If auth is present on the endpoint, factor this into your risk assessment.

IMPORTANT - Output language: ${langInstruction}`;
}

function buildUserPrompt(finding: FindingContext): string {
  let prompt = `Analyze this security finding:

**Rule**: ${finding.ruleId} - ${finding.ruleName}
**Severity**: ${finding.severity}
**CWE**: ${finding.cweId ? `CWE-${finding.cweId}` : "N/A"}
**OWASP**: ${finding.owaspCategory || "N/A"}
**File**: ${finding.filePath}:${finding.lineStart}-${finding.lineEnd}
**Message**: ${finding.message}`;

  if (finding.codeSnippet) {
    const ext = finding.filePath.split(".").pop() || "";
    prompt += `\n\n**Code**:\n\`\`\`${ext}\n${finding.codeSnippet}\n\`\`\``;
  }

  if (finding.taintFlow) {
    try {
      const flow = JSON.parse(finding.taintFlow);
      if (Array.isArray(flow) && flow.length > 0) {
        prompt += "\n\n**Taint Flow**:";
        for (const step of flow) {
          prompt += `\n- ${step.file}:${step.line} - ${step.message}`;
        }
      }
    } catch {
      // ignore parse errors
    }
  }

  if (finding.callChain) {
    try {
      const chain = JSON.parse(finding.callChain);
      if (Array.isArray(chain) && chain.length > 0) {
        prompt += "\n\n**Call Chain** (entry point -> vulnerability):";
        for (let i = 0; i < chain.length; i++) {
          const node = chain[i];
          if (typeof node === "string") {
            // Legacy format: plain function name strings
            prompt += `\n${i + 1}. ${node}`;
          } else {
            // Rich format: { function, filePath, line, snippet }
            const label = i === 0 ? " <- entry point" : i === chain.length - 1 ? " <- SINK" : "";
            prompt += `\n${i + 1}. ${node.function} (${node.filePath || "?"}:${node.line || "?"})${label}`;
            if (node.snippet) {
              prompt += `\n   \`${node.snippet.trim()}\``;
            }
          }
        }
      }
    } catch {
      // ignore parse errors
    }
  }

  if (finding.defenseContext) {
    try {
      const dc = JSON.parse(finding.defenseContext);
      prompt += "\n\n**Defense Analysis**:";
      prompt += `\n- Auth: ${dc.authPresent ? (dc.authDecorator || "Present") : "None detected"}`;
      prompt += `\n- Sanitizer: ${dc.sanitizerPresent ? (dc.sanitizerFunction || "Present") : "None detected"}`;
      prompt += `\n- Parameterized Query: ${dc.parameterizedQuery ? "Yes" : "No"}`;
      prompt += `\n- Input Validation: ${dc.inputValidation ? "Yes" : "No"}`;
      if (dc.endpoint) {
        prompt += `\n- Endpoint: ${dc.endpoint}`;
      }
    } catch {
      // ignore parse errors
    }
  }

  return prompt;
}

async function callAnthropic(
  apiKey: string,
  model: string,
  systemPrompt: string,
  userPrompt: string,
  endpoint?: string,
  headers?: Record<string, string>,
): Promise<string> {
  const isCustomEndpoint = !!endpoint;
  const baseUrl = (endpoint || "https://api.anthropic.com").replace(/\/+$/, "");
  const url = baseUrl.endsWith("/v1/messages") ? baseUrl : `${baseUrl}/v1/messages`;

  const reqHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (isCustomEndpoint) {
    // Custom endpoint (AI gateway): only send Content-Type + user's custom headers.
    // The gateway handles auth/routing via the user's custom headers.
  } else {
    // Direct Anthropic API: include provider-specific headers
    reqHeaders["anthropic-version"] = "2023-06-01";
    if (apiKey) {
      reqHeaders["x-api-key"] = apiKey;
    }
  }

  const res = await fetch(url, {
    method: "POST",
    headers: { ...reqHeaders, ...headers },
    body: JSON.stringify({
      model,
      max_tokens: 2048,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Anthropic API error ${res.status}: ${body}`);
  }

  const data = await res.json();
  return data.content?.[0]?.text || "";
}

async function callOpenAI(
  apiKey: string,
  model: string,
  systemPrompt: string,
  userPrompt: string,
  endpoint?: string,
  headers?: Record<string, string>,
): Promise<string> {
  const isCustomEndpoint = !!endpoint;
  const baseUrl = (endpoint || "https://api.openai.com").replace(/\/+$/, "");
  const url = baseUrl.endsWith("/v1/chat/completions") ? baseUrl : `${baseUrl}/v1/chat/completions`;

  const reqHeaders: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (isCustomEndpoint) {
    // Custom endpoint (AI gateway): only send Content-Type + user's custom headers.
  } else {
    // Direct OpenAI API: include provider-specific auth header
    if (apiKey) {
      reqHeaders["Authorization"] = `Bearer ${apiKey}`;
    }
  }

  const res = await fetch(url, {
    method: "POST",
    headers: { ...reqHeaders, ...headers },
    body: JSON.stringify({
      model,
      max_tokens: 2048,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${body}`);
  }

  const data = await res.json();
  return data.choices?.[0]?.message?.content || "";
}

function extractJson(raw: string): string {
  // Strategy 1: Try raw string directly
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) return trimmed;

  // Strategy 2: Find outermost { ... } by brace matching
  // This handles JSON wrapped in markdown code blocks that contain inner code blocks
  const firstBrace = raw.indexOf("{");
  const lastBrace = raw.lastIndexOf("}");
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    return raw.slice(firstBrace, lastBrace + 1);
  }

  return raw;
}

function parseResponse(raw: string): LLMResponse {
  const jsonStr = extractJson(raw);

  try {
    const parsed = JSON.parse(jsonStr);
    return {
      analysis: parsed.analysis || "",
      remediation: parsed.remediation || "",
      riskAssessment: parsed.riskAssessment || "MEDIUM",
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.5,
    };
  } catch {
    // If JSON parsing fails, treat the whole response as analysis
    return {
      analysis: raw,
      remediation: "",
      riskAssessment: "MEDIUM",
      confidence: 0.5,
    };
  }
}

export async function analyzeFinding(finding: FindingContext, languageOverride?: string): Promise<LLMResponse> {
  const config = await getLLMConfig();

  if (!config.enabled) {
    throw new Error("LLM analysis is not enabled. Configure it in Settings.");
  }

  const userPrompt = buildUserPrompt(finding);
  const systemPrompt = getSystemPrompt(languageOverride || config.language);
  let rawResponse: string;

  const hasCustomEndpoint = !!config.customEndpoint;
  const hasCustomHeaders = Object.keys(config.customHeaders).length > 0;

  if (config.provider === "anthropic") {
    if (!config.anthropicApiKey && !hasCustomEndpoint) {
      throw new Error("Anthropic API key is not configured. Set an API key or configure a custom endpoint.");
    }
    rawResponse = await callAnthropic(
      config.anthropicApiKey,
      config.model,
      systemPrompt,
      userPrompt,
      config.customEndpoint || undefined,
      hasCustomHeaders ? config.customHeaders : undefined,
    );
  } else if (config.provider === "openai") {
    if (!config.openaiApiKey && !hasCustomEndpoint) {
      throw new Error("OpenAI API key is not configured. Set an API key or configure a custom endpoint.");
    }
    rawResponse = await callOpenAI(
      config.openaiApiKey,
      config.model,
      systemPrompt,
      userPrompt,
      config.customEndpoint || undefined,
      hasCustomHeaders ? config.customHeaders : undefined,
    );
  } else {
    throw new Error(`Unsupported LLM provider: ${config.provider}`);
  }

  return parseResponse(rawResponse);
}

export async function testLLMConnection(): Promise<{ success: boolean; message: string }> {
  const config = await getLLMConfig();

  if (!config.enabled) {
    return { success: false, message: "LLM analysis is not enabled." };
  }

  try {
    const testPrompt = "Respond with exactly: {\"status\": \"ok\"}";
    const hasCustomEndpoint = !!config.customEndpoint;
    const hasCustomHeaders = Object.keys(config.customHeaders).length > 0;

    if (config.provider === "anthropic") {
      if (!config.anthropicApiKey && !hasCustomEndpoint) {
        return { success: false, message: "Anthropic API key is not configured. Set an API key or configure a custom endpoint." };
      }
      await callAnthropic(
        config.anthropicApiKey,
        config.model,
        "You are a test assistant.",
        testPrompt,
        config.customEndpoint || undefined,
        hasCustomHeaders ? config.customHeaders : undefined,
      );
    } else if (config.provider === "openai") {
      if (!config.openaiApiKey && !hasCustomEndpoint) {
        return { success: false, message: "OpenAI API key is not configured. Set an API key or configure a custom endpoint." };
      }
      await callOpenAI(
        config.openaiApiKey,
        config.model,
        "You are a test assistant.",
        testPrompt,
        config.customEndpoint || undefined,
        hasCustomHeaders ? config.customHeaders : undefined,
      );
    } else {
      return { success: false, message: `Unsupported provider: ${config.provider}` };
    }

    const endpointInfo = hasCustomEndpoint ? ` via ${config.customEndpoint}` : "";
    return { success: true, message: `Connected to ${config.provider} (${config.model})${endpointInfo}` };
  } catch (err) {
    return {
      success: false,
      message: err instanceof Error ? err.message : "Connection failed",
    };
  }
}
