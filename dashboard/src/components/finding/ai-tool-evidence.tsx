import type { AIReviewEvidenceView } from "@/lib/ai-review-evidence";

const STOP_LABELS: Record<string, string> = {
  final_review: "Review returned",
  tool_limit: "Tool budget reached",
  round_limit: "Round budget reached",
  prompt_limit: "Prompt budget reached",
  evidence_limit: "Evidence budget reached",
  invalid_citation: "Unsupported source reference",
  invalid_response: "Invalid model response",
  model_error: "Model unavailable",
};

export function AIToolEvidence({ evidence }: { evidence: AIReviewEvidenceView }) {
  if (!evidence.tools.length && !evidence.references.length && !evidence.modelCalls && !evidence.stopReason) return null;
  return (
    <section aria-label="AI source evidence and tool activity" className="space-y-4 rounded-xl border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h4 className="text-sm font-semibold">Source evidence &amp; tool activity</h4>
          <p className="mt-1 text-xs text-muted-foreground">
            {evidence.model || "Scanner reviewer"} · {evidence.modelCalls} model calls · {evidence.tools.length} tool calls
          </p>
        </div>
        {evidence.stopReason && <span className="rounded-full bg-muted px-2.5 py-1 text-xs">{STOP_LABELS[evidence.stopReason] || "Review stopped"}</span>}
      </div>
      <p className="text-xs text-muted-foreground">Source references identify the code read during this review. They do not establish runtime impact.</p>
      {evidence.references.length > 0 ? (
        <div className="space-y-2" aria-label="Source references">
          {evidence.references.map((reference, index) => (
            <details key={`${reference.id}-${index}`} className="group rounded-lg border bg-muted/20">
              <summary className="cursor-pointer px-3 py-2 text-xs">
                <span className="font-mono break-all">{reference.repository} / {reference.path}:{reference.lineStart}–{reference.lineEnd}</span>
                <span className="ml-2 text-muted-foreground">{reference.requestId} · Read code</span>
              </summary>
              <div className="space-y-2 border-t p-3">
                {reference.excerpt ? <pre className="max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{reference.excerpt.split("\n").map((line, offset) => `${String(reference.lineStart + offset).padStart(4)}  ${line}`).join("\n")}</pre>
                  : <p className="text-xs text-muted-foreground">The matching source excerpt was not retained in this report.</p>}
                <p className="break-all font-mono text-[11px] text-muted-foreground">Source: {reference.sourceDigest}</p>
                <p className="break-all font-mono text-[11px] text-muted-foreground">Excerpt: {reference.excerptDigest}</p>
              </div>
            </details>
          ))}
        </div>
      ) : <p className="text-xs text-muted-foreground">No source references retained. Inspect the evidence gaps before triage.</p>}
      <div className="space-y-1.5" aria-label="Tool activity">
        {evidence.tools.map((tool, index) => (
          <details key={`${tool.requestId}-${index}`} className="rounded-md border">
            <summary className="cursor-pointer px-3 py-2 text-xs">
              <span className="font-mono">{tool.requestId || `Tool ${index + 1}`} · {tool.name}</span>
              <span className={`ml-2 ${!tool.ok || tool.truncated ? "text-amber-700 dark:text-amber-400" : "text-muted-foreground"}`}>
                {!tool.ok ? "Failed" : tool.truncated ? "Truncated" : "Returned"}{tool.cached ? " · Cached" : ""} · {tool.durationMs.toFixed(1)} ms
              </span>
            </summary>
            <div className="space-y-2 border-t p-3 text-xs">
              <p>Round {tool.round}{tool.summary ? ` · ${tool.summary}` : ""}</p>
              <pre className="max-h-48 overflow-auto rounded-md bg-muted p-3">{tool.arguments}</pre>
              {tool.inputDigest && <p className="break-all font-mono text-[11px] text-muted-foreground">Input: {tool.inputDigest}</p>}
              {tool.outputDigest && <p className="break-all font-mono text-[11px] text-muted-foreground">Result: {tool.outputDigest}</p>}
            </div>
          </details>
        ))}
      </div>
      {(evidence.sourceManifest || evidence.promptDigest) && <details className="text-xs text-muted-foreground">
        <summary className="cursor-pointer">Review provenance</summary>
        <div className="mt-2 space-y-1 break-all font-mono text-[11px]">
          {evidence.sourceManifest && <p>Source manifest: {evidence.sourceManifest}</p>}
          {evidence.promptDigest && <p>Prompt: {evidence.promptDigest}</p>}
          <p>Prompt bytes across calls: {evidence.promptBytes.toLocaleString()}</p>
        </div>
      </details>}
    </section>
  );
}
