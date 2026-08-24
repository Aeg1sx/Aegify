"use client";

import { useState } from "react";
import { AlertTriangle, Check, Clipboard, ShieldCheck, Sparkles } from "lucide-react";

import { CodeHighlight } from "@/components/code-highlight";
import { Markdown } from "@/components/markdown";
import { Separator } from "@/components/ui/separator";

export interface AIReviewView {
  verdict: "likely_true_positive" | "likely_false_positive" | "needs_review";
  analysis: string;
  remediation: string;
  riskAssessment: string;
  confidence: number;
  evidenceFor: string[];
  evidenceAgainst: string[];
  evidenceGaps: string[];
  attackScenario: string;
  fixedCode: string;
  remediationSteps: string[];
  proof: {
    safety: string;
    requiresApproval: boolean;
    preconditions: string[];
    requestTemplate: string;
    payloadTemplate: string;
    expectedSignal: string;
    negativeControl: string;
    harnessPlan: Record<string, unknown>;
  };
}

const VERDICT_LABELS: Record<AIReviewView["verdict"], string> = {
  likely_true_positive: "Likely true positive",
  likely_false_positive: "Likely false positive",
  needs_review: "Needs human review",
};

function EvidenceList({ title, values, tone }: {
  title: string;
  values: string[];
  tone: "positive" | "negative" | "gap";
}) {
  const colors = {
    positive: "border-emerald-500/20 bg-emerald-500/5",
    negative: "border-sky-500/20 bg-sky-500/5",
    gap: "border-amber-500/20 bg-amber-500/5",
  };
  return (
    <div className={`rounded-lg border p-3 ${colors[tone]}`}>
      <p className="mb-2 text-xs font-semibold uppercase tracking-wide">{title}</p>
      {values.length ? (
        <ul className="space-y-1.5 text-xs text-muted-foreground">
          {values.map((value, index) => <li key={index}>• {value}</li>)}
        </ul>
      ) : <p className="text-xs text-muted-foreground">No evidence supplied.</p>}
    </div>
  );
}

function CopyBlock({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="overflow-hidden rounded-md border bg-[#0d1117]">
      <div className="flex items-center justify-between border-b border-white/10 px-3 py-2 text-xs text-slate-300">
        <span>{label}</span>
        <button type="button" onClick={copy} className="flex items-center gap-1 hover:text-white">
          {copied ? <Check className="h-3 w-3" /> : <Clipboard className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap p-3 text-xs text-slate-200">{value}</pre>
    </div>
  );
}

export function AIEvidencePanel({ review, language }: { review: AIReviewView; language?: string }) {
  const verdictTone = review.verdict === "likely_true_positive"
    ? "bg-red-500/10 text-red-600"
    : review.verdict === "likely_false_positive"
      ? "bg-emerald-500/10 text-emerald-600"
      : "bg-amber-500/10 text-amber-600";
  const harnessPlan = Object.keys(review.proof.harnessPlan).length
    ? JSON.stringify(review.proof.harnessPlan, null, 2)
    : "";
  const hasProof = Boolean(
    review.proof.requestTemplate || review.proof.payloadTemplate ||
    review.proof.expectedSignal || review.proof.negativeControl ||
    review.proof.preconditions.length || harnessPlan,
  );
  return (
    <div className="space-y-5">
      <div className="rounded-xl border bg-gradient-to-br from-violet-500/10 via-background to-cyan-500/5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Sparkles className="h-4 w-4 text-violet-500" />
          <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${verdictTone}`}>
            {VERDICT_LABELS[review.verdict]}
          </span>
          <span className="text-xs text-muted-foreground">
            {(review.confidence * 100).toFixed(0)}% model confidence
          </span>
          <span className="ml-auto text-[11px] text-muted-foreground">Suggestion only · status unchanged</span>
        </div>
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-muted">
          <div className="h-full rounded-full bg-gradient-to-r from-violet-500 to-cyan-500" style={{ width: `${review.confidence * 100}%` }} />
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        <EvidenceList title="Evidence for" values={review.evidenceFor} tone="positive" />
        <EvidenceList title="Evidence against" values={review.evidenceAgainst} tone="negative" />
        <EvidenceList title="Evidence gaps" values={review.evidenceGaps} tone="gap" />
      </div>

      {review.analysis && <div><h4 className="mb-2 text-sm font-medium">Analysis</h4><Markdown content={review.analysis} /></div>}
      {review.riskAssessment && <p className="text-xs text-muted-foreground">Model risk assessment: <span className="font-medium text-foreground">{review.riskAssessment}</span></p>}
      {review.attackScenario && <div><h4 className="mb-2 text-sm font-medium">Bounded attack scenario</h4><Markdown content={review.attackScenario} /></div>}
      <Separator />
      <div className="space-y-3">
        <h4 className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="h-4 w-4" />Remediation</h4>
        {review.remediation && <Markdown content={review.remediation} />}
        {review.remediationSteps.length > 0 && (
          <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
            {review.remediationSteps.map((step, index) => <li key={index}>{step}</li>)}
          </ol>
        )}
        {review.fixedCode && <CodeHighlight code={review.fixedCode} language={language} />}
      </div>

      {hasProof && (
        <div className="space-y-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-4">
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
            <div>
              <p className="text-sm font-semibold">PoC / payload validation plan</p>
              <p className="text-xs text-muted-foreground">
                {review.proof.safety.replaceAll("_", " ")}. {review.proof.requiresApproval ? "Human approval is required before execution." : "Review before execution."}
              </p>
            </div>
          </div>
          {review.proof.preconditions.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
              {review.proof.preconditions.map((item, index) => <li key={index}>{item}</li>)}
            </ul>
          )}
          <CopyBlock label="Request template" value={review.proof.requestTemplate} />
          <CopyBlock label="Payload template" value={review.proof.payloadTemplate} />
          <CopyBlock label="Harness plan" value={harnessPlan} />
          <div className="grid gap-3 md:grid-cols-2">
            <div className="rounded-md border bg-background p-3"><p className="text-xs font-medium">Expected signal</p><p className="mt-1 text-xs text-muted-foreground">{review.proof.expectedSignal || "Not supplied"}</p></div>
            <div className="rounded-md border bg-background p-3"><p className="text-xs font-medium">Negative control</p><p className="mt-1 text-xs text-muted-foreground">{review.proof.negativeControl || "Not supplied"}</p></div>
          </div>
        </div>
      )}
    </div>
  );
}
