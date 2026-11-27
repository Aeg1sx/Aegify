"use client";

import { useState } from "react";
import { AlertTriangle, Check, Clipboard, ShieldCheck, FileSearch } from "lucide-react";

import { RemediationComparison } from "./remediation-comparison";
import { Markdown } from "@/components/markdown";
import { Separator } from "@/components/ui/separator";
import { AIToolEvidence } from "@/components/finding/ai-tool-evidence";
import type { AIReviewEvidenceView } from "@/lib/ai-review-evidence";

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
  sourceEvidence?: AIReviewEvidenceView;
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
  const marker = { positive: "bg-primary", negative: "bg-muted-foreground", gap: "bg-[var(--severity-medium)]" };
  return <section className="min-w-0 px-4 py-3">
    <h4 className="mb-2 inline-flex items-center gap-2 text-sm font-semibold">
      <span aria-hidden className={`size-2 rounded-sm ${marker[tone]}`} />{title}
    </h4>
    {values.length
      ? <ul className="list-disc space-y-1.5 break-words pl-4 text-sm leading-relaxed">{values.map((value, index) => <li key={index}>{value}</li>)}</ul>
      : <p className="text-sm text-muted-foreground">None recorded</p>}
  </section>;
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
    <div className="overflow-hidden rounded-md border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border bg-muted px-3 text-xs text-muted-foreground">
        <span>{label}</span>
        <button type="button" onClick={copy} className="flex min-h-11 min-w-11 items-center gap-1 hover:text-foreground active:bg-accent focus-visible:outline-ring">
          {copied ? <Check className="h-3 w-3" /> : <Clipboard className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap p-3 text-xs text-foreground">{value}</pre>
    </div>
  );
}

export function AIEvidencePanel({ review, language, original }: { review: AIReviewView; language?: string; original: string }) {
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
      <div className="border-l-[3px] border-primary bg-muted/60 px-4 py-3">
        <h3 className="flex items-center gap-2 text-lg font-semibold tracking-tight"><FileSearch aria-hidden className="size-4 text-primary" />{VERDICT_LABELS[review.verdict]}</h3>
        <p className="mt-1.5 text-sm text-muted-foreground">AI review
          {review.sourceEvidence?.model && " · " + review.sourceEvidence.model}
          {review.verdict !== "needs_review" && ` · ${Math.round(review.confidence * 100)}% model estimate`}
        </p>
      </div>

      {review.analysis && <div className="max-w-prose"><h4 className="mb-2 text-sm font-medium">Analysis</h4><Markdown content={review.analysis} /></div>}

      <div className="divide-y border-y border-border">
        {review.verdict === "needs_review" && <EvidenceList title="Evidence gaps" values={review.evidenceGaps} tone="gap" />}
        {review.evidenceFor.length > 0 && <EvidenceList title="Evidence for" values={review.evidenceFor} tone="positive" />}
        {review.evidenceAgainst.length > 0 && <EvidenceList title="Evidence against" values={review.evidenceAgainst} tone="negative" />}
        {review.verdict !== "needs_review" && review.evidenceGaps.length > 0 && <EvidenceList title="Evidence gaps" values={review.evidenceGaps} tone="gap" />}
      </div>
      {review.riskAssessment && <p className="text-xs text-muted-foreground">Model risk assessment: <span className="font-medium text-foreground">{review.riskAssessment}</span></p>}
      {review.attackScenario && <div><h4 className="mb-2 text-sm font-medium">Bounded attack scenario</h4><Markdown content={review.attackScenario} /></div>}
      {(review.remediation || review.remediationSteps.length > 0 || review.fixedCode) && <>
      <Separator />
      <div className="space-y-3">
        <h4 className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="h-4 w-4" />Remediation</h4>
        {review.remediation && <Markdown content={review.remediation} />}
        {review.remediationSteps.length > 0 && (
          <ol className="list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
            {review.remediationSteps.map((step, index) => <li key={index}>{step}</li>)}
          </ol>
        )}
        {review.fixedCode && <RemediationComparison original={original} proposed={review.fixedCode} language={language} />}
      </div>

      </>}

      {review.sourceEvidence && <AIToolEvidence evidence={review.sourceEvidence} />}

      {hasProof && (
        <div className="space-y-3 rounded-md border border-border bg-muted/50 p-4">
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-[var(--severity-medium)]" />
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
