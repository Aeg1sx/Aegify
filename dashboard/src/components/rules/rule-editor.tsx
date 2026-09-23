"use client";

import { useEffect, useRef, useState } from "react";
import { AlertCircle, CheckCircle2 } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";

interface Diagnostic { level: "error" | "warning"; message: string; line?: number; ruleId?: string }
interface Validation { valid: boolean; ruleCount: number; diagnostics: Diagnostic[] }
export function RuleEditor({ value, originalValue, expectedRuleId, onChange, onValidityChange }: {
  value: string; originalValue?: string; expectedRuleId?: string;
  onChange: (value: string) => void; onValidityChange?: (valid: boolean) => void;
}) {
  const [mode, setMode] = useState<"edit" | "split" | "compare">("split");
  const [result, setResult] = useState<{ value: string; expectedRuleId?: string; validation: Validation } | null>(null);
  const [selectedLine, setSelectedLine] = useState<number>();
  const textarea = useRef<HTMLTextAreaElement>(null);
  const validity = useRef(onValidityChange);
  useEffect(() => { validity.current = onValidityChange; }, [onValidityChange]);
  const validation = result?.value === value && result?.expectedRuleId === expectedRuleId ? result.validation : null;
  useEffect(() => {
    const controller = new AbortController();
    // A previous valid response must not enable saving an unvalidated draft.
    validity.current?.(false);
    const timeout = setTimeout(async () => {
      try {
        const response = await fetch("/api/rules/validate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ yamlContent: value, expectedRuleId }), signal: controller.signal,
        });
        const data = await response.json();
        const next: Validation = Array.isArray(data.diagnostics) ? data : { valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: data.error || "Validation failed." }] };
        next.valid = response.ok && next.valid === true;
        if (!controller.signal.aborted) { setResult({ value, expectedRuleId, validation: next }); validity.current?.(next.valid); }
      } catch {
        if (!controller.signal.aborted) {
          setResult({ value, expectedRuleId, validation: { valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: "Validation request failed. Check the connection and edit to retry." }] } });
          validity.current?.(false);
        }
      }
    }, 300);
    return () => { clearTimeout(timeout); controller.abort(); };
  }, [value, expectedRuleId]);

  const goToLine = (line: number) => {
    setSelectedLine(line);
    const start = value.split("\n").slice(0, line - 1).reduce((offset, text) => offset + text.length + 1, 0);
    textarea.current?.focus();
    textarea.current?.setSelectionRange(start, start + (value.split("\n")[line - 1]?.length || 0));
    if (textarea.current) textarea.current.scrollTop = Math.max(0, (line - 4) * 24);
  };
  return <section className="workbench-panel" aria-label="Rule authoring workbench">
    <div className="workbench-heading">
      <div className="flex items-center gap-1">{(["edit", "split", ...(originalValue !== undefined ? ["compare"] : [])] as const).map((tab) => <button type="button" key={tab} aria-pressed={mode === tab} onClick={() => setMode(tab as typeof mode)} className={"rounded px-3 py-1.5 text-xs capitalize " + (mode === tab ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent")}>{tab === "compare" ? "Before / draft" : tab}</button>)}</div>
      <span className={"flex items-center gap-1.5 text-xs " + (validation?.valid ? "text-emerald-600 dark:text-emerald-400" : "text-muted-foreground")}>{validation?.valid ? <CheckCircle2 className="h-3.5 w-3.5" /> : <AlertCircle className="h-3.5 w-3.5" />}{validation ? validation.valid ? "Structure checked · " + validation.ruleCount + " rules" : "Changes need attention" : "Validation pending…"}</span>
    </div>
    <div className={"grid min-w-0 " + (mode !== "edit" ? "xl:grid-cols-2" : "")}>
      {mode === "compare" ? <div className="min-w-0 border-r border-border p-3"><p className="eyebrow mb-3">Saved definition</p><CodeHighlight code={originalValue || ""} language="yaml" /></div> : <div className="min-w-0 border-r border-border bg-[#11151c]">
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-2 text-xs text-slate-400"><span className="font-mono">{expectedRuleId || "New rule"}.yml</span><span>{value.split("\n").length} lines · YAML</span></div>
        <textarea ref={textarea} value={value} onChange={(event) => { validity.current?.(false); onChange(event.target.value); }} className="h-[480px] w-full resize-y bg-transparent p-4 font-mono text-[13px] leading-6 text-slate-200 outline-none" spellCheck={false} wrap="off" aria-label="Rule YAML editor" />
      </div>}
      {mode !== "edit" && <div className="min-w-0 p-3"><p className="eyebrow mb-3">{mode === "compare" ? "Current draft · not saved" : "Syntax preview · click a line to edit"}</p><CodeHighlight code={value} language="yaml" selectedLine={selectedLine} onLineSelect={goToLine} /></div>}
    </div>
    <div className="border-t border-border bg-muted/30 p-4">
      <div className="mb-3 flex items-center justify-between"><h3 className="eyebrow">Diagnostics · {validation?.diagnostics.length ?? "…"}</h3><span className="text-[11px] text-muted-foreground">Syntax &amp; structure only · detector semantics not executed</span></div>
      <div className="max-h-52 space-y-2 overflow-auto" role="status" aria-live="polite">
        {validation?.diagnostics.map((diagnostic, index) => <button type="button" key={index} disabled={!diagnostic.line} onClick={() => { if (diagnostic.line) goToLine(diagnostic.line); }} className={"flex w-full items-start gap-3 rounded border px-3 py-2 text-left text-xs " + (diagnostic.level === "error" ? "border-destructive/20 text-destructive" : "border-amber-500/20 text-amber-700 dark:text-amber-300")}><span className="w-14 shrink-0 font-mono">{diagnostic.line ? "L" + diagnostic.line : diagnostic.level}</span><span>{diagnostic.message}</span></button>)}
        {validation?.diagnostics.length === 0 && <p className="text-xs text-muted-foreground">No structural issues. Run the scanner's fixture tests before enabling a changed detector.</p>}
      </div>
    </div>
  </section>;
}
