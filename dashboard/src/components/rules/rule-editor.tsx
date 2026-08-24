"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertCircle, CheckCircle2, Code2, Eye } from "lucide-react";

import { YamlHighlight } from "@/components/code-highlight";

interface Diagnostic {
  level: "error" | "warning";
  message: string;
  line?: number;
  ruleId?: string;
}

interface Validation {
  valid: boolean;
  ruleCount: number;
  diagnostics: Diagnostic[];
}

export function RuleEditor({ value, expectedRuleId, onChange, onValidityChange }: {
  value: string;
  expectedRuleId?: string;
  onChange: (value: string) => void;
  onValidityChange?: (valid: boolean) => void;
}) {
  const [tab, setTab] = useState<"edit" | "preview">("edit");
  const [validation, setValidation] = useState<Validation | null>(null);
  const [validating, setValidating] = useState(false);
  const lineNumbers = useMemo(() => Array.from({ length: Math.max(1, value.split("\n").length) }), [value]);

  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(async () => {
      setValidating(true);
      try {
        const response = await fetch("/api/rules/validate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ yamlContent: value, expectedRuleId }),
          signal: controller.signal,
        });
        const result = await response.json() as Validation;
        setValidation(result);
        onValidityChange?.(result.valid);
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setValidation({ valid: false, ruleCount: 0, diagnostics: [{ level: "error", message: "Validation request failed." }] });
          onValidityChange?.(false);
        }
      } finally {
        setValidating(false);
      }
    }, 300);
    return () => {
      clearTimeout(timeout);
      controller.abort();
    };
  }, [value, expectedRuleId, onValidityChange]);

  return (
    <div className="overflow-hidden rounded-xl border bg-[#0d1117]">
      <div className="flex items-center justify-between border-b border-white/10 bg-[#161b22] px-3 py-2">
        <div className="flex gap-1">
          <button type="button" onClick={() => setTab("edit")} className={`flex items-center gap-1 rounded px-2 py-1 text-xs ${tab === "edit" ? "bg-white/10 text-white" : "text-slate-400"}`}><Code2 className="h-3 w-3" />Editor</button>
          <button type="button" onClick={() => setTab("preview")} className={`flex items-center gap-1 rounded px-2 py-1 text-xs ${tab === "preview" ? "bg-white/10 text-white" : "text-slate-400"}`}><Eye className="h-3 w-3" />Preview</button>
        </div>
        <div className="flex items-center gap-2 text-xs">
          {validating ? <span className="text-slate-400">Validating…</span> : validation?.valid ? (
            <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 className="h-3.5 w-3.5" />{validation.ruleCount} rule{validation.ruleCount === 1 ? "" : "s"} valid</span>
          ) : <span className="flex items-center gap-1 text-red-400"><AlertCircle className="h-3.5 w-3.5" />Validation required</span>}
        </div>
      </div>

      {tab === "edit" ? (
        <div className="grid max-h-[560px] min-h-80 grid-cols-[48px_1fr] overflow-auto">
          <div className="select-none border-r border-white/10 bg-[#0d1117] px-2 py-4 text-right font-mono text-xs leading-6 text-slate-600">
            {lineNumbers.map((_, index) => <div key={index}>{index + 1}</div>)}
          </div>
          <textarea
            value={value}
            onChange={(event) => onChange(event.target.value)}
            className="min-h-80 w-full resize-y bg-[#0d1117] p-4 font-mono text-xs leading-6 text-[#c9d1d9] outline-none"
            spellCheck={false}
            aria-label="Rule YAML editor"
          />
        </div>
      ) : (
        <div className="max-h-[560px] min-h-80 overflow-auto p-3"><YamlHighlight code={value} /></div>
      )}

      {validation && validation.diagnostics.length > 0 && (
        <div className="max-h-48 space-y-1 overflow-auto border-t border-white/10 bg-[#161b22] p-3" role="status" aria-live="polite">
          {validation.diagnostics.map((diagnostic, index) => (
            <div key={index} className={`flex gap-2 text-xs ${diagnostic.level === "error" ? "text-red-400" : "text-amber-400"}`}>
              <span className="w-14 shrink-0 uppercase">{diagnostic.level}</span>
              <span>{diagnostic.line ? `L${diagnostic.line}: ` : ""}{diagnostic.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
