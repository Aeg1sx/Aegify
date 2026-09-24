"use client";

import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";

interface Source { path: string; content: string }
interface Expected { rule_id: string; file_path: string; line_start: number }
interface Case { id: string; files: Source[]; expected: Expected[] }
interface Suite { schema_version: 1; suite_id: string; suite_version: string; rule_id: string; cases: Case[] }
function editableSuite(raw: string): Suite | null {
  try {
    const value = JSON.parse(raw);
    if (!value || value.schema_version !== 1 || [value.suite_id, value.suite_version, value.rule_id].some((item) => typeof item !== "string") || !Array.isArray(value.cases) || value.cases.length > 20 || !value.cases.every((item: Case) => item && typeof item.id === "string" && Array.isArray(item.files) && item.files.length <= 12 && item.files.every((file) => file && typeof file.path === "string" && typeof file.content === "string") && Array.isArray(item.expected) && item.expected.length <= 100 && item.expected.every((expected) => expected && typeof expected.rule_id === "string" && typeof expected.file_path === "string" && Number.isSafeInteger(expected.line_start)))) return null;
    return value;
  } catch { return null; }
}
const fieldClass = "w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs";
export function FixtureSuiteEditor({ value, onChange, disabled }: { value: string; onChange: (value: string) => void; disabled: boolean }) {
  const [mode, setMode] = useState<"guided" | "json">("guided");
  const [selected, setSelected] = useState(0);
  const suite = useMemo(() => editableSuite(value), [value]);
  const index = Math.min(selected, Math.max(0, (suite?.cases.length || 1) - 1));
  const current = suite?.cases[index];
  const update = (next: Suite) => onChange(JSON.stringify(next, null, 2) + "\n");
  const updateCase = (next: Case) => { if (suite) update({ ...suite, cases: suite.cases.map((item, position) => position === index ? next : item) }); };
  const addCase = () => {
    if (!suite || suite.cases.length >= 20) return;
    let suffix = suite.cases.length + 1;
    while (suite.cases.some((item) => item.id === `case-${suffix}`)) suffix++;
    update({ ...suite, cases: [...suite.cases, { id: `case-${suffix}`, files: [{ path: "main.py", content: "def example():\n    return 'constant'\n" }], expected: [] }] });
    setSelected(suite.cases.length);
  };
  return <section className="workbench-panel min-w-0" aria-label="Fixture suite editor">
    <div className="workbench-heading flex-wrap gap-2"><h2 className="font-semibold">2. Source examples</h2><div className="flex gap-1">{(["guided", "json"] as const).map((item) => <Button key={item} type="button" size="sm" variant={mode === item ? "secondary" : "ghost"} onClick={() => setMode(item)} aria-pressed={mode === item}>{item === "guided" ? "Cases & files" : "Suite JSON"}</Button>)}</div></div>
    <p className="border-b border-border px-4 py-3 text-xs text-muted-foreground">Use at least one positive and two close negative cases. Expected findings match the rule, file and exact start line.</p>
    {mode === "json" || !suite ? <div className="p-4">
      {!suite && <p className="mb-3 text-sm text-amber-600">The case editor needs a version 1 suite with cases, files and expected locations. Edit the JSON or load an example.</p>}
      <textarea aria-label="Fixture suite JSON" className={fieldClass + " min-h-[500px] leading-6"} value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled} spellCheck={false} />
    </div> : <div className="space-y-4 p-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="space-y-1 text-xs">Suite ID<input className={fieldClass} value={suite.suite_id} onChange={(event) => update({ ...suite, suite_id: event.target.value })} disabled={disabled} /></label>
        <label className="space-y-1 text-xs">Version<input className={fieldClass} value={suite.suite_version} onChange={(event) => update({ ...suite, suite_version: event.target.value })} disabled={disabled} /></label>
        <label className="space-y-1 text-xs">Rule ID<input className={fieldClass} value={suite.rule_id} onChange={(event) => update({ ...suite, rule_id: event.target.value, cases: suite.cases.map((item) => ({ ...item, expected: item.expected.map((expected) => ({ ...expected, rule_id: event.target.value })) })) })} disabled={disabled} /></label>
      </div>
      <div className="flex flex-wrap gap-2" aria-label="Fixture cases">{suite.cases.map((item, position) => <button key={position} type="button" aria-pressed={index === position} onClick={() => setSelected(position)} className={"max-w-full truncate rounded-md border px-3 py-2 text-xs " + (index === position ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground")}>{item.expected.length ? "+" : "−"} {item.id || "Unnamed case"}</button>)}<Button type="button" size="sm" variant="outline" onClick={addCase} disabled={disabled || suite.cases.length >= 20}>Add case</Button></div>
      {current && <div className="space-y-4 rounded-md border border-border p-3">
        <div className="flex items-end gap-3"><label className="min-w-0 flex-1 space-y-1 text-xs">Case ID<input className={fieldClass} value={current.id} disabled={disabled} onChange={(event) => updateCase({ ...current, id: event.target.value })} /></label><Button type="button" variant="ghost" size="sm" disabled={disabled || suite.cases.length <= 1} onClick={() => update({ ...suite, cases: suite.cases.filter((_, position) => position !== index) })}>Remove case</Button></div>
        {current.files.map((file, position) => <div key={position} className="space-y-2">
          <div className="flex items-center gap-2"><label className="min-w-0 flex-1 text-xs">File path<input aria-label={`File ${position + 1} path`} className={fieldClass} value={file.path} disabled={disabled} onChange={(event) => updateCase({ ...current, files: current.files.map((item, at) => at === position ? { ...item, path: event.target.value } : item), expected: current.expected.map((item) => item.file_path === file.path ? { ...item, file_path: event.target.value } : item) })} /></label><Button type="button" size="sm" variant="ghost" disabled={disabled || current.files.length <= 1} onClick={() => updateCase({ ...current, files: current.files.filter((_, at) => at !== position), expected: current.expected.filter((item) => item.file_path !== file.path) })}>Remove file</Button></div>
          <textarea aria-label={`Source for ${file.path}`} className={fieldClass + " min-h-[150px] resize-y leading-6"} value={file.content} disabled={disabled} onChange={(event) => updateCase({ ...current, files: current.files.map((item, at) => at === position ? { ...item, content: event.target.value } : item) })} spellCheck={false} wrap="off" />
          <p className="text-right font-mono text-[10px] text-muted-foreground">{file.content.split("\n").length} lines · max 64 KiB per file</p>
        </div>)}
        <Button type="button" variant="outline" size="sm" disabled={disabled || current.files.length >= 12} onClick={() => { let suffix = current.files.length + 1; while (current.files.some((file) => file.path === `file-${suffix}.py`)) suffix++; updateCase({ ...current, files: [...current.files, { path: `file-${suffix}.py`, content: "" }] }); }}>Add file</Button>
        <div className="space-y-2 border-t border-border pt-3"><h3 className="text-sm font-medium">Expected findings · {current.expected.length ? "positive case" : "negative case"}</h3>
          {!current.expected.length && <p className="text-xs text-muted-foreground">This case expects no findings. Any detected location counts as a false positive.</p>}
          {current.expected.map((expected, position) => <div key={position} className="flex flex-wrap items-end gap-2">
            <label className="min-w-0 flex-1 text-xs">File<select className={fieldClass} value={expected.file_path} disabled={disabled} onChange={(event) => updateCase({ ...current, expected: current.expected.map((item, at) => at === position ? { ...item, file_path: event.target.value } : item) })}>{current.files.map((file, at) => <option key={at} value={file.path}>{file.path}</option>)}</select></label>
            <label className="w-24 text-xs">Start line<input type="number" min={1} className={fieldClass} value={expected.line_start} disabled={disabled} onChange={(event) => updateCase({ ...current, expected: current.expected.map((item, at) => at === position ? { ...item, line_start: Number(event.target.value) } : item) })} /></label>
            <Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={() => updateCase({ ...current, expected: current.expected.filter((_, at) => at !== position) })}>Remove</Button>
          </div>)}
          <Button type="button" size="sm" variant="outline" disabled={disabled || !current.files.length || current.expected.length >= 100} onClick={() => updateCase({ ...current, expected: [...current.expected, { rule_id: suite.rule_id, file_path: current.files[0].path, line_start: 1 }] })}>Expect a finding</Button>
        </div>
      </div>}
    </div>}
  </section>;
}
