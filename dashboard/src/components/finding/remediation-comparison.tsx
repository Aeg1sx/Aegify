"use client";

import { useMemo, useState } from "react";
import { CodeHighlight } from "@/components/code-highlight";
import { remediationDiff } from "@/lib/remediation-diff";

const views = ["Changes", "Original", "Proposed"] as const;
const lineLabels = { add: "Added", remove: "Removed", context: "Unchanged" };
const lineMarkers = { add: "+", remove: "−", context: " " };

export function RemediationComparison({ original, proposed, language }: {
  original: string; proposed: string; language?: string;
}) {
  const rows = useMemo(() => original ? remediationDiff(original, proposed) : null, [original, proposed]);
  const [selected, setSelected] = useState<typeof views[number]>("Changes");
  const view = selected === "Changes" && !rows ? "Proposed" : selected;
  const available = views.filter((item) => item === "Proposed" || (item === "Changes" ? rows : original));
  const changed = rows?.filter((row) => row.kind !== "context") ?? [];
  return <section className="min-w-0 space-y-3" aria-label="Suggested code change">
    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-border">
      <h5 className="py-2 text-sm font-semibold">Suggested code change</h5>
      {available.length > 1 && <div role="group" aria-label="Code comparison view" className="flex gap-x-3">
        {available.map((item) => <button key={item} type="button" aria-pressed={view === item}
          className="min-h-11 min-w-11 border-b-2 border-transparent px-1 text-sm text-muted-foreground hover:text-foreground active:bg-accent focus-visible:outline-2 focus-visible:outline-ring aria-pressed:border-primary aria-pressed:font-semibold aria-pressed:text-foreground"
          onClick={() => setSelected(item)}>{item}</button>)}
      </div>}
    </div>
    {view === "Changes" && rows ? changed.length ? <>
      <p className="text-xs text-muted-foreground">{changed.filter((row) => row.kind === "add").length} added, {changed.filter((row) => row.kind === "remove").length} removed</p>
      <div tabIndex={0} role="region" aria-label="Line changes between excerpts" className="max-h-96 overflow-auto rounded-md border border-border bg-card text-xs leading-6">
        <table className="w-full border-collapse">
          <caption className="sr-only">Line numbers relative to the original and proposed excerpts</caption>
          <thead className="sr-only"><tr><th>Original line</th><th>Proposed line</th><th>Change</th><th>Code</th></tr></thead>
          <tbody className="font-mono tabular-nums">{rows.map((row, index) => <tr key={index} className={row.kind === "add" ? "bg-primary/10" : row.kind === "remove" ? "bg-destructive/10" : ""}>
            <td className="w-8 select-none pl-2 text-right align-top text-muted-foreground">{row.original}</td>
            <td className="w-8 select-none pl-1 text-right align-top text-muted-foreground">{row.proposed}</td>
            <td className="w-7 select-none text-center align-top"><span aria-hidden>{lineMarkers[row.kind]}</span><span className="sr-only">{lineLabels[row.kind]}</span></td>
            <td className="whitespace-pre-wrap pr-3 [overflow-wrap:anywhere]">{row.text || " "}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </> : <p className="py-2 text-sm text-muted-foreground">The proposed excerpt matches the original.</p>
      : <><CodeHighlight code={view === "Original" ? original : proposed} language={language} lineStart={null} label={view + " excerpt"} />
        {original && !rows && <p className="text-xs text-muted-foreground">Large excerpts are available in the Original and Proposed views.</p>}</>}
  </section>;
}
