"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, ExternalLink, Pencil } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { YamlHighlight } from "@/components/code-highlight";
import { RuleEditor } from "@/components/rules/rule-editor";

interface RuleDetail {
  id: string;
  name: string;
  severity: string;
  cweId: number | null;
  owaspCategory: string | null;
  languages: string;
  enabled: boolean;
  yamlContent: string;
  description: string;
  sourceFile: string;
}

interface RuleStats {
  totalFindings: number;
  statusBreakdown: Record<string, number>;
  avgConfidence: number;
  filePathCount: number;
  topFiles: Array<{ path: string; count: number }>;
}

type RecordData = { rule: RuleDetail; stats: RuleStats };
type Failure = "access" | "missing" | "load";
const failureText: Record<Failure, string> = {
  access: "Workspace administrator access is required to view this rule.",
  missing: "Rule not found.",
  load: "Couldn’t load this rule.",
};
const changeFailure = {
  state: "Couldn’t change the rule state. Try again.",
  save: "Couldn’t save the definition. Your draft is still open.",
  file: "Couldn’t write the YAML file. Check the rule source and try again.",
};

export default function RuleDetailPage({ params, searchParams }: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { id } = use(params);
  const search = use(searchParams);
  const catalog = new URLSearchParams();
  for (const key of ["q", "severity", "page"]) {
    const value = search[key];
    if (typeof value === "string" && value) catalog.set(key, value);
  }
  return <RuleRecord key={id} id={id} backHref={catalog.size ? "/rules?" + catalog : "/rules"} />;
}

function RuleRecord({ id, backHref }: { id: string; backHref: string }) {
  const [record, setRecord] = useState<RecordData | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [pending, setPending] = useState<"state" | "save" | "file" | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [valid, setValid] = useState(false);
  const [message, setMessage] = useState("");
  const [stateMessage, setStateMessage] = useState("");
  const endpoint = "/api/rules/" + encodeURIComponent(id);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch(endpoint, { signal: controller.signal });
        if (!response.ok) {
          if (!controller.signal.aborted) setFailure(response.status === 403 ? "access" : response.status === 404 ? "missing" : "load");
          return;
        }
        const data: RecordData = await response.json();
        if (!controller.signal.aborted) { setRecord(data); setFailure(null); }
      } catch {
        if (!controller.signal.aborted) setFailure("load");
      }
    }
    void load();
    return () => controller.abort();
  }, [endpoint, attempt]);

  async function change(action: "state" | "save" | "file") {
    if (!record || pending) return;
    const { rule } = record;
    setPending(action);
    const feedback = action === "state" ? setStateMessage : setMessage;
    feedback("");
    try {
      const file = action === "file";
      const response = await fetch(file ? "/api/rules/sync" : endpoint, {
        method: file ? "POST" : "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(file
          ? { direction: "db-to-yaml", ruleId: rule.id }
          : action === "state" ? { enabled: !rule.enabled } : { yamlContent: draft }),
      });
      if (!response.ok) throw new Error();
      if (file) {
        feedback("Saved to the YAML file.");
      } else {
        const data: { rule: RuleDetail } = await response.json();
        setRecord({ ...record, rule: data.rule });
        if (action === "save") { setEditing(false); feedback("Definition saved."); }
        else feedback(data.rule.enabled ? "Rule enabled." : "Rule disabled.");
      }
    } catch {
      feedback(changeFailure[action]);
    } finally {
      setPending(null);
    }
  }

  function startEdit() {
    setDraft(record?.rule.yamlContent || "");
    setValid(false);
    setMessage("");
    setEditing(true);
  }

  const back = (
    <Link href={backHref} className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-primary">
      <ArrowLeft aria-hidden className="size-4" />Detection rules
    </Link>
  );
  if (!record) {
    return <div className="space-y-3">{back}
      <p role={failure ? "alert" : "status"}>{failure ? failureText[failure] : "Loading rule…"}</p>
      {failure === "load" && <Button variant="outline" className="min-h-11" onClick={() => { setFailure(null); setAttempt((n) => n + 1); }}>Retry</Button>}
    </div>;
  }

  const { rule, stats } = record;
  const languages = rule.languages.split(",").map((language) => language.trim()).filter(Boolean);
  return (
    <article className="mx-auto w-full max-w-7xl space-y-6">
      <header className="space-y-2">
        {back}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <span className="break-all font-mono text-sm text-muted-foreground">{rule.id}</span>
          <SeverityBadge severity={rule.severity} />
        </div>
        <h1 className="workbench-title max-w-4xl [overflow-wrap:anywhere]">{rule.name}</h1>
        {rule.description && <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{rule.description}</p>}
      </header>

      <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0 space-y-6">
          <section className="workbench-panel" aria-labelledby="rule-definition">
            <div className="workbench-heading items-start">
              <div className="min-w-0">
                <h2 id="rule-definition" className="font-semibold">Rule definition</h2>
                {rule.sourceFile && (editing || !rule.yamlContent) && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{rule.sourceFile}</p>}
              </div>
              <div className="flex flex-wrap gap-2">
                {editing ? <>
                  <Button variant="outline" className="min-h-11" disabled={!!pending} onClick={() => { setEditing(false); setMessage(""); }}>Cancel</Button>
                  <Button className="min-h-11" disabled={!!pending || !valid} onClick={() => change("save")}>{pending === "save" ? "Saving…" : "Save definition"}</Button>
                </> : <>
                  {rule.yamlContent && <Button variant="outline" className="min-h-11" disabled={!!pending} onClick={() => change("file")}>{pending === "file" ? "Writing…" : "Write YAML file"}</Button>}
                  <Button variant="outline" className="min-h-11" disabled={!!pending} onClick={startEdit}>
                    <Pencil aria-hidden />{rule.yamlContent ? "Edit YAML" : "Add definition"}
                  </Button>
                </>}
              </div>
            </div>
            {message && <p role="status" className="border-b px-5 py-3 text-sm">{message}</p>}
            <div className="min-w-0 p-3 sm:p-4">
              {editing ? <fieldset disabled={pending === "save"} className="min-w-0"><RuleEditor value={draft} originalValue={rule.yamlContent} expectedRuleId={rule.id} onChange={setDraft} onValidityChange={setValid} /></fieldset>
                : rule.yamlContent ? <YamlHighlight code={rule.yamlContent} filePath={rule.sourceFile} />
                : <p className="p-1 text-sm text-muted-foreground">No YAML definition has been saved.</p>}
            </div>
          </section>
          <section className="min-w-0 border-t pt-4" aria-labelledby="rule-current-findings">
            <div className="flex flex-wrap items-center justify-between gap-x-4">
              <h2 id="rule-current-findings" className="text-lg font-semibold">Current findings</h2>
              <Link href={"/findings?ruleId=" + encodeURIComponent(id)} className="inline-flex min-h-11 items-center gap-2 text-sm font-medium text-primary hover:underline">Open findings <ArrowRight aria-hidden className="size-4" /></Link>
            </div>
            {stats.totalFindings ? (
              <div className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  {stats.totalFindings.toLocaleString()} current · {stats.filePathCount.toLocaleString()} distinct {stats.filePathCount === 1 ? "path" : "paths"} · {Math.round(stats.avgConfidence * 100)}% average confidence
                </p>
                <dl className="flex flex-wrap gap-x-5 gap-y-1 text-xs">{Object.entries(stats.statusBreakdown).map(([status, count]) => (
                  <div key={status} className="flex gap-1.5"><dt className="capitalize text-muted-foreground">{status.replaceAll("_", " ")}</dt><dd className="font-medium tabular-nums">{count}</dd></div>
                ))}</dl>
                {stats.topFiles.length > 0 && <>
                  <h3 className="text-sm font-medium">Paths with the most findings</h3>
                  <ul className="divide-y border-y">{stats.topFiles.map((file) => (
                    <li key={file.path} className="flex items-baseline justify-between gap-4 py-2 text-sm">
                      <span className="min-w-0 break-all font-mono text-xs">{file.path || "Path unavailable"}</span>
                      <span className="tabular-nums">{file.count}</span>
                    </li>
                  ))}</ul>
                </>}
              </div>
            ) : <p className="mt-1 text-sm text-muted-foreground">No current findings for this rule.</p>}
          </section>
        </div>

        <aside aria-label="Rule configuration" className="min-w-0 self-start border-t pt-4 xl:border-t-0 xl:border-l xl:pt-1 xl:pl-6">
          <h2 className="font-semibold">Configuration</h2>
          <dl className="mt-1 divide-y text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2 py-2">
              <dt className="text-muted-foreground">Rule state</dt>
              <dd><Button role="switch" aria-label="Enable rule" aria-checked={rule.enabled} variant="outline" className="min-h-11" disabled={!!pending} onClick={() => change("state")}>
                <span aria-hidden className={rule.enabled ? "size-2 rounded-full bg-primary" : "size-2 rounded-full border border-muted-foreground"} />{rule.enabled ? "Enabled" : "Disabled"}
              </Button></dd>
            </div>
            <div className="py-3"><dt className="text-xs text-muted-foreground">Languages</dt><dd className="mt-1">{languages.join(", ") || "Unspecified"}</dd></div>
            {rule.cweId !== null && <div className="py-2"><dt className="sr-only">CWE classification</dt><dd>
              <a href={"https://cwe.mitre.org/data/definitions/" + rule.cweId + ".html"} target="_blank" rel="noreferrer" className="inline-flex min-h-11 items-center gap-1.5 text-primary hover:underline">
                CWE-{rule.cweId} <ExternalLink aria-hidden className="size-3.5" />
              </a>
            </dd></div>}
            {rule.owaspCategory && <div className="py-3"><dt className="text-xs text-muted-foreground">OWASP category</dt><dd className="mt-1">{rule.owaspCategory}</dd></div>}
          </dl>
          {stateMessage && <p role="status" className="mt-2 text-sm text-muted-foreground">{stateMessage}</p>}
        </aside>
      </div>
    </article>
  );
}
