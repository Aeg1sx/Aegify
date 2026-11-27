"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { ArrowRight, Check, CircleAlert, FileUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ImportReceipt } from "@/lib/sarif-import";
import { uploadValidationError } from "@/lib/upload-validation";

type Project = { id: string; name: string; accessRole: string };
type ImportState =
  | { state: "importing"; filename: string }
  | { state: "error"; filename: string; message: string; checkHistory: boolean }
  | { state: "saved"; filename: string; receipt: Pick<ImportReceipt, "scanId" | "findingsCount" | "status"> };

const scanStatus = { completed: "Completed", partial: "Partial coverage", failed: "Scan failed" };
const scanCommand = String.raw`aegify scan ./src --no-llm \
  --output sarif \
  --output-file results.sarif`;
const uploadCommand = String.raw`aegify upload results.sarif \
  --dashboard-url https://your-dashboard.example`;

export default function UploadPage() {
  const [dragging, setDragging] = useState(false);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [projectState, setProjectState] = useState<"loading" | "ready" | "error">("loading");
  const [attempt, setAttempt] = useState(0);
  const activeUpload = useRef(false);
  const [result, setResult] = useState<ImportState | null>(null);
  const project = projects.find(({ id }) => id === projectId);
  const uploading = result?.state === "importing";

  useEffect(() => {
    const controller = new AbortController();
    async function loadProjects() {
      try {
        const response = await fetch("/api/projects", { signal: controller.signal });
        if (!response.ok) throw new Error();
        const data = await response.json();
        if (controller.signal.aborted) return;
        setProjects(data.projects.filter((item: Project) => ["admin", "maintainer"].includes(item.accessRole)));
        setProjectState("ready");
      } catch { if (!controller.signal.aborted) setProjectState("error"); }
    }
    void loadProjects();
    return () => controller.abort();
  }, [attempt]);
  async function importFile(file: File) {
    if (activeUpload.current) return;
    const filename = file.name;
    function fail(message: string, checkHistory = false) {
      setResult({ state: "error", filename, message, checkHistory });
    }
    if (!project) return fail("Select a destination project, then choose the file again.");
    const validation = uploadValidationError(file, "sarif");
    if (validation) return fail(validation);
    activeUpload.current = true;
    setResult({ state: "importing", filename });
    try {
      const text = await file.text().catch(() => null);
      if (text === null) return fail("The file could not be read. Choose it again.");
      try {
        JSON.parse(text);
      } catch {
        return fail("The file contains invalid JSON. Choose a SARIF report exported by your scanner.");
      }
      const response = await fetch("/api/upload?projectId=" + encodeURIComponent(project.id), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: text,
      });
      const receipt = await response.json().catch(() => null);
      if (!response.ok && response.status < 500) {
        return fail(typeof receipt?.error === "string" ? receipt.error : "The dashboard rejected this report (HTTP " + response.status + ").");
      }
      if (!response.ok || typeof receipt?.scanId !== "string" || !receipt.scanId ||
          !Number.isSafeInteger(receipt.findingsCount) || receipt.findingsCount < 0 ||
          typeof receipt.status !== "string" || !Object.hasOwn(scanStatus, receipt.status)) {
        return fail("Check scan history before trying again.", true);
      }
      setResult({ state: "saved", filename, receipt });
    } catch {
      fail("Check scan history before trying again.", true);
    } finally {
      activeUpload.current = false;
    }
  }

  return (
    <div className="max-w-6xl">
      <header className="border-b border-border pb-5">
        <h1 className="workbench-title">Import scan</h1>
      </header>
      <div className="grid gap-x-12 gap-y-8 pt-7 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="min-w-0">
          <label htmlFor="import-project" className="block text-lg font-semibold">Destination project</label>
          <select id="import-project" className="mt-3 block h-11 w-full rounded-md border border-input bg-card px-3 text-sm" disabled={projectState !== "ready" || !projects.length || uploading} value={projectId} onChange={(event) => { setProjectId(event.target.value); setResult(null); }}>
            <option value="">{projectState === "loading" ? "Loading projects…" : "Select a project"}</option>
            {projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
          {projectState === "ready" && !projects.length && <p className="mt-2 text-sm text-muted-foreground">Ask a project administrator for maintainer access, or create a project as a workspace administrator.</p>}
          {projectState === "error" && <div role="alert" className="mt-2 flex items-center gap-3 text-sm">Couldn’t load projects.<Button type="button" variant="outline" onClick={() => { setProjectState("loading"); setAttempt((value) => value + 1); }}>Retry</Button></div>}

          <section aria-labelledby="report-title" className="mt-7">
            <h2 id="report-title" className="text-lg font-semibold">SARIF report</h2>
            <div className={"mt-3 flex flex-wrap items-center justify-between gap-4 border-y px-4 py-4 " + (dragging ? "border-primary bg-accent outline-2 outline-primary" : "border-border bg-muted/50")}
              onDragOver={(event) => { event.preventDefault(); setDragging(Boolean(project) && !uploading); }}
              onDragLeave={(event) => { if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) setDragging(false); }}
              onDrop={(event) => {
                event.preventDefault();
                setDragging(false);
                const file = event.dataTransfer.files[0];
                if (file) void importFile(file);
              }}>
              <div id="file-help" className="min-w-0 text-sm">
                <p className="font-medium">{dragging ? "Drop to import" : project ? "Choose a file or drop it here to import." : "Select a project to enable file import."}</p>
                <p className="mt-1 text-muted-foreground">.sarif or .json · up to 100 MB</p>
              </div>
              <label className="relative inline-flex min-h-11 items-center gap-2 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-ring has-disabled:opacity-50">
                <FileUp aria-hidden className="size-4" />Choose file
                <input type="file" accept=".sarif,.json" disabled={uploading || !project} aria-describedby="file-help" onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  if (file) void importFile(file);
                }} className="absolute inset-0 h-full w-full cursor-pointer opacity-0 disabled:cursor-default" />
              </label>
            </div>
          </section>

          {result && <section className="mt-5 min-w-0 border-l-2 border-input pl-4 text-sm" aria-label="Import result">
            {result.state === "error" ? <div role="alert">
              <p className="flex items-center gap-2 font-semibold"><CircleAlert aria-hidden className="size-4 shrink-0 text-destructive" />{result.checkHistory ? "Import status unknown" : "Couldn’t import report"}</p>
              <p className="mt-1 font-mono text-xs [overflow-wrap:anywhere]">{result.filename}</p>
              <p className="mt-2 text-muted-foreground">{result.message}</p>
              {result.checkHistory && <Link href="/scans" className="inline-flex min-h-11 items-center text-primary underline underline-offset-4">Open scan history</Link>}
            </div> : result.state === "importing" ? <p role="status" className="[overflow-wrap:anywhere]">Importing <strong>{result.filename}</strong> into {project?.name}…</p> : <>
              <div role="status">
                <p className="flex items-center gap-2 font-semibold"><Check aria-hidden className="size-4 text-primary" />Report imported</p>
                <p className="mt-1 font-mono text-xs [overflow-wrap:anywhere]">{result.filename}</p>
                <dl className="mt-4 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-5 gap-y-1.5">
                  <dt className="text-muted-foreground">Project</dt><dd className="font-medium [overflow-wrap:anywhere]">{project?.name}</dd>
                  <dt className="text-muted-foreground">Scan status</dt>
                  <dd className="flex items-center gap-1.5">
                    {result.receipt.status !== "completed" && <CircleAlert aria-hidden className={"size-3.5 shrink-0 " + (result.receipt.status === "partial" ? "text-[var(--severity-medium)]" : "text-destructive")} />}
                    {scanStatus[result.receipt.status]}
                  </dd>
                  <dt className="text-muted-foreground">Findings</dt><dd className="tabular-nums">{result.receipt.findingsCount}</dd>
                </dl>
              </div>
              <Link href={"/scans/" + encodeURIComponent(result.receipt.scanId)} className="mt-1 inline-flex min-h-11 items-center gap-1.5 font-medium text-primary underline underline-offset-4">Open scan <ArrowRight aria-hidden className="size-4" /></Link>
            </>}
          </section>}
        </div>

        <aside className="min-w-0 border-t border-border pt-5 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-7" aria-label="Command line import">
          <details open>
            <summary className="min-h-11 cursor-pointer text-sm font-semibold">Scan and import from the CLI</summary>
            <p className="mb-2 text-sm text-muted-foreground">Generate a SARIF report in your repository.</p>
            <pre className="whitespace-pre-wrap rounded-sm bg-muted p-3 font-mono text-xs leading-5 [overflow-wrap:anywhere]"><code>{scanCommand}</code></pre>
            <p className="mt-4 mb-2 text-sm text-muted-foreground">Set <code>AEGIFY_UPLOAD_TOKEN</code> to a project token, then use your dashboard URL.</p>
            <pre className="whitespace-pre-wrap rounded-sm bg-muted p-3 font-mono text-xs leading-5 [overflow-wrap:anywhere]"><code>{uploadCommand}</code></pre>
          </details>
        </aside>
      </div>
    </div>
  );
}
