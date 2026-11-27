"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ChevronDown, Download, FileText, FileUp, Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ApiContract } from "@/lib/openapi-contract";
import { fieldClass, SpecificationReview, type Comparison } from "./specification-review";

interface Scan {
  id: string;
  repository: string;
  branch: string;
  createdAt: string;
}
interface Snapshot {
  id: string;
  repositoryId: string;
  title: string;
  sourceName: string;
  sourceUrl: string;
  contentHash: string;
  operationCount: number;
  createdAt: string;
}
interface Listing {
  scan: Scan;
  scanId: string;
  repositoryId: string | null;
  repositoryIds: string[];
  specifications: Snapshot[];
  total: number;
}
interface Inspection {
  scanId: string;
  repositoryId: string;
  contract: ApiContract;
  comparison: Comparison;
  sourceName: string;
  snapshot?: Pick<Snapshot, "id" | "sourceUrl">;
}
type Action = "preview" | "save" | "read";
const listingUrl = "/api/endpoints/import-openapi?";
const date = (value: string) =>
  new Date(value).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });

export default function ApiSpecificationsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanId, setScanId] = useState("");
  const [repositoryId, setRepositoryId] = useState<string | null>(null);
  const [listing, setListing] = useState<Listing | null>(null);
  const [listingFailure, setListingFailure] = useState<{
    scanId: string;
    repositoryId: string | null;
  } | null>(null);
  const [revision, setRevision] = useState(0);
  const [mode, setMode] = useState<"file" | "url">("file");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [expanded, setExpanded] = useState(true);
  const [inspection, setInspection] = useState<Inspection | null>(null);
  const [pending, setPending] = useState<Action | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const request = useRef<AbortController | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);
  const lastScope = listing?.scanId === scanId ? listing : null;
  const history = lastScope?.repositoryId === repositoryId ? lastScope : null;
  const historyFailed = listingFailure?.scanId === scanId && listingFailure.repositoryId === repositoryId;
  const olderScan = !!scanId && !scans.some((scan) => scan.id === scanId);

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/scans?limit=100", { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load scans.");
        const data = await response.json();
        if (controller.signal.aborted) return;
        setScans(data.scans || []);
        const requested = new URLSearchParams(window.location.search).get("scanId");
        if (requested) setScanId(requested);
      })
      .catch((reason) => {
        if (!controller.signal.aborted) setError(reason.message);
      });
    return () => {
      controller.abort();
      request.current?.abort();
    };
  }, []);

  useEffect(() => {
    if (!scanId) return;
    const controller = new AbortController();
    const params = new URLSearchParams({ scanId });
    if (repositoryId !== null) params.set("repositoryId", repositoryId);
    void fetch(listingUrl + params, { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unable to load saved specifications.");
        const data = await response.json();
        if (!controller.signal.aborted) {
          setListing({ ...data, scanId, repositoryId });
          setListingFailure(null);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setListingFailure({ scanId, repositoryId });
      });
    return () => controller.abort();
  }, [scanId, repositoryId, revision]);

  useEffect(() => {
    if (inspection) resultHeading.current?.focus();
  }, [inspection]);

  function invalidate() {
    request.current?.abort();
    request.current = null;
    setPending(null);
    setInspection(null);
    setNotice("");
    setError("");
    setExpanded(true);
  }
  function start(action: Action) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setPending(action);
    setError("");
    setNotice("");
    return controller;
  }
  function finish(controller: AbortController) {
    if (request.current === controller) {
      request.current = null;
      setPending(null);
    }
  }
  async function readSnapshot(id: string, repo: string, controller: AbortController) {
    const params = new URLSearchParams({ scanId, repositoryId: repo, id });
    const response = await fetch(listingUrl + params, { signal: controller.signal, cache: "no-store" });
    const data = await response.json();
    if (controller.signal.aborted) return;
    if (!response.ok) throw new Error(data.error || "Unable to load snapshot.");
    const spec = data.spec;
    if (spec.id !== id || spec.scanId !== scanId || spec.repositoryId !== repo)
      throw new Error("The requested snapshot could not be verified.");
    setInspection({
      scanId,
      repositoryId: repo,
      contract: spec.contract,
      comparison: data.comparison,
      sourceName: spec.sourceName,
      snapshot: { id, sourceUrl: spec.sourceUrl },
    });
    setExpanded(false);
  }
  async function openSnapshot(snapshot: Snapshot) {
    invalidate();
    setRepositoryId(snapshot.repositoryId);
    const controller = start("read");
    try {
      await readSnapshot(snapshot.id, snapshot.repositoryId, controller);
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(reason instanceof Error ? reason.message : "Unable to load snapshot.");
    } finally {
      finish(controller);
    }
  }
  async function importSpec(save: boolean) {
    if (!scanId || repositoryId === null || pending) return;
    if (
      save &&
      (!inspection ||
        inspection.snapshot ||
        inspection.scanId !== scanId ||
        inspection.repositoryId !== repositoryId)
    )
      return;
    const controller = start(save ? "save" : "preview");
    if (!save) setInspection(null);
    try {
      const params = new URLSearchParams({ scanId, repositoryId });
      if (save && inspection) params.set("expectedHash", inspection.contract.digest);
      else params.set("preview", "true");
      let body: BodyInit;
      const headers: Record<string, string> = {};
      if (mode === "file") {
        if (!file) throw new Error("Choose a specification file.");
        const form = new FormData();
        form.set("file", file);
        body = form;
      } else {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify({ url, authorized });
      }
      const response = await fetch(listingUrl + params, {
        method: "POST",
        body,
        headers,
        signal: controller.signal,
      });
      const data = await response.json();
      if (controller.signal.aborted) return;
      if (!response.ok) throw new Error(data.error || "Unable to import specification.");
      if (save) {
        setInspection(null);
        setRevision((current) => current + 1);
        setNotice(data.duplicate ? "This version was already saved." : "Saved to this scan and repository.");
        await readSnapshot(data.id, repositoryId, controller);
      } else {
        setInspection({
          scanId,
          repositoryId,
          contract: data.contract,
          comparison: data.comparison,
          sourceName: data.sourceName,
        });
        setExpanded(false);
      }
    } catch (reason) {
      if (!controller.signal.aborted) {
        setInspection(null);
        setExpanded(true);
        setError(reason instanceof Error ? reason.message : "Unable to import specification.");
      }
    } finally {
      finish(controller);
    }
  }
  function download() {
    if (!inspection) return;
    const { scanId, repositoryId, contract, comparison, sourceName, snapshot } = inspection;
    const contents = {
      kind: "normalized_contract_review",
      evidenceBoundary:
        "Specification declarations and exact route associations observed in a source scan. Runtime enforcement requires separate verification.",
      scanId,
      repositoryId,
      sourceName,
      contract,
      comparison,
      ...(snapshot && { specificationId: snapshot.id }),
    };
    const href = URL.createObjectURL(
      new Blob([JSON.stringify(contents, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = href;
    link.download = "api-contract-" + contract.digest.slice(0, 12) + ".json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function changeSource(next: "file" | "url") {
    if (mode === next) return;
    invalidate();
    setFile(null);
    setUrl("");
    setAuthorized(false);
    setMode(next);
  }
  const canPreview = !!scanId && repositoryId !== null && (mode === "file" ? !!file : !!url && authorized);

  return (
    <div className="mx-auto min-w-0 max-w-[90rem] space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">API specifications</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Compare the routes and authentication in a contract with the handlers in a source scan.
          </p>
        </div>
        <Link
          href="/endpoints"
          className="inline-flex min-h-11 items-center gap-1.5 text-sm font-medium text-primary hover:underline"
        >
          Endpoint inventory <ArrowUpRight aria-hidden className="size-4" />
        </Link>
      </header>
      <div className="workbench-panel">
        <div className="grid gap-3 p-4 sm:grid-cols-2 sm:px-5">
          <label className="min-w-0">
            <span className="mb-1.5 block text-xs font-medium">Scan snapshot</span>
            <select
              id="spec-scan"
              className={fieldClass}
              value={scanId}
              onChange={(event) => {
                invalidate();
                setScanId(event.target.value);
                setRepositoryId(null);
              }}
            >
              <option value="">Select a scan…</option>
              {olderScan && (
                <option value={scanId}>
                  {lastScope
                    ? (lastScope.scan.repository || scanId.slice(0, 8)) +
                      " · " +
                      date(lastScope.scan.createdAt)
                    : "Selected scan · " + scanId.slice(0, 8)}
                </option>
              )}
              {scans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {scan.repository || scan.id.slice(0, 8)} · {scan.branch || "snapshot"} ·{" "}
                  {date(scan.createdAt)}
                </option>
              ))}
            </select>
          </label>
          <label className="min-w-0">
            <span className="mb-1.5 block text-xs font-medium">Repository scope</span>
            <select
              id="spec-repository"
              className={fieldClass}
              value={repositoryId ?? "__choose__"}
              disabled={!lastScope}
              onChange={(event) => {
                invalidate();
                setRepositoryId(event.target.value === "__choose__" ? null : event.target.value);
              }}
            >
              <option value="__choose__">Select a repository…</option>
              {lastScope?.repositoryIds.map((id) => (
                <option key={id} value={id}>
                  {id || "Default repository"}
                </option>
              ))}
            </select>
          </label>
        </div>
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls="spec-documents"
          className="flex min-h-11 w-full items-center justify-between gap-2 border-t px-4 py-2 text-left text-sm font-medium hover:bg-muted/30 sm:px-5"
          onClick={() => setExpanded(!expanded)}
        >
          <span className="flex items-center gap-2">
            <FileText aria-hidden className="size-4 text-muted-foreground" />
            {inspection ? "Change specification" : "Choose a specification"}
          </span>
          <ChevronDown
            aria-hidden
            className={"size-4 transition-transform " + (expanded ? "rotate-180" : "")}
          />
        </button>
        <div id="spec-documents" hidden={!expanded}>
          <div className="grid gap-5 border-t p-4 sm:p-5 lg:grid-cols-2 lg:gap-8">
            <form
              aria-label="Preview specification"
              className="min-w-0 space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                if (canPreview) void importSpec(false);
              }}
            >
              <div className="flex flex-wrap gap-2">
                {(["file", "url"] as const).map((value) => (
                  <Button
                    type="button"
                    key={value}
                    aria-pressed={mode === value}
                    variant={mode === value ? "secondary" : "ghost"}
                    className="min-h-11"
                    onClick={() => changeSource(value)}
                  >
                    {value === "file" ? <FileUp aria-hidden /> : <Link2 aria-hidden />}
                    {value === "file" ? "Upload file" : "HTTPS URL"}
                  </Button>
                ))}
              </div>
              {mode === "file" ? (
                <div key="file">
                  <label htmlFor="spec-file" className="mb-2 block text-xs font-medium">
                    Specification file
                  </label>
                  <input
                    id="spec-file"
                    name="file"
                    type="file"
                    accept=".json,.yaml,.yml"
                    className="min-h-11 w-full min-w-0 text-xs file:mr-3 file:min-h-11 file:rounded-md file:border file:bg-background file:px-3"
                    onChange={(event) => {
                      invalidate();
                      setFile(event.target.files?.[0] || null);
                    }}
                  />
                  <p className="mt-2 text-xs text-muted-foreground">
                    Swagger 2.0 and OpenAPI 3.0–3.2 · JSON or YAML · 2 MiB limit
                  </p>
                </div>
              ) : (
                <div key="url" className="space-y-2">
                  <label htmlFor="spec-url" className="block text-xs font-medium">
                    Raw specification URL
                  </label>
                  <input
                    id="spec-url"
                    name="url"
                    type="url"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    className={fieldClass}
                    value={url}
                    placeholder="https://api.example.com/openapi.json"
                    onChange={(event) => {
                      invalidate();
                      setUrl(event.target.value);
                      setAuthorized(false);
                    }}
                  />
                  <label className="flex min-h-11 items-center gap-2 text-xs">
                    <input
                      type="checkbox"
                      checked={authorized}
                      onChange={(event) => {
                        invalidate();
                        setAuthorized(event.target.checked);
                      }}
                    />
                    I am authorized to retrieve this specification.
                  </label>
                  <p className="text-xs leading-5 text-muted-foreground">
                    Preview and save each fetch the public HTTPS document once. Upload a file for a private
                    specification.
                  </p>
                </div>
              )}
              <Button
                type="submit"
                variant="outline"
                className="min-h-11"
                disabled={!canPreview || !!pending}
              >
                {pending === "preview" ? "Loading preview…" : "Preview specification"}
              </Button>
            </form>
            <section className="min-w-0 border-t pt-4 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
              <h2 className="text-sm font-semibold">Saved specifications</h2>
              {historyFailed && (
                <div role="alert" className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                  <span>Couldn’t load specifications for this scope.</span>
                  <Button
                    variant="outline"
                    className="min-h-11"
                    onClick={() => {
                      setListingFailure(null);
                      setRevision((n) => n + 1);
                    }}
                  >
                    Retry
                  </Button>
                </div>
              )}
              {history?.total ? (
                <>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Showing {history.specifications.length} of {history.total} in this{" "}
                    {repositoryId === null ? "scan" : "repository"}
                  </p>
                  <ul className="mt-2 max-h-64 divide-y overflow-auto">
                    {history.specifications.map((item) => (
                      <li key={item.id}>
                        <button
                          type="button"
                          onClick={() => openSnapshot(item)}
                          className="block min-h-11 w-full px-1 py-2 text-left hover:bg-muted/40"
                        >
                          <span className="block break-words text-sm font-medium">{item.title}</span>
                          <span className="block break-all text-xs text-muted-foreground">
                            {item.repositoryId || "Default repository"} · {item.operationCount} operations ·{" "}
                            {date(item.createdAt)} · {item.contentHash.slice(0, 8)}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                !historyFailed && (
                  <p className="mt-2 text-xs leading-5 text-muted-foreground">
                    {!scanId
                      ? "Select a scan to see its saved specifications."
                      : !history
                        ? "Loading specifications…"
                        : "No specifications saved in this scope."}
                  </p>
                )
              )}
            </section>
          </div>
        </div>
      </div>
      {error && (
        <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">
          {error}
        </p>
      )}
      {notice && (
        <p
          role="status"
          className={
            inspection?.snapshot && notice === "Saved to this scan and repository."
              ? "sr-only"
              : "text-sm text-primary"
          }
        >
          {notice}
        </p>
      )}
      {pending === "read" && (
        <p role="status" className="text-sm text-muted-foreground">
          Opening saved specification…
        </p>
      )}
      {inspection && (
        <>
          <section className="space-y-4 border-b px-1 pt-1 pb-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <p className="text-xs font-medium text-muted-foreground">
                  {inspection.snapshot ? "Saved specification" : "Unsaved preview"}
                </p>
                <h2
                  ref={resultHeading}
                  tabIndex={-1}
                  className="mt-1 w-fit max-w-full scroll-mt-20 rounded-sm break-words text-2xl font-semibold tracking-tight"
                >
                  {inspection.contract.title}
                </h2>
                <p className="mt-1.5 break-words text-xs text-muted-foreground">
                  {inspection.sourceName} · {inspection.contract.version === "2.0" ? "Swagger " : "OpenAPI "}
                  {inspection.contract.version}
                  {inspection.contract.apiVersion && " · API " + inspection.contract.apiVersion}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                {!inspection.snapshot && (
                  <Button
                    disabled={!!pending || !inspection.contract.operations.length}
                    className="min-h-11"
                    onClick={() => importSpec(true)}
                  >
                    {pending === "save" ? "Saving…" : "Save specification"}
                  </Button>
                )}
                <Button variant="outline" className="min-h-11" onClick={download}>
                  <Download aria-hidden />
                  Export review
                </Button>
              </div>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
              {(
                [
                  ["Matched", inspection.comparison.matched],
                  ["Spec only", inspection.comparison.specOnly],
                  ["Ambiguous", inspection.comparison.ambiguous],
                  ["Source only", inspection.comparison.codeOnly.length],
                ] as const
              ).map(([label, count]) => (
                <div key={label} className="flex flex-wrap items-baseline gap-x-2">
                  <dt className="order-2 text-xs text-muted-foreground">{label}</dt>
                  <dd className="text-xl font-semibold tabular-nums">{count}</dd>
                </div>
              ))}
            </dl>
          </section>
          <SpecificationReview
            key={[
              inspection.scanId,
              inspection.repositoryId,
              inspection.contract.digest,
              inspection.snapshot?.id,
            ].join("/")}
            contract={inspection.contract}
            comparison={inspection.comparison}
          />
          <details className="border-t">
            <summary className="min-h-11 cursor-pointer py-3 text-xs font-medium">
              Document provenance
            </summary>
            <p className="break-all font-mono text-xs text-muted-foreground">
              SHA-256 {inspection.contract.digest}
            </p>
            {inspection.snapshot?.sourceUrl && (
              <Button
                variant="outline"
                className="my-3 min-h-11"
                onClick={() => {
                  const source = inspection.snapshot!.sourceUrl;
                  invalidate();
                  setFile(null);
                  setMode("url");
                  setUrl(source);
                  setAuthorized(false);
                }}
              >
                Prepare URL refresh
              </Button>
            )}
          </details>
        </>
      )}
    </div>
  );
}
