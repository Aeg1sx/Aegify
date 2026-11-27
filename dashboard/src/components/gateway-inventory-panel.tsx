"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { scanFindingsHref } from "@/lib/finding-view";
import { Button } from "@/components/ui/button";
import type { GatewayFileReview, GatewayReview, GatewayRouteReview } from "@/lib/gateway-inventory";

const explanations: Record<GatewayRouteReview["reason"], string> = {
  manifest_service_name: "Declared service owner",
  multiple_manifest_owners: "Multiple repositories declare this service",
  no_manifest_owner: "No repository declares this service",
  dynamic_or_unsupported_destination: "Destination is dynamic or unsupported",
  unresolved_service_ref: "Service reference could not be resolved",
  ambiguous_service_ref: "Service reference has multiple matches",
  conflicting_service_ref: "Route contains conflicting service references",
  conflicting_service_destination: "Service declares conflicting destinations",
  kong_upstream_pool: "Kong Upstream pool membership needs review",
};
const fileIssues: Record<string, string> = {
  unreadable_or_size_limit: "File could not be read within the size limit.",
  unsupported_kong_format: "Unsupported Kong declarative format.",
  invalid_or_unsupported_configuration: "Invalid or unsupported configuration.",
  no_supported_gateway_declarations: "No supported gateway declarations found.",
};
const pageSize = 25;

function fileLabel(file: GatewayFileReview) {
  return file.repositoryId ? file.repositoryId + " · " + file.path : file.path;
}

const filters = [
  ["all", "All ownership statuses"],
  ["unresolved", "Unresolved"],
  ["ambiguous", "Ambiguous"],
  ["resolved", "Resolved"],
] as const;

function RouteOwners({ route, scanId }: { route: GatewayRouteReview; scanId: string }) {
  const [expanded, setExpanded] = useState(false);
  if (!route.owners.length) return null;
  const ownerLink = (owner: string) => (
    <Link key={owner} prefetch={false} href={scanFindingsHref(scanId, owner)}
      aria-label={`View findings for ${owner} in this scan`}
      className="inline-flex min-h-8 items-center gap-1 break-all rounded-sm font-mono text-xs text-primary underline underline-offset-4">
      {owner}
    </Link>
  );
  if (route.status === "resolved") return ownerLink(route.owners[0]);
  return <details className="mt-1" onToggle={(event) => setExpanded(event.currentTarget.open)}>
    <summary className="w-fit cursor-pointer py-1.5 text-xs font-medium">{route.owners.length} candidate repositories</summary>
    {expanded && <ul className="grid max-h-48 overflow-y-auto border-l pl-3">
      {route.owners.map((owner) => <li key={owner}>{ownerLink(owner)}</li>)}
    </ul>}
  </details>;
}

export function GatewayInventoryPanel({ review, scanId }: { review: GatewayReview; scanId: string }) {
  const id = useId();
  const section = useRef<HTMLElement>(null);
  useEffect(() => {
    // The scan request can finish after the browser has tried its fragment jump.
    if (window.location.hash === "#gateway-inventory" && section.current) {
      section.current.focus({ preventScroll: true });
      section.current.scrollIntoView({ block: "start" });
    }
  }, []);
  const [fileIndex, setFileIndex] = useState(-1);
  const [status, setStatus] = useState("all");
  const [ownerSearch, setOwnerSearch] = useState("");
  const ownerQuery = ownerSearch.trim().toLowerCase();
  const [page, setPage] = useState(0);
  const selected = review.files[fileIndex];
  const files = useMemo(() => selected ? [selected] : review.files, [review.files, selected]);
  const matches = useMemo(() => files.flatMap((file) => file.routes
    .map((route, routeIndex) => ({ route, file, routeIndex }))
    .filter(({ route }) => (status === "all" || route.status === status)
      && (!ownerQuery || route.owners.some((owner) => owner.toLowerCase().includes(ownerQuery))))), [files, status, ownerQuery]);
  const pages = Math.ceil(matches.length / pageSize);
  const start = Math.min(page, Math.max(0, pages - 1)) * pageSize;
  const selectClass = "min-h-11 w-full min-w-0 rounded-md border bg-background px-3 text-sm";

  return (
    <section ref={section} id="gateway-inventory" tabIndex={-1} aria-labelledby={id + "-heading"} className="min-w-0 scroll-mt-16 space-y-4 border-t pt-4 lg:scroll-mt-4">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h2 id={id + "-heading"} className="text-base font-semibold">Gateway ownership</h2>
          <p className="text-sm text-muted-foreground">
            {review.fileCount} configuration {review.fileCount === 1 ? "file" : "files"} · {review.resolved} resolved · {review.ambiguous} ambiguous · {review.unresolved} unresolved
          </p>
        </div>
        <span className="text-xs text-muted-foreground">{review.inputStatus === "partial" ? "Partial input" : "Input processed"}</span>
      </header>
      {(review.omittedFiles > 0 || review.omittedRoutes > 0) && (
        <p className="text-sm">Omitted by scanner limits · {review.omittedFiles} files · {review.omittedRoutes} declarations</p>
      )}
      {review.files.length > 0 && (
        <div className="grid gap-3 rounded-lg border bg-muted/30 p-3 md:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <label className="grid min-w-0 gap-1 text-xs font-medium">
            Configuration file
            <select className={selectClass} value={fileIndex} onChange={(event) => { setFileIndex(Number(event.target.value)); setPage(0); }}>
              <option value={-1}>All configuration files</option>
              {review.files.map((file, index) => <option key={index} value={index}>{fileLabel(file)}</option>)}
            </select>
          </label>
          <label className="grid min-w-0 gap-1 text-xs font-medium">
            Ownership status
            <select className={selectClass} value={status} onChange={(event) => { setStatus(event.target.value); setPage(0); }}>
              {filters.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <label className="grid min-w-0 gap-1 text-xs font-medium">
            Destination repository
            <input type="search" className={selectClass} value={ownerSearch} placeholder="Filter by owner…"
              onChange={(event) => { setOwnerSearch(event.target.value); setPage(0); }} />
          </label>
        </div>
      )}
      {files.filter((file) => file.diagnostics.length > 0).map((file) => (
        <div key={JSON.stringify([file.repositoryId, file.path])} className="rounded-md border px-3 py-2 text-sm">
          <p className="break-all font-medium">{fileLabel(file)}</p>
          {file.diagnostics.map((issue) => <p key={issue}>{fileIssues[issue]}</p>)}
        </div>
      ))}
      <p aria-live="polite" className="text-xs text-muted-foreground">
        {matches.length ? `Showing ${start + 1}–${Math.min(start + pageSize, matches.length)} of ${matches.length} declarations`
          : ownerQuery ? "No declarations match this destination repository." : status === "all" ? "No route declarations recorded." : "No declarations match this ownership status."}
      </p>
      {matches.length > 0 && (
        <ul aria-label="Gateway route declarations" className="divide-y rounded-lg border">
          {matches.slice(start, start + pageSize).map(({ route, file, routeIndex }) => (
            <li key={JSON.stringify([file.repositoryId, file.path, routeIndex])} className="grid gap-2 px-4 py-3 sm:grid-cols-2 sm:gap-4">
              <div className="min-w-0">
                <span className="block break-all text-sm font-semibold">{route.name || "Unnamed declaration"}</span>
                <span className="block break-all text-xs text-muted-foreground">{fileLabel(file)}</span>
                <span className="block break-all text-xs text-muted-foreground">{route.schema} · Document {route.document} · Line {route.line}</span>
              </div>
              <div className="min-w-0 text-sm">
                <span className="font-medium capitalize">{route.status}</span>
                <p className="text-xs text-muted-foreground">{explanations[route.reason]}</p>
                <RouteOwners route={route} scanId={scanId} />
              </div>
            </li>
          ))}
        </ul>
      )}
      {pages > 1 && (
        <nav aria-label="Gateway declarations" className="flex flex-wrap items-center gap-3">
          <Button type="button" variant="outline" className="min-h-11" disabled={start === 0} onClick={() => setPage(start / pageSize - 1)}>Previous</Button>
          <span className="text-sm">Page {start / pageSize + 1} of {pages}</span>
          <Button type="button" variant="outline" className="min-h-11" disabled={start + pageSize >= matches.length} onClick={() => setPage(start / pageSize + 1)}>Next</Button>
        </nav>
      )}
      {selected?.sha256 && <details className="text-xs text-muted-foreground"><summary>Configuration SHA-256</summary><code className="break-all">{selected.sha256}</code></details>}
    </section>
  );
}
