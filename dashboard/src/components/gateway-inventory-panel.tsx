"use client";

import { useId, useState } from "react";
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

function Declarations({ file }: { file: GatewayFileReview }) {
  const [page, setPage] = useState(0);
  const pages = Math.ceil(file.routes.length / pageSize);
  return (
    <div className="space-y-3">
      {file.diagnostics.map((issue) => <p key={issue} className="text-sm">{fileIssues[issue]}</p>)}
      {file.routes.length === 0 ? <p className="text-sm text-muted-foreground">No route declarations recorded in this file.</p> : (
        <ul className="divide-y rounded-md border">
          {file.routes.slice(page * pageSize, (page + 1) * pageSize).map((route, index) => (
            <li key={index} className="grid gap-1 px-3 py-2 sm:grid-cols-2 sm:gap-4">
              <div className="min-w-0 text-sm">
                <span className="block font-medium break-all">{route.name || "Unnamed declaration"}</span>
                <span className="block text-xs text-muted-foreground break-all">{route.schema} · Document {route.document} · Line {route.line}</span>
              </div>
              <div className="min-w-0 text-sm">
                <span className="font-medium capitalize">{route.status}</span>
                {route.owners.length > 0 && <span className="break-all"> · {route.owners.join(", ")}</span>}
                <span className="block text-xs text-muted-foreground">{explanations[route.reason]}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
      {pages > 1 && (
        <nav aria-label="Gateway declarations" className="flex items-center gap-4 text-sm">
          <button type="button" className="min-h-11 disabled:opacity-50" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span aria-live="polite">Page {page + 1} of {pages}</span>
          <button type="button" className="min-h-11 disabled:opacity-50" disabled={page + 1 === pages} onClick={() => setPage(page + 1)}>Next</button>
        </nav>
      )}
      {file.sha256 && <details className="text-xs text-muted-foreground"><summary>Configuration SHA-256</summary><code className="break-all">{file.sha256}</code></details>}
    </div>
  );
}

export function GatewayInventoryPanel({ review }: { review: GatewayReview }) {
  const selectId = useId();
  const [selected, setSelected] = useState(0);
  const file = review.files[selected];
  return (
    <section id="gateway-inventory" aria-labelledby="gateway-heading" className="space-y-3 border-t pt-4">
      <h2 id="gateway-heading" className="text-base font-semibold">Gateway ownership</h2>
      <p className="text-sm text-muted-foreground">
        {review.fileCount} configuration {review.fileCount === 1 ? "file" : "files"} · {review.resolved} resolved · {review.ambiguous} ambiguous · {review.unresolved} unresolved
        {" · "}{review.inputStatus === "partial" ? "Partial input" : "Input processed"}
      </p>
      {(review.omittedFiles > 0 || review.omittedRoutes > 0) && (
        <p className="text-sm">Omitted by scanner limits · {review.omittedFiles} files · {review.omittedRoutes} declarations</p>
      )}
      {file && (
        <>
          <label htmlFor={selectId} className="block text-sm font-medium">Configuration file</label>
          <select id={selectId} value={selected} onChange={(event) => setSelected(Number(event.target.value))}
            className="w-full max-w-full rounded-md border bg-background p-2 text-sm sm:w-auto">
            {review.files.map((entry, index) => (
              <option key={JSON.stringify([entry.repositoryId, entry.path])} value={index}>
                {entry.repositoryId ? entry.repositoryId + " · " : ""}{entry.path}
              </option>
            ))}
          </select>
          <Declarations key={JSON.stringify([file.repositoryId, file.path])} file={file} />
        </>
      )}
    </section>
  );
}
