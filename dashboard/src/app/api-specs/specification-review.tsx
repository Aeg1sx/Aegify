"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Search } from "lucide-react";
import { CodeHighlight } from "@/components/code-highlight";
import { Button } from "@/components/ui/button";
import type { ApiContract, reconcileContract } from "@/lib/openapi-contract";

export type Comparison = ReturnType<typeof reconcileContract>;
type Operation = Comparison["operations"][number];
export const fieldClass = "min-h-11 w-full min-w-0 rounded-md border bg-background px-3 py-2 text-sm";
const associationNames: Record<string, string> = {
  exact_route: "Exact match",
  ambiguous: "Multiple matches",
  spec_only: "Spec only",
};
const requirementNames = {
  required: "Authentication required",
  optional: "Authentication optional",
  none: "No authentication required",
  undeclared: "Authentication unspecified",
  unknown: "Declaration unreadable",
};

function OperationDetail({ operation, contract }: { operation: Operation; contract: ApiContract }) {
  const [showJson, setShowJson] = useState(false);
  const { matches, security, parameters, responses, requestBody } = operation;
  const formats = Object.keys((requestBody.content ?? {}) as Record<string, unknown>);
  return (
    <article aria-label="Operation detail" className="min-w-0 px-4 py-5 sm:p-6">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-sm font-semibold text-primary">{operation.method}</span>
        <h3 className="min-w-0 break-all font-mono text-lg font-semibold tracking-tight">{operation.path}</h3>
      </div>
      {operation.summary && <p className="mt-2 break-words text-sm">{operation.summary}</p>}
      {operation.deprecated && (
        <p className="mt-2 text-xs font-medium text-muted-foreground">Deprecated in this specification</p>
      )}
      <div className="mt-5 grid divide-y border-y sm:grid-cols-2 sm:divide-x sm:divide-y-0">
        <section aria-label="Specification authentication" className="min-w-0 py-4 sm:pr-4">
          <h4 className="text-xs text-muted-foreground">Specification</h4>
          <p className="mt-2 text-sm font-semibold">{requirementNames[security.state]}</p>
          {security.alternatives.map((group, index) => (
            <div key={index} className="mt-1 break-words text-xs leading-5 text-muted-foreground">
              {index > 0 && <span className="mr-1 italic">or</span>}
              {Object.entries(group)
                .map(([scheme, scopes]) => scheme + (scopes.length ? " (" + scopes.join(", ") + ")" : ""))
                .join(" + ") || "Anonymous access"}
            </div>
          ))}
        </section>
        <section aria-label="Source authentication" className="min-w-0 py-4 sm:pl-4">
          <h4 className="text-xs text-muted-foreground">Scanned source</h4>
          <p className="mt-2 text-sm font-semibold">
            {matches.length === 0
              ? "No matching handler"
              : matches.length > 1
                ? matches.length + " possible handlers"
                : matches[0].authRequired
                  ? "Auth signal recorded"
                  : "No auth signal recorded"}
          </p>
          {!!operation.reviewNotes.length && (
            <p className="mt-1 text-xs leading-5 text-muted-foreground">
              Check the handler and its middleware for the required authentication.
            </p>
          )}
          {matches.map((match) => (
            <Link
              key={match.id}
              href={"/endpoints/" + match.id}
              className="flex min-h-11 items-center gap-1.5 py-1 text-xs text-primary hover:underline"
            >
              <span className="min-w-0 break-all font-mono">
                {match.filePath}:{match.lineStart}
                {match.lineEnd !== match.lineStart && "–" + match.lineEnd}
                {matches.length > 1 && (
                  <span className="mt-1 block font-sans text-muted-foreground">
                    {match.authRequired ? "Auth signal recorded" : "No auth signal recorded"}
                  </span>
                )}
              </span>
              <ArrowUpRight aria-hidden className="size-3.5 shrink-0" />
            </Link>
          ))}
        </section>
      </div>
      <dl className="mt-2 divide-y text-sm">
        {operation.operationId && (
          <div className="grid gap-1 py-3 sm:grid-cols-[6rem_minmax(0,1fr)]">
            <dt className="text-xs text-muted-foreground">Operation ID</dt>
            <dd className="break-all font-mono text-xs">{operation.operationId}</dd>
          </div>
        )}
        {!!parameters.length && (
          <div className="grid gap-2 py-3 sm:grid-cols-[6rem_minmax(0,1fr)]">
            <dt className="text-xs text-muted-foreground">Parameters</dt>
            <dd>
              <ul className="space-y-1.5">
                {parameters.map((param) => (
                  <li key={param.location + ":" + param.name} className="break-all text-xs">
                    <code>{param.name}</code>
                    <span className="ml-2 text-muted-foreground">
                      {param.location} · {param.required ? "required" : "optional"}
                    </span>
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}
        {!!formats.length && (
          <div className="grid gap-1 py-3 sm:grid-cols-[6rem_minmax(0,1fr)]">
            <dt className="text-xs text-muted-foreground">Request body</dt>
            <dd className="break-all text-xs">
              {formats.join(", ")} · {requestBody.required ? "required" : "optional"}
            </dd>
          </div>
        )}
        {!!Object.keys(responses).length && (
          <div className="grid gap-1 py-3 sm:grid-cols-[6rem_minmax(0,1fr)]">
            <dt className="text-xs text-muted-foreground">Response codes</dt>
            <dd className="break-words font-mono text-xs">{Object.keys(responses).join(" · ")}</dd>
          </div>
        )}
      </dl>
      <details className="mt-3 border-t" onToggle={(event) => setShowJson(event.currentTarget.open)}>
        <summary className="min-h-11 cursor-pointer py-3 text-xs font-medium">
          Normalized operation JSON
        </summary>
        {showJson && (
          <CodeHighlight
            language="json"
            lineStart={null}
            filePath="normalized-operation.json"
            code={JSON.stringify(
              {
                pointer: operation.pointer,
                tags: operation.tags,
                security,
                securitySchemes: contract.securitySchemes,
                parameters,
                requestBody,
                responses,
                servers: operation.servers,
                deprecated: operation.deprecated,
              },
              null,
              2,
            )}
          />
        )}
      </details>
    </article>
  );
}

export function SpecificationReview({
  contract,
  comparison,
}: {
  contract: ApiContract;
  comparison: Comparison;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState("");
  const [visible, setVisible] = useState(100);
  const operations = comparison.operations.filter(
    (operation) =>
      (filter === "all" || operation.association === filter) &&
      [operation.method, operation.path, operation.operationId, ...operation.tags]
        .join(" ")
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
  );
  const operation = operations.find((item) => item.pointer === selected) ?? operations[0];
  return (
    <>
      {!!contract.warnings.length && (
        <details className="workbench-panel px-4">
          <summary className="min-h-11 cursor-pointer py-3 text-sm font-medium">
            Extraction warnings ({contract.warnings.length})
          </summary>
          <ul className="mb-4 list-disc space-y-2 pl-5 text-xs text-muted-foreground">
            {contract.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </details>
      )}
      <section aria-label="Contract operations" className="workbench-panel min-w-0 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b px-4 py-3 sm:px-6">
          <h2 className="font-semibold">Operations</h2>
          <p aria-live="polite" className="text-xs tabular-nums text-muted-foreground">
            {operations.length} of {comparison.operations.length} shown
          </p>
        </div>
        <div className="grid min-w-0 xl:grid-cols-[minmax(14rem,0.78fr)_minmax(0,1.8fr)]">
          <div className="min-w-0 border-b xl:border-r xl:border-b-0">
            <div className="grid gap-2 p-4 sm:grid-cols-2 xl:grid-cols-1">
              <label className="relative block">
                <span className="sr-only">Search specification operations</span>
                <Search
                  aria-hidden
                  className="pointer-events-none absolute top-3.5 left-3 size-4 text-muted-foreground"
                />
                <input
                  type="search"
                  className={fieldClass + " pl-9"}
                  value={query}
                  placeholder="Search routes or tags"
                  onChange={(event) => {
                    setQuery(event.target.value);
                    setVisible(100);
                  }}
                />
              </label>
              <select
                aria-label="Filter contract associations"
                className={fieldClass}
                value={filter}
                onChange={(event) => {
                  setFilter(event.target.value);
                  setVisible(100);
                }}
              >
                <option value="all">All associations</option>
                {Object.entries(associationNames).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
              {!!operations.length && (
                <div className="sm:col-span-2 xl:hidden">
                  <label htmlFor="contract-operation" className="mb-1 block text-xs font-medium">
                    Operation
                  </label>
                  <select
                    id="contract-operation"
                    className={fieldClass}
                    value={operation.pointer}
                    onChange={(event) => setSelected(event.target.value)}
                  >
                    {operations.map((item) => (
                      <option key={item.pointer} value={item.pointer}>
                        {item.method} {item.path}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            <div aria-label="Route list" className="hidden max-h-[32rem] overflow-y-auto border-t xl:block">
              {operations.slice(0, visible).map((item) => (
                <button
                  key={item.pointer}
                  type="button"
                  aria-current={operation?.pointer === item.pointer ? "true" : undefined}
                  onClick={() => setSelected(item.pointer)}
                  className={
                    "grid min-h-14 w-full grid-cols-[3rem_minmax(0,1fr)] gap-1.5 border-b border-l-2 px-3 py-3 text-left last:border-b-0 " +
                    (operation?.pointer === item.pointer
                      ? "border-l-primary bg-muted/60"
                      : "border-l-transparent hover:bg-muted/30")
                  }
                >
                  <span className="font-mono text-[11px] font-semibold text-primary">{item.method}</span>
                  <span className="min-w-0 break-all font-mono text-xs">
                    {item.path}
                    <span className="mt-1 block font-sans text-[11px] text-muted-foreground">
                      {associationNames[item.association]}
                    </span>
                  </span>
                </button>
              ))}
              {operations.length > visible && (
                <Button
                  variant="ghost"
                  className="min-h-11 w-full"
                  onClick={() => setVisible((n) => n + 100)}
                >
                  Show more routes
                </Button>
              )}
            </div>
          </div>
          {operation ? (
            <OperationDetail key={operation.pointer} operation={operation} contract={contract} />
          ) : (
            <p className="p-6 text-sm text-muted-foreground">
              {comparison.operations.length
                ? "No operations match these filters."
                : "This document contains no supported operations."}
            </p>
          )}
        </div>
      </section>
      {!!comparison.codeOnly.length && (
        <details className="workbench-panel px-4">
          <summary className="min-h-11 cursor-pointer py-3 text-sm font-medium">
            Source routes missing from this specification ({comparison.codeOnly.length})
          </summary>
          <ul className="mb-3 max-h-72 overflow-auto divide-y">
            {comparison.codeOnly.map((endpoint) => (
              <li key={endpoint.id}>
                <Link
                  href={"/endpoints/" + endpoint.id}
                  className="flex min-h-11 items-center gap-2 break-all py-2 font-mono text-xs text-primary hover:underline"
                >
                  {endpoint.method} {endpoint.path}
                  <ArrowUpRight aria-hidden className="size-3 shrink-0" />
                </Link>
              </li>
            ))}
          </ul>
        </details>
      )}
    </>
  );
}
