import { useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { scanFindingsHref } from "@/lib/finding-view";

export interface RepositoryCoverage {
  repositoryId: string;
  analyzedFiles: number;
  discoveryErrors: number;
}

const pageSize = 10;

export function RepositoryCoveragePanel({ scanId, rows }: { scanId: string; rows: RepositoryCoverage[] }) {
  const [page, setPage] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);
  const pages = Math.ceil(rows.length / pageSize);
  const currentPage = Math.min(page, Math.max(0, pages - 1));
  const start = currentPage * pageSize;
  function changePage(next: number) {
    setPage(next);
    heading.current?.focus();
  }

  return (
    <section aria-labelledby="repository-coverage" className="workbench-panel">
      <div className="workbench-heading flex-wrap">
        <h2 ref={heading} tabIndex={-1} id="repository-coverage" className="rounded-sm text-lg font-semibold focus-visible:outline-2 focus-visible:outline-ring">Repository coverage</h2>
        <span className="ml-auto text-sm tabular-nums text-muted-foreground">
          {rows.length.toLocaleString()} {rows.length === 1 ? "repository" : "repositories"}
        </span>
      </div>
      <table aria-labelledby="repository-coverage" className="w-full table-fixed text-sm">
        <colgroup>
          <col className="w-[46%] sm:w-[60%]" />
          <col />
          <col />
        </colgroup>
        <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
          <tr>
            <th scope="col" className="px-3 py-2 text-left font-medium sm:px-5">Repository</th>
            <th scope="col" className="px-2 py-2 text-right font-medium sm:px-5">Analyzed files</th>
            <th scope="col" className="px-3 py-2 text-right font-medium sm:px-5">Discovery errors</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.slice(start, start + pageSize).map((row) => (
            <tr key={row.repositoryId}>
              <th scope="row" className="px-3 text-left font-normal sm:px-5">
                <Link prefetch={false} href={scanFindingsHref(scanId, row.repositoryId)}
                  aria-label={`Review findings for ${row.repositoryId}`}
                  className="inline-flex min-h-11 max-w-full items-center gap-1.5 rounded-sm py-1.5 font-mono text-xs text-primary underline decoration-primary/35 underline-offset-4 hover:decoration-current focus-visible:outline-2 focus-visible:outline-ring">
                  <span className="min-w-0 [overflow-wrap:anywhere]">{row.repositoryId}</span>
                  <ArrowUpRight aria-hidden className="size-3.5 shrink-0" />
                </Link>
              </th>
              <td className="px-2 text-right tabular-nums [overflow-wrap:anywhere] sm:px-5">{row.analyzedFiles.toLocaleString()}</td>
              <td className={`px-3 text-right tabular-nums [overflow-wrap:anywhere] sm:px-5 ${row.discoveryErrors > 0 ? "font-semibold text-[var(--severity-medium)]" : ""}`}>
                {row.discoveryErrors.toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {pages > 1 && <nav aria-label="Repository coverage pages" className="flex flex-wrap items-center justify-end gap-2 border-t px-3 py-2 sm:px-5">
        <span aria-live="polite" aria-atomic="true" className="mr-auto text-xs tabular-nums text-muted-foreground">
          Page {currentPage + 1} of {pages}
        </span>
        <Button type="button" variant="outline" className="min-h-11" disabled={currentPage === 0}
          onClick={() => changePage(currentPage - 1)}>Previous</Button>
        <Button type="button" variant="outline" className="min-h-11" disabled={currentPage + 1 >= pages}
          onClick={() => changePage(currentPage + 1)}>Next</Button>
      </nav>}
    </section>
  );
}
