"use client";

import { useEffect, useRef, useState } from "react";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";

export type AuditPage = {
  events: { id: string; action: string; actorId: string; targetId: string; createdAt: string }[];
  nextCursor: string | null;
};

export function ProjectAuditHistory({ url, first }: { url: string; first: AuditPage }) {
  const [current, setCurrent] = useState<{ page: AuditPage; cursor: string | null } | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [denied, setDenied] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  const page = current?.page ?? first;

  async function navigate(direction: "older" | "newer") {
    if (active.current || (direction === "older" ? !page.nextCursor : !history.length)) return;
    const cursor = direction === "older" ? page.nextCursor : history[history.length - 1];
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: "15" });
      if (cursor) params.set("cursor", cursor);
      const response = await fetch(url + "?" + params, { cache: "no-store", signal: controller.signal });
      if ([401, 403, 404].includes(response.status)) {
        setDenied(true);
        return;
      }
      if (!response.ok) throw new Error();
      const result: AuditPage = await response.json();
      if (controller.signal.aborted) return;
      setHistory(direction === "older" ? [...history, current?.cursor ?? null] : history.slice(0, -1));
      setCurrent({ page: result, cursor });
    } catch {
      if (!controller.signal.aborted) setError("Could not load audit events. Try again.");
    } finally {
      active.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  return (
    <section aria-labelledby="project-events-heading">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <h3 id="project-events-heading">Project audit log</h3>
        {!denied && <a href={url + "?format=jsonl"} className="project-text-link inline-flex min-h-11 items-center gap-2">
          <Download aria-hidden className="size-4" />Download JSONL
        </a>}
      </div>
      {denied ? <p role="alert">You no longer have access to this audit log.</p> : <>
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        {page.events.length ? (
          <ol aria-label="Audit events" aria-busy={busy} className="divide-y border-y">
            {page.events.map((event) => (
              <li key={event.id} className="justify-between">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{event.action.replaceAll(".", " ").replaceAll("_", " ")}</p>
                  <p className="text-xs text-muted-foreground">Actor {event.actorId} · Target {event.targetId}</p>
                </div>
                <time className="text-xs text-muted-foreground" dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time>
              </li>
            ))}
          </ol>
        ) : <p className="text-sm text-muted-foreground">No recorded events yet.</p>}
        {(history.length > 0 || page.nextCursor) && <nav aria-label="Audit history pages" className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" disabled={busy || !history.length} onClick={() => navigate("newer")}>Newer events</Button>
          <Button variant="outline" size="sm" disabled={busy || !page.nextCursor} onClick={() => navigate("older")}>Older events</Button>
          <span role="status" className="text-xs text-muted-foreground">{busy ? "Loading events…" : `Page ${history.length + 1}`}</span>
        </nav>}
      </>}
    </section>
  );
}
