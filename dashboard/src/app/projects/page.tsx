"use client";

import { Suspense, useEffect, useRef, useState, type FormEvent } from "react";
import Link from "next/link";
import { replaceHistorySearch, useHistorySearch } from "@/lib/use-history-search";
import { Archive, ArrowUpRight, Plus, RotateCcw, Search } from "lucide-react";
import { repositoryName } from "@/lib/project-view";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface ProjectSummary {
  id: string;
  name: string;
  description: string;
  repositoryUrl: string;
  ownerSlug?: string;
  accessRole: string;
  archived: boolean;
  color: string;
  scanCount: number;
  findingCount: number;
  lastScan: { id: string; createdAt: string; status: string } | null;
}

const scanDate = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });
const columns = "xl:grid-cols-[minmax(0,1fr)_4rem_7rem_10rem_6rem]";

export default function ProjectsPage() {
  return (
    <Suspense fallback={<p role="status">Loading projects…</p>}>
      <ProjectDirectory />
    </Suspense>
  );
}

function ProjectDirectory() {
  const params = useHistorySearch();
  const archived = params.get("archived") === "true";
  const query = params.get("q") || "";
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [canCreate, setCanCreate] = useState(false);
  const [listState, setListState] = useState<"loading" | "ready" | "error">("loading");
  const [revision, setRevision] = useState(0);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const mutation = useRef<AbortController | null>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const newButton = useRef<HTMLButtonElement>(null);
  const archiveView = useRef<HTMLButtonElement>(null);
  const message = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setListState("loading");
      try {
        const response = await fetch(archived ? "/api/projects?archived=true" : "/api/projects", {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error();
        const data = await response.json();
        if (!Array.isArray(data.projects)) throw new Error();
        if (controller.signal.aborted) return;
        setProjects(data.projects);
        setCanCreate(data.canCreate === true);
        setListState("ready");
      } catch {
        if (!controller.signal.aborted) setListState("error");
      }
    }
    void load();
    return () => controller.abort();
  }, [archived, revision]);

  useEffect(() => () => mutation.current?.abort(), []);
  useEffect(() => {
    if (showForm && !archived) nameInput.current?.focus();
  }, [showForm, archived]);
  useEffect(() => {
    if (error) message.current?.focus();
  }, [error]);

  function filter(key: "q" | "archived", value: string) {
    const url = new URL(window.location.href);
    if (value) url.searchParams.set(key, value);
    else url.searchParams.delete(key);
    replaceHistorySearch(url);
  }

  function selectView(next: boolean) {
    if (next === archived) return;
    setListState("loading");
    setShowForm(false);
    setNotice("");
    setError("");
    filter("archived", next ? "true" : "");
  }

  async function save(path: string, options: RequestInit, fallback: string) {
    if (mutation.current) return false;
    const controller = new AbortController();
    mutation.current = controller;
    setSaving(true);
    setNotice("");
    setError("");
    try {
      const response = await fetch(path, { ...options, signal: controller.signal });
      if (!response.ok) {
        const data = await response.json().catch(() => null);
        throw new Error(typeof data?.error === "string" ? data.error : fallback);
      }
      return true;
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(reason instanceof Error && reason.name !== "TypeError" ? reason.message : fallback);
      return false;
    } finally {
      mutation.current = null;
      if (!controller.signal.aborted) setSaving(false);
    }
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get("name") || "").trim();
    if (!name) {
      nameInput.current?.setCustomValidity("Enter a project name.");
      nameInput.current?.reportValidity();
      return;
    }
    const ok = await save(
      "/api/projects",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          repositoryUrl: String(data.get("repository") || "").trim(),
          description: String(data.get("description") || "").trim(),
        }),
      },
      "The project could not be created.",
    );
    if (ok) {
      setShowForm(false);
      setNotice(name + " created.");
      filter("q", "");
      setRevision((value) => value + 1);
      newButton.current?.focus();
    }
  }

  async function changeArchive(project: ProjectSummary) {
    const path = "/api/projects/" + encodeURIComponent(project.id);
    const ok = await save(
      project.archived ? path + "/restore" : path,
      { method: project.archived ? "POST" : "DELETE" },
      project.archived ? "The project could not be restored." : "The project could not be archived.",
    );
    if (ok) {
      setNotice(project.name + (project.archived ? " restored." : " archived."));
      setRevision((value) => value + 1);
      archiveView.current?.focus();
    }
  }

  const searchTerm = query.trim().toLowerCase();
  const visible = projects.filter((project) =>
    [project.name, project.description, repositoryName(project)].some((value) =>
      value.toLowerCase().includes(searchTerm),
    ),
  );

  return (
    <div className="min-w-0 space-y-5 pb-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="workbench-title">Projects</h1>
        {canCreate && !archived && (
          <Button
            ref={newButton}
            className="min-h-11"
            disabled={saving}
            aria-expanded={showForm}
            aria-controls="create-project"
            onClick={() => {
              setShowForm(!showForm);
              setError("");
              setNotice("");
            }}
          >
            {!showForm && <Plus aria-hidden className="size-4" />}
            {showForm ? "Cancel" : "New project"}
          </Button>
        )}
      </header>
      {showForm && canCreate && !archived && (
        <form
          id="create-project"
          aria-labelledby="create-heading"
          onSubmit={create}
          className="workbench-panel"
        >
          <h2 id="create-heading" className="workbench-heading text-base font-semibold">
            New project
          </h2>
          <div className="grid gap-4 p-4 sm:grid-cols-2 sm:p-5">
            <label className="grid gap-1.5 text-sm font-medium">
              Project name
              <Input
                ref={nameInput}
                name="name"
                required
                className="h-11"
                onInput={(event) => event.currentTarget.setCustomValidity("")}
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium">
              <span>
                Repository URL <span className="font-normal text-muted-foreground">(optional)</span>
              </span>
              <Input
                name="repository"
                inputMode="url"
                autoCapitalize="none"
                spellCheck={false}
                className="h-11"
              />
            </label>
            <label className="grid gap-1.5 text-sm font-medium sm:col-span-2">
              <span>
                Description <span className="font-normal text-muted-foreground">(optional)</span>
              </span>
              <Input name="description" className="h-11" />
            </label>
            <Button type="submit" disabled={saving} className="min-h-11 w-fit">
              {saving ? "Saving…" : "Create project"}
            </Button>
          </div>
        </form>
      )}
      {error && (
        <p role="alert" ref={message} tabIndex={-1} className="border-l-2 border-destructive pl-3 text-sm">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 border-b">
        <div role="group" aria-label="Project list" className="flex gap-5">
          {[false, true].map((mode) => (
            <button
              key={String(mode)}
              ref={mode === archived ? archiveView : undefined}
              type="button"
              aria-pressed={archived === mode}
              disabled={saving}
              onClick={() => selectView(mode)}
              className="min-h-11 border-b-2 border-transparent px-1 text-sm text-muted-foreground hover:text-foreground aria-pressed:border-primary aria-pressed:font-semibold aria-pressed:text-foreground"
            >
              {mode ? "Archived" : "Active"}
            </button>
          ))}
        </div>
        <label className="relative mb-2 min-w-0 basis-full sm:basis-64">
          <span className="sr-only">Find a project</span>
          <Search
            aria-hidden
            className="pointer-events-none absolute left-3 top-3.5 size-4 text-muted-foreground"
          />
          <Input
            type="search"
            value={query}
            placeholder="Find a project…"
            className="h-11 pl-9"
            onChange={(event) => filter("q", event.target.value)}
          />
        </label>
      </div>
      {listState === "loading" ? (
        <p role="status" className="py-3 text-sm text-muted-foreground">
          Loading projects…
        </p>
      ) : listState === "error" ? (
        <div role="alert">
          <p className="text-sm">The project list could not be loaded.</p>
          <button
            className="min-h-11 text-sm font-semibold text-primary"
            onClick={() => setRevision((value) => value + 1)}
          >
            Retry
          </button>
        </div>
      ) : !visible.length ? (
        <div className="py-4">
          <p role="status" className="text-sm text-muted-foreground">
            {searchTerm
              ? "No projects match your search."
              : archived
                ? "No archived projects."
                : "No active projects."}
          </p>
          {searchTerm && (
            <button className="min-h-11 text-sm font-semibold text-primary" onClick={() => filter("q", "")}>
              Clear search
            </button>
          )}
        </div>
      ) : (
        <section aria-label={archived ? "Archived projects" : "Active projects"}>
          <div
            aria-hidden
            className={
              "hidden items-end gap-4 border-b px-2 pb-2 text-xs text-muted-foreground xl:grid " + columns
            }
          >
            <span>Project</span>
            <span>Scans</span>
            <span>Latest findings</span>
            <span>Last scan</span>
          </div>
          <ul aria-label="Project records" className="divide-y border-b">
            {visible.map((project) => {
              const repository = repositoryName(project);
              return (
                <li
                  key={project.id}
                  className={
                    "grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-4 gap-y-2 px-2 py-4 " + columns
                  }
                >
                  <div className="min-w-0">
                    <Link
                      href={"/projects/" + project.id}
                      className="inline-flex min-h-11 max-w-full items-center gap-2 font-semibold leading-5 hover:text-primary hover:underline"
                    >
                      {project.color && project.color !== "#6366f1" && (
                        <span
                          aria-hidden
                          className="size-2 shrink-0 rounded-full"
                          style={{ backgroundColor: project.color }}
                        />
                      )}
                      <span className="break-words [overflow-wrap:anywhere]">{project.name}</span>
                    </Link>
                    {repository && (
                      <p className="break-all font-mono text-xs text-muted-foreground">{repository}</p>
                    )}
                    {project.description && (
                      <p className="mt-1.5 break-words text-sm leading-5 text-muted-foreground">
                        {project.description}
                      </p>
                    )}
                  </div>
                  <dl className="col-span-2 flex flex-wrap gap-x-6 gap-y-2 text-sm xl:contents">
                    <div className="xl:pt-3">
                      <dt className="text-xs text-muted-foreground xl:sr-only">Scans</dt>
                      <dd className="font-mono tabular-nums">{project.scanCount.toLocaleString()}</dd>
                    </div>
                    <div className="xl:pt-3">
                      <dt className="text-xs text-muted-foreground xl:sr-only">Latest findings</dt>
                      <dd className="font-mono tabular-nums">
                        {!project.lastScan ? (
                          <>
                            <span aria-hidden>—</span>
                            <span className="sr-only">No scan yet</span>
                          </>
                        ) : !project.findingCount &&
                          ["pending", "running"].includes(project.lastScan.status) ? (
                          <span className="font-sans text-muted-foreground">Pending</span>
                        ) : (
                          project.findingCount.toLocaleString()
                        )}
                      </dd>
                    </div>
                    <div className="min-w-0">
                      <dt className="text-xs text-muted-foreground xl:sr-only">Last scan</dt>
                      <dd>
                        {project.lastScan ? (
                          <Link
                            href={"/scans/" + project.lastScan.id}
                            className="inline-flex min-h-11 items-center gap-1.5 text-sm hover:text-primary hover:underline"
                          >
                            <span>
                              <span className="block capitalize">{project.lastScan.status}</span>
                              <time
                                className="text-xs text-muted-foreground"
                                dateTime={project.lastScan.createdAt}
                              >
                                {scanDate.format(new Date(project.lastScan.createdAt))}
                              </time>
                            </span>
                            <ArrowUpRight aria-hidden className="size-3.5 shrink-0 text-muted-foreground" />
                          </Link>
                        ) : (
                          <span className="text-sm text-muted-foreground xl:block xl:pt-3">No scans yet</span>
                        )}
                      </dd>
                    </div>
                  </dl>
                  {project.accessRole === "admin" && (
                    <button
                      type="button"
                      disabled={saving}
                      aria-label={(archived ? "Restore " : "Archive ") + project.name}
                      onClick={() => void changeArchive(project)}
                      className="col-start-2 row-start-1 inline-flex min-h-11 items-center justify-self-end gap-1.5 px-1 text-sm text-muted-foreground hover:text-foreground hover:underline xl:col-start-5"
                    >
                      {archived ? (
                        <RotateCcw aria-hidden className="size-3.5" />
                      ) : (
                        <Archive aria-hidden className="size-3.5" />
                      )}
                      {archived ? "Restore" : "Archive"}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </div>
  );
}
