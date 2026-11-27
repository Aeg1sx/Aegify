"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  ChevronDown,
  GitBranch,
  Play,
  RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { SeverityChart } from "@/components/severity-chart";
import { ProjectAccessPanel } from "@/components/project-access-panel";
import { RepoConnector, type RepositoryChoice } from "@/components/repo-connector";
import type { GatewaySummary } from "@/lib/gateway-inventory";
import { repositoryLink, repositoryName } from "@/lib/project-view";

interface Scan {
  gatewayInventory?: GatewaySummary | null;
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  status: string;
  scanType: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  _count: { findings: number };
}
interface Project {
  id: string;
  name: string;
  description: string;
  repositoryUrl: string;
  provider: string;
  ownerSlug: string;
  defaultBranch: string;
  accessRole: string;
  archived: boolean;
  updatedAt: string;
  scans: Scan[];
  scanCount: number;
  scanPage: { page: number; pages: number; limit: number };
  severities: Record<string, number>;
}

const date = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  year: "numeric",
  hour: "numeric",
  minute: "2-digit",
});
const countLabel = (count: number, noun: string) =>
  count.toLocaleString() + " " + noun + (count === 1 ? "" : "s");

function ScanRow({ scan, repository }: { scan: Scan; repository: string }) {
  const finished = scan.status === "completed";
  const ongoing = ["pending", "running", "queued"].includes(scan.status);
  const count = scan._count.findings;
  const result =
    count || finished
      ? countLabel(count, "finding") + (ongoing ? " so far" : "")
      : ongoing
        ? "Awaiting results"
        : "No results recorded";
  const measures = [
    ...(finished || scan.filesScanned > 0 ? [countLabel(scan.filesScanned, "file")] : []),
    ...(finished || scan.duration > 0 ? [scan.duration.toFixed(1) + " s"] : []),
  ];
  return (
    <li>
      <Link className="project-scan-row" href={"/scans/" + encodeURIComponent(scan.id)}>
        <div className="min-w-0 space-y-1">
          <span className="block text-sm font-semibold wrap-anywhere">
            {scan.branch || "Branch not recorded"}
          </span>
          <span className="block text-xs text-muted-foreground wrap-anywhere">
            {scan.commitSha ? <code>{scan.commitSha.slice(0, 8)}</code> : <code>#{scan.id.slice(-8)}</code>}
            {scan.repository && scan.repository !== repository && " · " + scan.repository}
            {scan.scanType === "repo-ai-candidate" && " · AI candidate scan"}
          </span>
        </div>
        <div className="space-y-1">
          <span className="inline-flex items-center gap-2 text-sm capitalize">
            <span data-state={scan.status} aria-hidden className="project-scan-dot" />
            {scan.status || "Unknown"}
          </span>
          <span className="block text-xs text-muted-foreground">
            {result}
            {scan.status === "partial" && " · Partial coverage"}
          </span>
        </div>
        <div className="project-scan-time">
          <time dateTime={scan.createdAt}>{date.format(new Date(scan.createdAt))}</time>
          {measures.length > 0 && <span>{measures.join(" · ")}</span>}
        </div>
      </Link>
      {scan.gatewayInventory && (
        <Link href={"/scans/" + encodeURIComponent(scan.id) + "#gateway-inventory"}
          className="inline-block min-h-11 py-2 text-sm text-primary underline-offset-4 hover:underline">
          Gateway ownership · {scan.gatewayInventory.resolved} resolved · {scan.gatewayInventory.ambiguous} ambiguous
          {" · "}{scan.gatewayInventory.unresolved} unresolved
          {scan.gatewayInventory.inputStatus === "partial" && " · Partial input"}
        </Link>
      )}
    </li>
  );
}

function History({ project, path }: { project: Project; path: string }) {
  const { page, pages, limit } = project.scanPage;
  const pageLink = (value: number) => (value === 1 ? path : path + "?page=" + value);
  return (
    <section aria-labelledby="scan-history" className="project-history min-w-0">
      <header className="project-section-heading">
        <h2 id="scan-history">Scan history</h2>
        <span className="text-sm text-muted-foreground">{countLabel(project.scanCount, "scan")}</span>
      </header>
      {project.scans.length ? (
        <>
          <div aria-hidden className="project-scan-labels">
            <span>Revision</span>
            <span>Scan result</span>
            <span>Recorded</span>
          </div>
          <ol aria-label="Project scan history" className="divide-y border-b">
            {project.scans.map((scan) => (
              <ScanRow key={scan.id} scan={scan} repository={project.ownerSlug} />
            ))}
          </ol>
          {pages > 1 && (
            <nav
              aria-label="Scan history pages"
              className="flex flex-wrap items-center justify-between gap-x-4 pt-1 text-sm"
            >
              <span className="py-2 text-muted-foreground tabular-nums">
                {(page - 1) * limit + 1}–{Math.min(page * limit, project.scanCount)} of {project.scanCount}
              </span>
              <span className="flex gap-4">
                {page > 1 && (
                  <Link className="project-text-link" href={pageLink(page - 1)} scroll={false} rel="prev">
                    <ArrowLeft aria-hidden />
                    Previous
                  </Link>
                )}
                {page < pages && (
                  <Link className="project-text-link" href={pageLink(page + 1)} scroll={false} rel="next">
                    Next
                    <ArrowRight aria-hidden />
                  </Link>
                )}
              </span>
            </nav>
          )}
        </>
      ) : (
        <p className="border-b py-7 text-sm text-muted-foreground">
          No scans have been recorded for this project.
        </p>
      )}
    </section>
  );
}

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  return (
    <Suspense fallback={<p role="status">Loading project…</p>}>
      <ProjectRecord key={id} id={id} />
    </Suspense>
  );
}

type Action = "scan" | "connect" | "disconnect" | "archive" | "restore";

function ProjectRecord({ id }: { id: string }) {
  const router = useRouter();
  const params = useSearchParams();
  const requested = Number(params.get("page"));
  const page = Number.isSafeInteger(requested) && requested > 0 ? Math.min(requested, 100000) : 1;
  const path = "/projects/" + encodeURIComponent(id);
  const api = "/api" + path;
  const [record, setRecord] = useState<{ page: number; project: Project } | null>(null);
  const [loadError, setLoadError] = useState("");
  const [revision, setRevision] = useState(0);
  const [connector, setConnector] = useState(false);
  const [settings, setSettings] = useState(false);
  const [settingsVisited, setSettingsVisited] = useState(false);
  const [confirm, setConfirm] = useState<"archive" | "disconnect" | null>(null);
  const [busy, setBusy] = useState<Action | null>(null);
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const [conflict, setConflict] = useState(false);
  const mutation = useRef<AbortController | null>(null);
  const connectButton = useRef<HTMLButtonElement>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const confirmCancel = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoadError("");
      try {
        const response = await fetch(api + "?scanLimit=10&scanPage=" + page, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(
            [401, 403, 404].includes(response.status)
              ? "This project is unavailable to your account."
              : "The project could not be loaded.",
          );
        }
        const data: Project = await response.json();
        if (!controller.signal.aborted) setRecord({ page, project: data });
      } catch (error) {
        if (!controller.signal.aborted) {
          setRecord(null);
          setLoadError(
            error instanceof Error && error.name === "Error"
              ? error.message
              : "The project could not be loaded.",
          );
        }
      }
    }
    void load();
    return () => controller.abort();
  }, [api, page, revision]);
  useEffect(() => () => mutation.current?.abort(), []);
  useEffect(() => {
    if (confirm) confirmCancel.current?.focus();
  }, [confirm]);

  const project = record?.page === page ? record.project : null;
  function reload() {
    setConfirm(null);
    setActionError("");
    setConflict(false);
    setConnector(false);
    setRevision((value) => value + 1);
  }
  async function act(action: Action, repo?: RepositoryChoice) {
    if (mutation.current || !project) return;
    const controller = new AbortController();
    mutation.current = controller;
    setBusy(action);
    setActionError("");
    setConflict(false);
    setNotice("");
    const updatingRepo = action === "connect" || action === "disconnect";
    const method = updatingRepo ? "PATCH" : action === "archive" ? "DELETE" : "POST";
    const body = updatingRepo
      ? {
          provider: repo?.provider ?? "",
          providerRepoId: repo?.id.replace(/^(gh|gl)-/, "") ?? "",
          ownerSlug: repo?.fullName ?? "",
          repositoryUrl: repo?.url ?? "",
          ...(repo && { defaultBranch: repo.defaultBranch }),
          expectedUpdatedAt: project.updatedAt,
        }
      : action === "scan"
        ? {}
        : undefined;
    try {
      const response = await fetch(api + (action === "scan" || action === "restore" ? "/" + action : ""), {
        method,
        signal: controller.signal,
        ...(body && { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
      });
      const result = await response.json().catch(() => null);
      if (!response.ok) {
        setConflict(response.status === 409 && updatingRepo);
        throw new Error(
          typeof result?.error === "string" ? result.error : "The request could not be completed.",
        );
      }
      if (controller.signal.aborted) return;
      if (action === "scan") {
        router.push("/scans/" + encodeURIComponent(result.scanId));
        return;
      }
      setRecord({
        page,
        project: updatingRepo ? { ...project, ...result } : { ...project, archived: action === "archive" },
      });
      setNotice(
        {
          connect: "Repository connected.",
          disconnect: "Repository disconnected.",
          archive: "Project archived.",
          restore: "Project restored.",
        }[action],
      );
      reload();
      title.current?.focus();
    } catch (error) {
      if (!controller.signal.aborted)
        setActionError(
          error instanceof Error && error.name === "Error"
            ? error.message
            : "The request could not be completed. Try again.",
        );
    } finally {
      mutation.current = null;
      if (!controller.signal.aborted) setBusy(null);
    }
  }
  const back = (
    <Link href={project?.archived ? "/projects?archived=true" : "/projects"} className="project-text-link">
      <ArrowLeft aria-hidden />
      Projects
    </Link>
  );
  if (!project)
    return (
      <div className="space-y-4">
        {back}
        {loadError ? (
          <>
            <p role="alert">{loadError}</p>
            <Button variant="outline" className="min-h-11" onClick={reload}>
              Retry
            </Button>
          </>
        ) : (
          <p role="status" className="text-sm text-muted-foreground">
            Loading project…
          </p>
        )}
      </div>
    );

  const admin = project.accessRole === "admin";
  const active = !project.archived;
  const connected = !!(project.provider && project.ownerSlug);
  const name = repositoryName(project);
  const href = repositoryLink(project.repositoryUrl);
  const canScan = active && connected && (admin || project.accessRole === "maintainer");
  const readFindings = "/findings?projectId=" + encodeURIComponent(id);
  return (
    <article className="project-record min-w-0 pb-6">
      <nav aria-label="Project navigation">{back}</nav>
      <header className="project-masthead">
        <div className="min-w-0">
          {project.archived && (
            <p className="mb-1 text-sm font-medium text-muted-foreground">Archived project</p>
          )}
          <h1 ref={title} tabIndex={-1} className="workbench-title wrap-anywhere">
            {project.name}
          </h1>
          {project.description && (
            <p className="mt-2 max-w-prose text-sm leading-relaxed text-muted-foreground wrap-anywhere">
              {project.description}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="outline" className="min-h-11">
            <Link href={path + "/rule-lab"}>
              <BookOpen aria-hidden />
              Rule lab
            </Link>
          </Button>
          {canScan && (
            <Button className="min-h-11" disabled={!!busy} onClick={() => act("scan")}>
              <Play aria-hidden />
              {busy === "scan" ? "Queuing scan…" : "Start source scan"}
            </Button>
          )}
          {admin && active && !connected && (
            <Button
              ref={connectButton}
              className="min-h-11"
              disabled={!!busy}
              onClick={() => {
                setActionError("");
                setConflict(false);
                setConnector(true);
              }}
            >
              <GitBranch aria-hidden />
              Connect repository
            </Button>
          )}
          {admin && !active && (
            <Button className="min-h-11" disabled={!!busy} onClick={() => act("restore")}>
              <RotateCcw aria-hidden />
              Restore project
            </Button>
          )}
        </div>
      </header>
      <dl className="project-facts">
        <div>
          <dt>Repository</dt>
          <dd>
            {name ? (
              href ? (
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex max-w-full items-center gap-1.5 hover:text-primary hover:underline"
                >
                  <span className="wrap-anywhere">{name}</span>
                  <ArrowUpRight aria-hidden className="size-3.5 shrink-0" />
                </a>
              ) : (
                name
              )
            ) : (
              "No repository connected"
            )}
          </dd>
        </div>
        <div>
          <dt>Default branch</dt>
          <dd className="font-mono">{project.defaultBranch || "Not recorded"}</dd>
        </div>
        <div>
          <dt>Your role</dt>
          <dd className="capitalize">{project.accessRole}</dd>
        </div>
      </dl>
      {project.archived && (
        <p className="mt-3 text-sm text-muted-foreground">
          Scan history is available. New source scans and CI uploads are paused.
        </p>
      )}
      {notice && (
        <p className="mt-3 text-sm text-primary" role="status">
          {notice}
        </p>
      )}
      {actionError && !connector && (
        <div className="mt-3">
          <p role="alert" className="text-sm text-destructive">
            {actionError}
          </p>
          {conflict && (
            <Button className="min-h-11" variant="link" onClick={reload}>
              Reload project
            </Button>
          )}
        </div>
      )}
      <div className="project-workspace">
        <section className="project-findings min-w-0" aria-labelledby="project-findings">
          <header className="project-section-heading">
            <h2 id="project-findings">Current findings</h2>
            <Link
              className="project-text-link text-sm"
              aria-label="View all findings for this project"
              href={readFindings}
            >
              View all
              <ArrowRight aria-hidden />
            </Link>
          </header>
          <SeverityChart severities={project.severities} projectId={project.id} />
        </section>
        <History project={project} path={path} />
      </div>
      {admin && (
        <section className="mt-6 border-y">
          <button
            type="button"
            className="flex min-h-12 w-full items-center justify-between gap-3 py-2 text-left font-semibold hover:text-primary"
            aria-expanded={settings}
            aria-controls="project-settings"
            onClick={() => {
              setSettings(!settings);
              setSettingsVisited(true);
            }}
          >
            Project settings
            <ChevronDown aria-hidden className={"size-4 " + (settings ? "rotate-180" : "")} />
          </button>
          <div hidden={!settings} id="project-settings" className="pb-4">
            {settingsVisited && (
              <>
                <ProjectAccessPanel
                  key={project.archived ? "archived" : "active"}
                  projectId={id}
                  archived={project.archived}
                />
                {active && (
                  <div className="mt-4 flex flex-wrap items-center gap-3 border-t pt-3">
                    {confirm ? (
                      <>
                        <p className="w-full text-sm">
                          {confirm === "archive"
                            ? "Archiving pauses new scans and CI uploads. Scan history stays available."
                            : "Disconnecting removes the repository link. Existing scan results stay available."}
                        </p>
                        <Button
                          ref={confirmCancel}
                          className="min-h-11"
                          variant="outline"
                          disabled={!!busy}
                          onClick={() => {
                            setConfirm(null);
                            requestAnimationFrame(() =>
                              document.getElementById("project-" + confirm)?.focus(),
                            );
                          }}
                        >
                          Cancel
                        </Button>
                        <Button className="min-h-11" disabled={!!busy} onClick={() => act(confirm)}>
                          {confirm === "archive" ? "Confirm archive" : "Confirm disconnect"}
                        </Button>
                      </>
                    ) : (
                      <>
                        {connected && (
                          <Button
                            className="min-h-11"
                            variant="outline"
                            id="project-disconnect"
                            onClick={() => setConfirm("disconnect")}
                          >
                            Disconnect repository
                          </Button>
                        )}
                        <Button
                          className="min-h-11"
                          variant="outline"
                          id="project-archive"
                          onClick={() => setConfirm("archive")}
                        >
                          Archive project
                        </Button>
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </section>
      )}
      {connector && admin && active && !connected && (
        <RepoConnector
          onClose={() => {
            setConnector(false);
            setActionError("");
            setConflict(false);
          }}
          onReturnFocus={() => (connectButton.current || title.current)?.focus()}
          busy={busy === "connect"}
          error={actionError}
          onReload={conflict ? reload : undefined}
          onSelect={(repo) => act("connect", repo)}
        />
      )}
    </article>
  );
}
