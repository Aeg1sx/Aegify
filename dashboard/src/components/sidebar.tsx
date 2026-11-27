"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Menu,
  LayoutDashboard,
  ScanSearch,
  AlertTriangle,
  BookOpen,
  Upload,
  Settings,
  FolderKanban,
  Globe,
  ClipboardList,
  Moon,
  Sun,
  Clock,
  Workflow,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useEffect, useState, useSyncExternalStore } from "react";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { UserMenu } from "@/components/user-menu";
import { WorkspaceBrand } from "@/components/workspace-brand";

const navSections = [
  {
    label: "Workspace",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard },
      { href: "/scans", label: "Scans", icon: ScanSearch },
      { href: "/findings", label: "Findings", icon: AlertTriangle },
    ],
  },
  {
    label: "Analysis",
    items: [
      { href: "/projects", label: "Projects", icon: FolderKanban },
      { href: "/endpoints", label: "Endpoints", icon: Globe },
      { href: "/api-specs", label: "API specifications", icon: BookOpen },
      { href: "/agents", label: "AI agents", icon: Workflow },
      { href: "/llm-scan", label: "AI reviews", icon: ClipboardList },
    ],
  },
  {
    label: "Tools",
    items: [
      { href: "/rules", label: "Rules", icon: BookOpen },
      { href: "/upload", label: "Import scan", icon: Upload },
    ],
  },
  {
    label: "System",
    items: [{ href: "/settings", label: "Settings", icon: Settings }],
  },
];

interface ActiveJob {
  status: string;
  totalFindings: number;
  reviewedCount: number;
  scan: { repository: string };
}

function LlmJobIndicator() {
  const [job, setJob] = useState<ActiveJob | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        const response = await fetch("/api/llm-jobs?active=true&limit=1", { signal: controller.signal, cache: "no-store" });
        if (!response.ok) throw new Error();
        const data = await response.json();
        if (!controller.signal.aborted) setJob(data.jobs?.[0] ?? null);
      } catch {
        if (!controller.signal.aborted) setJob(null);
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(poll, 5000);
      }
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, []);

  if (!job) return null;

  const queued = job.status === "pending";

  return (
    <Link
      href="/llm-scan"
      data-review-state={job.status}
      className="mx-3 block border-t border-sidebar-border px-3 py-3 text-sm hover:bg-sidebar-accent"
    >
      <span className="flex items-center gap-2 font-medium">
        {queued ? <Clock aria-hidden className="size-3.5" /> : <ClipboardList aria-hidden className="size-3.5" />}
        {queued ? "Review queued" : "Active review"}
      </span>
      {job.scan?.repository && <span className="mt-1 block wrap-anywhere text-xs text-muted-foreground">{job.scan.repository}</span>}
      {!queued && job.totalFindings > 0 && <>
        <progress className="my-1.5 block h-1 w-full accent-primary" aria-label="Findings reviewed in active run" value={job.reviewedCount} max={job.totalFindings} />
        <span className="block text-xs tabular-nums text-muted-foreground">{job.reviewedCount}/{job.totalFindings} reviewed</span>
      </>}
    </Link>
  );
}

function ThemeToggle() {
  const [dark, setDark] = useState(false);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      setDark(document.documentElement.classList.contains("dark"));
    });
    return () => cancelAnimationFrame(frame);
  }, []);

  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    try { localStorage.setItem("theme", next ? "dark" : "light"); } catch { /* The session theme still applies. */ }
  };

  return (
    <button
      type="button"
      onClick={toggle}
      className="flex items-center gap-2 px-3 min-h-11 rounded-md text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-colors w-full"
    >
      {dark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
      {dark ? "Light mode" : "Dark mode"}
    </button>
  );
}

const mobileQuery = "(max-width: 47.999rem)";
function listenViewport(notify: () => void) {
  const query = window.matchMedia(mobileQuery);
  query.addEventListener("change", notify);
  return () => query.removeEventListener("change", notify);
}
const mobileViewport = () => window.matchMedia(mobileQuery).matches;
const serverViewport = () => false;

function Navigation({ pathname, workspaceAdmin, onNavigate }: {
  pathname: string; workspaceAdmin: boolean; onNavigate?: () => void;
}) {
  return <>
    <div className="px-5 pb-3 pt-4"><WorkspaceBrand onNavigate={onNavigate} /></div>
    <nav aria-label="Workspace" className="min-h-0 flex-1 space-y-5 overflow-y-auto px-3 pb-5 pt-3">
      {navSections.map((section) => {
        const items = section.items.filter((item) => workspaceAdmin || !["/settings", "/rules"].includes(item.href));
        if (!items.length) return null;
        return <div key={section.label}>
          <p className="mb-1.5 px-3 text-xs font-semibold text-muted-foreground">{section.label}</p>
          <ul>{items.map((item) => {
            const active = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href + "/"));
            return <li key={item.href}><Link href={item.href} onClick={onNavigate} aria-current={active ? "page" : undefined}
              className={cn("workspace-nav-link flex min-h-11 items-center gap-3 rounded-sm px-3 text-sm transition-colors md:min-h-9",
                active ? "bg-sidebar-accent font-semibold text-sidebar-accent-foreground" : "text-sidebar-foreground hover:bg-sidebar-accent/60")}>
              <item.icon aria-hidden className="size-4 shrink-0" /><span>{item.label}</span>
            </Link></li>;
          })}</ul>
        </div>;
      })}
    </nav>
    <LlmJobIndicator />
    <div className="shrink-0 border-t border-sidebar-border p-3"><UserMenu /><ThemeToggle /><p className="px-3 pt-1 font-mono text-xs text-muted-foreground">v0.3.0-beta.1</p></div>
  </>;
}

function MobileNavigation({ pathname, workspaceAdmin }: { pathname: string; workspaceAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  return <header className="workspace-rail app-sidebar flex shrink-0 items-center justify-between border-b border-sidebar-border px-4 py-1.5 md:hidden">
    <WorkspaceBrand />
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild><button type="button" aria-label="Open navigation" className="grid size-11 place-items-center rounded-md hover:bg-sidebar-accent"><Menu aria-hidden className="size-5" /></button></SheetTrigger>
      <SheetContent side="left" aria-describedby={undefined} className="workspace-rail flex h-dvh w-72 max-w-[90vw] flex-col gap-0 border-sidebar-border p-0 [&_[data-slot=sheet-close]]:size-10">
        <SheetTitle className="sr-only">Workspace navigation</SheetTitle>
        <Navigation pathname={pathname} workspaceAdmin={workspaceAdmin} onNavigate={() => setOpen(false)} />
      </SheetContent>
    </Sheet>
  </header>;
}

export function Sidebar() {
  const pathname = usePathname();
  const mobile = useSyncExternalStore(listenViewport, mobileViewport, serverViewport);
  const [workspaceAdmin, setWorkspaceAdmin] = useState(false);
  const authPage = pathname.startsWith("/auth/");
  useEffect(() => {
    if (authPage) return;
    const controller = new AbortController();
    fetch("/api/account/access", { signal: controller.signal })
      .then((response) => response.ok ? response.json() : { workspaceAdmin: false })
      .then((access) => { if (!controller.signal.aborted) setWorkspaceAdmin(access.workspaceAdmin === true); })
      .catch(() => { if (!controller.signal.aborted) setWorkspaceAdmin(false); });
    return () => controller.abort();
  }, [authPage, pathname]);
  if (authPage) return null;
  if (mobile) return <MobileNavigation key={pathname} pathname={pathname} workspaceAdmin={workspaceAdmin} />;
  return <aside className="workspace-rail app-sidebar hidden w-48 shrink-0 flex-col border-r border-sidebar-border md:flex xl:w-52">
    <Navigation pathname={pathname} workspaceAdmin={workspaceAdmin} />
  </aside>;
}
