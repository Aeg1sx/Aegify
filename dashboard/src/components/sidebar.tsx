"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  ScanSearch,
  AlertTriangle,
  BookOpen,
  Upload,
  Settings,
  FolderKanban,
  Globe,
  Bot,
  Moon,
  Sun,
  Loader2,
  Workflow,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useEffect, useState } from "react";
import { UserMenu } from "@/components/user-menu";

const navSections = [
  {
    label: "Analytics",
    items: [
      { href: "/", label: "Overview", icon: LayoutDashboard },
      { href: "/scans", label: "Scans", icon: ScanSearch },
      { href: "/findings", label: "Findings", icon: AlertTriangle },
    ],
  },
  {
    label: "Security",
    items: [
      { href: "/projects", label: "Projects", icon: FolderKanban },
      { href: "/endpoints", label: "Endpoints", icon: Globe },
      { href: "/agents", label: "AI Agents", icon: Workflow },
      { href: "/llm-scan", label: "LLM Scan", icon: Bot },
    ],
  },
  {
    label: "Tools",
    items: [
      { href: "/rules", label: "Rules", icon: BookOpen },
      { href: "/upload", label: "Upload", icon: Upload },
    ],
  },
  {
    label: "System",
    items: [{ href: "/settings", label: "Settings", icon: Settings }],
  },
];

interface ActiveJob {
  id: string;
  status: string;
  mode: string;
  totalFindings: number;
  reviewedCount: number;
  currentBatch: number;
  totalBatches: number;
  scan: { repository: string };
}

function LlmJobIndicator() {
  const [job, setJob] = useState<ActiveJob | null>(null);

  useEffect(() => {
    let mounted = true;

    async function poll() {
      try {
        const res = await fetch("/api/llm-jobs?active=true&limit=1");
        const data = await res.json();
        if (!mounted) return;
        setJob(data.jobs?.[0] || null);
      } catch {
        // ignore
      }
    }

    poll();
    const interval = setInterval(poll, 5000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (!job) return null;

  const percent =
    job.totalFindings > 0
      ? Math.round((job.reviewedCount / job.totalFindings) * 100)
      : 0;

  return (
    <Link
      href="/llm-scan"
      className="mx-3 mb-2 p-2 rounded-md bg-primary/5 border border-primary/20 hover:bg-primary/10 transition-colors block"
    >
      <div className="flex items-center gap-2 text-xs font-medium text-primary mb-1.5">
        <Loader2 className="h-3 w-3 animate-spin" />
        <span>Reviewing{job.scan?.repository ? ` ${job.scan.repository}` : ""}...</span>
      </div>
      <div className="w-full h-1.5 bg-primary/10 rounded-full overflow-hidden">
        <div
          className="h-full bg-primary rounded-full transition-all duration-500"
          style={{ width: `${Math.max(percent, 2)}%` }}
        />
      </div>
      <p className="text-[10px] text-muted-foreground mt-1">
        {job.currentBatch}/{job.totalBatches} batches — {percent}%
      </p>
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
    localStorage.setItem("theme", next ? "dark" : "light");
  };

  return (
    <button
      onClick={toggle}
      className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-accent transition-colors w-full"
    >
      {dark ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
      {dark ? "Light mode" : "Dark mode"}
    </button>
  );
}

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 border-r border-border bg-sidebar flex flex-col">
      <div className="p-4 border-b border-border">
        <Link href="/" className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-semibold text-lg text-foreground">Aegify</span>
        </Link>
        <p className="text-xs text-muted-foreground mt-1">SAST Dashboard</p>
      </div>
      <nav className="flex-1 p-3 space-y-4 overflow-y-auto">
        {navSections.map((section) => (
          <div key={section.label}>
            <p className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">
              {section.label}
            </p>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive =
                  pathname === item.href ||
                  (item.href !== "/" && pathname.startsWith(item.href));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3 py-1.5 rounded-md text-sm transition-colors relative",
                      isActive
                        ? "bg-accent text-foreground font-medium before:absolute before:left-0 before:top-1 before:bottom-1 before:w-0.5 before:rounded-full before:bg-primary"
                        : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                    )}
                  >
                    <item.icon className="h-4 w-4" />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <LlmJobIndicator />
      <div className="p-3 border-t border-border space-y-1">
        <UserMenu />
        <ThemeToggle />
        <p className="text-[10px] text-muted-foreground/50 px-3">v0.3.0</p>
      </div>
    </aside>
  );
}
