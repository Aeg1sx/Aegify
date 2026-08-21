"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityChart } from "@/components/severity-chart";
import { RepoConnector } from "@/components/repo-connector";
import {
  ArrowLeft,
  ScanSearch,
  AlertTriangle,
  Clock,
  Trash2,
  ExternalLink,
  GitBranch,
  Unplug,
  Loader2,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";

interface ScanSummary {
  id: string;
  repository: string;
  branch: string;
  status: string;
  scanType: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  _count: { findings: number };
}

interface ProjectDetail {
  id: string;
  name: string;
  repositoryUrl: string;
  defaultBranch: string;
  description: string;
  color: string;
  provider: string;
  providerRepoId: string;
  ownerSlug: string;
  createdAt: string;
  scans: ScanSummary[];
  severities: Record<string, number>;
  totalFindings: number;
}

export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [project, setProject] = useState<ProjectDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [connectorOpen, setConnectorOpen] = useState(false);
  const [scanning, setScanning] = useState(false);

  const fetchProject = useCallback(() => {
    fetch(`/api/projects/${params.id}`)
      .then((r) => r.json())
      .then(setProject)
      .finally(() => setLoading(false));
  }, [params.id]);

  useEffect(() => {
    fetchProject();
  }, [fetchProject]);

  const deleteProject = async () => {
    if (!confirm("Delete this project? Scans will be unlinked, not deleted.")) return;
    await fetch(`/api/projects/${params.id}`, { method: "DELETE" });
    router.push("/projects");
  };

  const connectRepo = async (repo: {
    provider: string;
    id: string;
    fullName: string;
    url: string;
    defaultBranch: string;
  }) => {
    // Extract numeric ID from "gh-123" or "gl-456"
    const numericId = repo.id.replace(/^(gh|gl)-/, "");

    await fetch(`/api/projects/${params.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: repo.provider,
        providerRepoId: numericId,
        ownerSlug: repo.fullName,
        repositoryUrl: repo.url,
        defaultBranch: repo.defaultBranch,
      }),
    });

    setConnectorOpen(false);
    fetchProject();
  };

  const disconnectRepo = async () => {
    if (!confirm("Disconnect repository from this project?")) return;
    await fetch(`/api/projects/${params.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        provider: "",
        providerRepoId: "",
        ownerSlug: "",
      }),
    });
    fetchProject();
  };

  const startRepoScan = async () => {
    setScanning(true);
    try {
      await fetch(`/api/projects/${params.id}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      // Poll for completion
      const poll = setInterval(() => {
        fetch(`/api/projects/${params.id}`)
          .then((r) => r.json())
          .then((data) => {
            setProject(data);
            const hasRunning = data.scans?.some(
              (s: ScanSummary) => s.status === "running",
            );
            if (!hasRunning) {
              clearInterval(poll);
              setScanning(false);
            }
          });
      }, 3000);
      // Safety: stop polling after 5 minutes
      setTimeout(() => {
        clearInterval(poll);
        setScanning(false);
      }, 300_000);
    } catch {
      setScanning(false);
    }
  };

  if (loading || !project) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const hasRepo = !!project.provider && !!project.ownerSlug;

  return (
    <div className="space-y-6">
      <div className="flex items-start gap-3">
        <Link href="/projects" className="text-muted-foreground hover:text-foreground mt-1">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <div
              className="w-4 h-4 rounded-full"
              style={{ backgroundColor: project.color }}
            />
            <h1 className="text-2xl font-bold">{project.name}</h1>
          </div>
          {project.description && (
            <p className="text-muted-foreground mt-1">{project.description}</p>
          )}
          {project.repositoryUrl && (
            <a
              href={project.repositoryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-primary hover:underline flex items-center gap-1 mt-1"
            >
              {project.repositoryUrl}
              <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>
        <Button variant="outline" size="sm" onClick={deleteProject}>
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>

      {/* Repository Connection Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <GitBranch className="h-5 w-5" />
            Repository
          </CardTitle>
        </CardHeader>
        <CardContent>
          {hasRepo ? (
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <ProviderIcon provider={project.provider} />
                <div>
                  <p className="text-sm font-medium">{project.ownerSlug}</p>
                  <p className="text-xs text-muted-foreground">
                    {project.defaultBranch || "main"} &middot; {project.provider}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="default"
                  size="sm"
                  onClick={startRepoScan}
                  disabled={scanning}
                >
                  {scanning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin mr-1" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <ScanSearch className="h-4 w-4 mr-1" />
                      Scan from Repo
                    </>
                  )}
                </Button>
                <Button variant="outline" size="sm" onClick={disconnectRepo}>
                  <Unplug className="h-4 w-4" />
                </Button>
              </div>
            </div>
          ) : (
            <div className="text-center py-4">
              <GitBranch className="h-8 w-8 mx-auto mb-2 text-muted-foreground opacity-50" />
              <p className="text-sm text-muted-foreground mb-3">
                No repository connected
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setConnectorOpen(true)}
              >
                Connect Repository
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Scans</p>
                <p className="text-3xl font-bold">{project.scans.length}</p>
              </div>
              <ScanSearch className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Findings</p>
                <p className="text-3xl font-bold">{project.totalFindings}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <CardTitle className="text-sm mb-3">Severity</CardTitle>
            <SeverityChart severities={project.severities} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {project.scans.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">
              No scans linked to this project yet
            </p>
          ) : (
            <div className="space-y-2">
              {project.scans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="block p-3 rounded-md border border-border hover:bg-accent/30 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <ScanSearch className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <span className="text-sm font-medium">
                          {scan.branch || "main"}
                          {scan.scanType === "repo-scan" && (
                            <span className="ml-2 text-xs text-muted-foreground font-normal">
                              repo scan
                            </span>
                          )}
                          {scan.status === "running" && (
                            <Loader2 className="inline-block h-3 w-3 animate-spin ml-2" />
                          )}
                        </span>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground mt-0.5">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDistanceToNow(new Date(scan.createdAt), {
                              addSuffix: true,
                            })}
                          </span>
                          <span>{scan.filesScanned} files</span>
                          <span>{scan.duration.toFixed(1)}s</span>
                        </div>
                      </div>
                    </div>
                    <span className="text-sm font-mono">
                      {scan._count.findings} findings
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center gap-2">
        <Link href={`/findings?projectId=${project.id}`}>
          <Button variant="outline" size="sm">
            View all findings
          </Button>
        </Link>
      </div>

      <RepoConnector
        open={connectorOpen}
        onOpenChange={setConnectorOpen}
        onSelect={connectRepo}
      />
    </div>
  );
}

function ProviderIcon({ provider }: { provider: string }) {
  if (provider === "github") {
    return (
      <svg className="h-5 w-5 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
      </svg>
    );
  }
  if (provider === "gitlab") {
    return (
      <svg className="h-5 w-5 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z" />
      </svg>
    );
  }
  return <GitBranch className="h-5 w-5 flex-shrink-0" />;
}
