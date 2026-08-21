"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Archive,
  FolderKanban,
  Plus,
  RotateCcw,
  ScanSearch,
  AlertTriangle,
  Clock,
  X,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";

interface ProjectSummary {
  id: string;
  name: string;
  repositoryUrl: string;
  description: string;
  color: string;
  archived: boolean;
  scanCount: number;
  findingCount: number;
  lastScan: {
    id: string;
    createdAt: string;
    status: string;
  } | null;
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [newName, setNewName] = useState("");
  const [newRepo, setNewRepo] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [creating, setCreating] = useState(false);

  const fetchProjects = useCallback(() => {
    const query = showArchived ? "?archived=true" : "";
    fetch(`/api/projects${query}`)
      .then((r) => r.json())
      .then((data) => setProjects(data.projects || []))
      .finally(() => setLoading(false));
  }, [showArchived]);

  const archiveProject = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await fetch(`/api/projects/${id}`, { method: "DELETE" });
    fetchProjects();
  };

  const restoreProject = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    await fetch(`/api/projects/${id}/restore`, { method: "POST" });
    fetchProjects();
  };

  useEffect(() => {
    fetchProjects();
  }, [fetchProjects]);

  const createProject = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    await fetch("/api/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: newName,
        repositoryUrl: newRepo,
        description: newDesc,
      }),
    });
    setNewName("");
    setNewRepo("");
    setNewDesc("");
    setShowCreate(false);
    setCreating(false);
    fetchProjects();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Projects</h1>
          <p className="text-muted-foreground">
            Organize scans and findings by project
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={showArchived ? "default" : "outline"}
            size="sm"
            onClick={() => setShowArchived(!showArchived)}
            className="flex items-center gap-2"
          >
            <Archive className="h-4 w-4" />
            {showArchived ? "Active" : "Archived"}
          </Button>
          {!showArchived && (
            <Button
              onClick={() => setShowCreate(!showCreate)}
              className="flex items-center gap-2"
            >
              {showCreate ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
              {showCreate ? "Cancel" : "New Project"}
            </Button>
          )}
        </div>
      </div>

      {showCreate && (
        <Card>
          <CardContent className="pt-6 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Name</label>
                <Input
                  placeholder="My Project"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Repository URL</label>
                <Input
                  placeholder="https://github.com/org/repo"
                  value={newRepo}
                  onChange={(e) => setNewRepo(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Input
                placeholder="Brief description..."
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
              />
            </div>
            <Button onClick={createProject} disabled={creating || !newName.trim()}>
              {creating ? "Creating..." : "Create Project"}
            </Button>
          </CardContent>
        </Card>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-[40vh]">
          <div className="animate-pulse text-muted-foreground">Loading...</div>
        </div>
      ) : projects.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FolderKanban className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No projects yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              Create a project to organize your scans and findings
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {projects.map((project) => (
            <Link key={project.id} href={`/projects/${project.id}`}>
              <Card className="hover:shadow-md transition-shadow cursor-pointer h-full group">
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-3 h-3 rounded-full shrink-0"
                      style={{ backgroundColor: project.color }}
                    />
                    <CardTitle className="text-base truncate">
                      {project.name}
                    </CardTitle>
                  </div>
                  {project.description && (
                    <p className="text-xs text-muted-foreground line-clamp-2 mt-1">
                      {project.description}
                    </p>
                  )}
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <ScanSearch className="h-3.5 w-3.5" />
                        {project.scanCount} scans
                      </span>
                      <span className="flex items-center gap-1">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        {project.findingCount} findings
                      </span>
                    </div>
                    {showArchived ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => restoreProject(project.id, e)}
                        title="Restore project"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => archiveProject(project.id, e)}
                        title="Archive project"
                        className="opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Archive className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                  {project.lastScan && (
                    <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      Last scan{" "}
                      {formatDistanceToNow(new Date(project.lastScan.createdAt), {
                        addSuffix: true,
                      })}
                    </p>
                  )}
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
