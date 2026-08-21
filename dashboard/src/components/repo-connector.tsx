"use client";

import { useEffect, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { GitBranch, Search, Lock, Globe, Loader2 } from "lucide-react";

interface Repo {
  provider: string;
  id: string;
  name: string;
  fullName: string;
  url: string;
  description: string | null;
  isPrivate: boolean;
  defaultBranch: string;
  language: string | null;
  updatedAt: string;
}

interface RepoConnectorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (repo: Repo) => void;
}

export function RepoConnector({ open, onOpenChange, onSelect }: RepoConnectorProps) {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [providers, setProviders] = useState<{ github: boolean; gitlab: boolean }>({
    github: false,
    gitlab: false,
  });
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    async function loadRepositories() {
      await Promise.resolve();
      if (cancelled) return;
      setLoading(true);
      try {
        const response = await fetch("/api/repos");
        const data = await response.json();
        if (cancelled) return;
        setRepos(data.repos || []);
        setProviders(data.providers || { github: false, gitlab: false });
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadRepositories();
    return () => {
      cancelled = true;
    };
  }, [open]);

  const filtered = repos.filter((r) =>
    r.fullName.toLowerCase().includes(search.toLowerCase()),
  );

  const noProviders = !providers.github && !providers.gitlab;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Connect Repository</DialogTitle>
          <DialogDescription>
            Select a repository to connect for code scanning.
          </DialogDescription>
        </DialogHeader>

        {noProviders && !loading ? (
          <div className="text-center py-8 text-muted-foreground">
            <GitBranch className="h-8 w-8 mx-auto mb-3 opacity-50" />
            <p className="text-sm font-medium mb-1">No providers connected</p>
            <p className="text-xs">
              Sign in with GitHub or GitLab in Settings to connect repositories.
            </p>
          </div>
        ) : (
          <>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search repositories..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>

            <ScrollArea className="h-[300px]">
              {loading ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                </div>
              ) : filtered.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground text-sm">
                  {search ? "No matching repositories" : "No repositories found"}
                </div>
              ) : (
                <div className="space-y-1 pr-4">
                  {filtered.map((repo) => (
                    <button
                      key={repo.id}
                      onClick={() => onSelect(repo)}
                      className="w-full text-left p-3 rounded-md border border-border hover:bg-accent/30 transition-colors"
                    >
                      <div className="flex items-center gap-2">
                        <ProviderIcon provider={repo.provider} />
                        <span className="text-sm font-medium truncate flex-1">
                          {repo.fullName}
                        </span>
                        {repo.isPrivate ? (
                          <Lock className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                        ) : (
                          <Globe className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                        )}
                      </div>
                      {repo.description && (
                        <p className="text-xs text-muted-foreground mt-1 truncate">
                          {repo.description}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        {repo.language && <span>{repo.language}</span>}
                        <span>{repo.defaultBranch}</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </ScrollArea>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ProviderIcon({ provider }: { provider: string }) {
  if (provider === "github") {
    return (
      <svg className="h-4 w-4 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
      </svg>
    );
  }
  if (provider === "gitlab") {
    return (
      <svg className="h-4 w-4 flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
        <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z" />
      </svg>
    );
  }
  return <GitBranch className="h-4 w-4 flex-shrink-0" />;
}
