"use client";

import { useEffect, useState } from "react";
import { GitBranch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

export interface RepositoryChoice {
  provider: string;
  id: string;
  fullName: string;
  url: string;
  isPrivate: boolean;
  defaultBranch: string;
}

interface Directory {
  repos: RepositoryChoice[];
  providers: { github: boolean; gitlab: boolean };
  warnings?: string[];
  retryable?: boolean;
}

export function RepoConnector({
  onClose,
  onReturnFocus,
  onSelect,
  busy,
  error,
  onReload,
}: {
  onClose: () => void;
  onReturnFocus: () => void;
  onSelect: (repo: RepositoryChoice) => void;
  busy: boolean;
  error: string;
  onReload?: () => void;
}) {
  const [directory, setDirectory] = useState<Directory | null>(null);
  const [loadError, setLoadError] = useState("");
  const [search, setSearch] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      setLoadError("");
      setDirectory(null);
      try {
        const response = await fetch("/api/repos", { cache: "no-store", signal: controller.signal });
        const data = await response.json();
        if (!response.ok || !Array.isArray(data.repos) || !data.providers) throw new Error();
        if (!controller.signal.aborted) setDirectory(data);
      } catch {
        if (!controller.signal.aborted) setLoadError("Your repositories could not be loaded.");
      }
    }
    void load();
    return () => controller.abort();
  }, [attempt]);

  const repos =
    directory?.repos.filter((item) => item.fullName.toLowerCase().includes(search.trim().toLowerCase())) ??
    [];
  const hasProvider = directory?.providers.github || directory?.providers.gitlab;
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <DialogContent
        className="max-h-[85dvh] overflow-y-auto sm:max-w-lg [&_[data-slot=dialog-close]]:size-11 [&_[data-slot=dialog-close]]:top-1 [&_[data-slot=dialog-close]]:right-1 [&_[data-slot=dialog-close]]:grid [&_[data-slot=dialog-close]]:place-items-center"
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          onReturnFocus();
        }}
        showCloseButton={!busy}
      >
        <DialogHeader className="text-left">
          <DialogTitle>Connect repository</DialogTitle>
          <DialogDescription>Choose the GitHub or GitLab repository for source scans.</DialogDescription>
        </DialogHeader>
        {!directory && !loadError && (
          <p role="status" className="text-sm text-muted-foreground">
            Loading repositories…
          </p>
        )}
        {loadError && (
          <p role="alert" className="text-sm text-destructive">
            {loadError}
          </p>
        )}
        {directory?.warnings?.map((warning) => (
          <p role="status" className="text-sm text-muted-foreground" key={warning}>
            {warning}
          </p>
        ))}
        {(loadError || directory?.retryable) && (
          <Button
            type="button"
            variant="outline"
            className="min-h-11 justify-self-start"
            disabled={busy}
            onClick={() => setAttempt((value) => value + 1)}
          >
            Retry listing
          </Button>
        )}
        {directory &&
          (hasProvider ? (
            <>
              <label className="grid gap-1.5 text-sm font-medium">
                Search repositories
                <Input
                  type="search"
                  className="h-11"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </label>
              {repos.length ? (
                <ul aria-label="Available repositories" className="max-h-64 divide-y overflow-auto border-y">
                  {repos.map((repo) => (
                    <li key={repo.id}>
                      <button
                        type="button"
                        disabled={busy || !!onReload}
                        aria-label={"Connect " + repo.fullName}
                        onClick={() => onSelect(repo)}
                        className="flex min-h-12 w-full items-start gap-2 px-1 py-2 text-left hover:bg-accent disabled:opacity-70"
                      >
                        <GitBranch className="mt-1 size-4 shrink-0 text-muted-foreground" aria-hidden />
                        <span className="min-w-0">
                          <span className="block text-sm font-medium wrap-anywhere">{repo.fullName}</span>
                          <span className="block text-xs text-muted-foreground wrap-anywhere">
                            {repo.provider === "github" ? "GitHub" : "GitLab"} ·{" "}
                            {repo.isPrivate ? "Private" : "Public"}
                            {repo.defaultBranch && " · " + repo.defaultBranch}
                          </span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : (
                !directory.retryable && (
                  <p className="py-3 text-sm text-muted-foreground">
                    {search.trim()
                      ? "No repositories match your search."
                      : "No repositories are available from your connected accounts."}
                  </p>
                )
              )}
            </>
          ) : (
            <p className="text-sm text-muted-foreground">
              Sign in with GitHub or GitLab to choose a repository.
            </p>
          ))}
        {busy && (
          <p role="status" className="text-sm">
            Connecting repository…
          </p>
        )}
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        {onReload && (
          <Button type="button" variant="outline" className="min-h-11" onClick={onReload}>
            Reload project
          </Button>
        )}
      </DialogContent>
    </Dialog>
  );
}
