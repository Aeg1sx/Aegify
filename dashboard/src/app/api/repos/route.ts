import { requireAccess } from "@/lib/access";
import { NextResponse } from "next/server";
import { getGitHubToken, listGitHubRepos } from "@/lib/github";
import { getGitLabToken, listGitLabProjects } from "@/lib/gitlab";

export async function GET(request: Request) {
  const access = await requireAccess(request);
  if (access instanceof Response) return access;
  if (!access.userId)
    return NextResponse.json({ error: "Sign in to list your repositories." }, { status: 401 });

  const [ghToken, glToken] = await Promise.all([
    getGitHubToken(access.userId),
    getGitLabToken(access.userId),
  ]);
  const [github, gitlab] = await Promise.all([
    ghToken ? listGitHubRepos(ghToken, request.signal) : undefined,
    glToken ? listGitLabProjects(glToken, request.signal) : undefined,
  ]);
  const warnings: string[] = [];
  for (const [provider, state] of [
    ["GitHub", github?.state],
    ["GitLab", gitlab?.state],
  ]) {
    if (state === "interrupted")
      warnings.push(provider + " could not finish loading repositories. Try again.");
    if (state === "limited") warnings.push("Showing the first 500 repositories from " + provider + ".");
  }

  const repos = [
    ...(github?.items ?? []).map((repo) => ({
      provider: "github",
      id: "gh-" + repo.id,
      name: repo.name,
      fullName: repo.full_name,
      url: repo.html_url,
      description: repo.description,
      isPrivate: repo.private,
      defaultBranch: repo.default_branch,
      language: repo.language,
      updatedAt: repo.updated_at,
    })),
    ...(gitlab?.items ?? []).map((repo) => ({
      provider: "gitlab",
      id: "gl-" + repo.id,
      name: repo.name,
      fullName: repo.path_with_namespace,
      url: repo.web_url,
      description: repo.description,
      isPrivate: repo.visibility !== "public",
      defaultBranch: repo.default_branch || "",
      language: null,
      updatedAt: repo.last_activity_at,
    })),
  ];
  return NextResponse.json(
    {
      repos,
      providers: { github: !!ghToken, gitlab: !!glToken },
      warnings,
      retryable: [github?.state, gitlab?.state].includes("interrupted"),
    },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}
