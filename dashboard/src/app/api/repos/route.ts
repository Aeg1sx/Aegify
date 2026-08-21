import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { getGitHubToken, listGitHubRepos } from "@/lib/github";
import { getGitLabToken, listGitLabProjects } from "@/lib/gitlab";

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const repos: Array<{
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
  }> = [];

  // Fetch GitHub repos
  const ghToken = await getGitHubToken(session.user.id);
  if (ghToken) {
    try {
      const ghRepos = await listGitHubRepos(ghToken);
      for (const repo of ghRepos) {
        repos.push({
          provider: "github",
          id: `gh-${repo.id}`,
          name: repo.name,
          fullName: repo.full_name,
          url: repo.html_url,
          description: repo.description,
          isPrivate: repo.private,
          defaultBranch: repo.default_branch,
          language: repo.language,
          updatedAt: repo.updated_at,
        });
      }
    } catch (e) {
      console.error("GitHub repo fetch error:", e);
    }
  }

  // Fetch GitLab projects
  const glToken = await getGitLabToken(session.user.id);
  if (glToken) {
    try {
      const glProjects = await listGitLabProjects(glToken);
      for (const proj of glProjects) {
        repos.push({
          provider: "gitlab",
          id: `gl-${proj.id}`,
          name: proj.name,
          fullName: proj.path_with_namespace,
          url: proj.web_url,
          description: proj.description,
          isPrivate: proj.visibility !== "public",
          defaultBranch: proj.default_branch,
          language: null,
          updatedAt: proj.last_activity_at,
        });
      }
    } catch (e) {
      console.error("GitLab project fetch error:", e);
    }
  }

  return NextResponse.json({
    repos,
    providers: {
      github: !!ghToken,
      gitlab: !!glToken,
    },
  });
}
