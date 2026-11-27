import { repositoryPages } from "./repository-pages.ts";
import { prisma } from "@/lib/prisma";

interface GitLabProject {
  id: number;
  name: string;
  path_with_namespace: string;
  web_url: string;
  description: string | null;
  visibility: string;
  default_branch: string;
  last_activity_at: string;
}

export async function getGitLabToken(userId: string): Promise<string | null> {
  const account = await prisma.account.findFirst({
    where: { userId, provider: "gitlab" },
  });
  return account?.access_token || null;
}

export function listGitLabProjects(accessToken: string, signal: AbortSignal, start = 1) {
  return repositoryPages<GitLabProject>((page) => `https://gitlab.com/api/v4/projects?membership=true&per_page=100&page=${page}&order_by=last_activity_at`, { Authorization: `Bearer ${accessToken}` }, signal, start);
}

export async function getGitLabFileContent(
  accessToken: string,
  projectId: number,
  filePath: string,
  ref?: string,
): Promise<string | null> {
  const encodedPath = encodeURIComponent(filePath);
  const url = `https://gitlab.com/api/v4/projects/${projectId}/repository/files/${encodedPath}/raw${ref ? `?ref=${ref}` : ""}`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!res.ok) return null;
  return res.text();
}
