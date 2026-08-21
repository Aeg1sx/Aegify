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

export async function listGitLabProjects(accessToken: string): Promise<GitLabProject[]> {
  const projects: GitLabProject[] = [];
  let page = 1;

  while (page <= 5) {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects?membership=true&per_page=100&page=${page}&order_by=last_activity_at`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );

    if (!res.ok) break;

    const data = await res.json();
    if (!Array.isArray(data) || data.length === 0) break;

    projects.push(...data);
    page++;
  }

  return projects;
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
