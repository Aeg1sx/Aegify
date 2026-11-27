import { repositoryPages } from "./repository-pages.ts";
import { prisma } from "@/lib/prisma";

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  html_url: string;
  description: string | null;
  private: boolean;
  default_branch: string;
  language: string | null;
  updated_at: string;
}

export async function getGitHubToken(userId: string): Promise<string | null> {
  const account = await prisma.account.findFirst({
    where: { userId, provider: "github" },
  });
  return account?.access_token || null;
}

export function listGitHubRepos(accessToken: string, signal: AbortSignal) {
  return repositoryPages<GitHubRepo>((page) => `https://api.github.com/user/repos?per_page=100&page=${page}&sort=updated&type=all`, { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github.v3+json" }, signal);
}

export async function getGitHubFileContent(
  accessToken: string,
  owner: string,
  repo: string,
  path: string,
  ref?: string,
): Promise<string | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}${ref ? `?ref=${ref}` : ""}`;

  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github.v3.raw",
    },
  });

  if (!res.ok) return null;
  return res.text();
}
