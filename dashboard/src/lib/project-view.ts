export function repositoryName(project: { ownerSlug?: string; repositoryUrl: string }) {
  if (project.ownerSlug) return project.ownerSlug;
  if (!project.repositoryUrl) return "";
  try {
    const url = new URL(project.repositoryUrl);
    if (url.hostname) return url.host + url.pathname.replace(/\/$/, "");
  } catch {
    /* Some older projects use SCP-style repository addresses. */
  }
  const ssh = /^[\w.-]+@([\w.-]+):([\w./-]+)$/.exec(project.repositoryUrl);
  return ssh ? ssh[1] + "/" + ssh[2] : "";
}

export function repositoryLink(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (!["https:", "http:"].includes(url.protocol)) return undefined;
    return url.origin + url.pathname;
  } catch {
    return undefined;
  }
}
