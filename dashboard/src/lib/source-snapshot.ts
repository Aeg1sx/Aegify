import { createHash } from "node:crypto";

export interface SourceSnapshot {
  version: 1;
  provider: string;
  repository: string;
  commit: string;
  sourceDigest: string;
  truncated: boolean;
  files: Array<{ path: string; content: string; sha256: string }>;
}

/** Preserve the source worker's v1 manifest identity across source consumers. */
export function sourceDigest(snapshot: Omit<SourceSnapshot, "sourceDigest">): string {
  const hash = createHash("sha256").update(`aegify-source/v1\n${snapshot.provider}\0${snapshot.repository}\0${snapshot.commit}\n`);
  for (const file of [...snapshot.files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))) hash.update(`${file.path}\0${file.sha256}\n`);
  return `sha256:${hash.digest("hex")}`;
}
