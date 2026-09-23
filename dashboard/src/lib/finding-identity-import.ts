import { Prisma, type FindingIdentity } from "@prisma/client";
import { sourceFindingFingerprint } from "./finding-lifecycle.ts";

export interface IncomingIdentity {
  fingerprint: string;
  ruleId: string;
  filePath: string;
  repositoryId: string;
  modulePath: string;
  codeSnippet: string;
  message: string;
}

function chunks<T>(items: T[], size = 200): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) result.push(items.slice(index, index + size));
  return result;
}

export async function readFindingIdentities(tx: Prisma.TransactionClient, projectId: string, fingerprints: string[]): Promise<FindingIdentity[]> {
  const rows: FindingIdentity[] = [];
  for (const batch of chunks([...new Set(fingerprints)])) {
    rows.push(...await tx.findingIdentity.findMany({ where: { projectId, fingerprint: { in: batch } } }));
  }
  return rows;
}

const versioned = (fingerprint: string) => fingerprint.startsWith("aegify-finding/v2:") || fingerprint.startsWith("sarif-finding/v2:");
const scopeKey = (finding: { repositoryId: string; modulePath: string; ruleId: string }) => JSON.stringify([finding.repositoryId, finding.modulePath, finding.ruleId]);

/** Upgrade only a one-to-one, source/scope-bound legacy identity inside publication. */
export async function migrateFindingIdentities(
  tx: Prisma.TransactionClient,
  context: { projectId: string; scanId: string; actorId: string },
  incoming: IncomingIdentity[],
  known: FindingIdentity[],
  legacyHints: Map<string, Set<string>>,
): Promise<{ migrated: number; reviewRequired: number }> {
  const knownKeys = new Set(known.map((row) => row.fingerprint));
  const missing = incoming.filter((row) => !knownKeys.has(row.fingerprint));
  if (!missing.length) return { migrated: 0, reviewRequired: 0 };
  const candidates = new Map<string, FindingIdentity>();
  const reviews = new Set<string>();
  const byFingerprint = new Map(missing.map((row) => [row.fingerprint, row]));
  const byScope = new Map<string, IncomingIdentity[]>();
  const byHint = new Map<string, IncomingIdentity[]>();
  for (const row of missing) {
    const key = scopeKey(row);
    const scoped = byScope.get(key) || [];
    scoped.push(row);
    byScope.set(key, scoped);
    for (const hint of legacyHints.get(row.fingerprint) || []) {
      const hinted = byHint.get(hint) || [];
      hinted.push(row);
      byHint.set(hint, hinted);
    }
  }
  const limit = 5000;
  const reviewAll = async () => {
    await recordMigrationReview(tx, context, missing.map((row) => row.fingerprint), "migration_budget");
    return { migrated: 0, reviewRequired: missing.length };
  };
  for (const batch of chunks([...byHint.keys()])) {
    for (const row of await readFindingIdentities(tx, context.projectId, batch)) {
      if (!versioned(row.fingerprint)) candidates.set(row.id, row);
    }
    if (candidates.size > limit) return reviewAll();
  }
  const scopes = [...byScope.values()].map((rows) => rows[0]).filter((row) => row.modulePath);
  for (const batch of chunks(scopes, 100)) {
    const rows = await tx.findingIdentity.findMany({
      where: { projectId: context.projectId,
        NOT: { OR: [{ fingerprint: { startsWith: "aegify-finding/v2:" } }, { fingerprint: { startsWith: "sarif-finding/v2:" } }] },
        OR: batch.map(({ repositoryId, modulePath, ruleId }) => ({ repositoryId, modulePath, ruleId })) },
      take: limit + 1,
    });
    if (rows.length > limit) return reviewAll();
    for (const row of rows) candidates.set(row.id, row);
    if (candidates.size > limit) return reviewAll();
  }
  type Retained = { identityId: string; ruleId: string; filePath: string; codeSnippet: string; message: string; snippetLength: bigint | number; messageLength: bigint | number };
  const retained = new Map<string, Retained[]>();
  const incomplete = new Set<string>();
  let retainedCount = 0;
  for (const batch of chunks([...candidates.keys()])) {
    const rows = await tx.$queryRaw<Retained[]>(Prisma.sql`
      SELECT f.identityId, f.ruleId, f.filePath,
        substr(f.codeSnippet, 1, 16385) AS codeSnippet, length(CAST(f.codeSnippet AS BLOB)) AS snippetLength,
        substr(f.message, 1, 16385) AS message, length(CAST(f.message AS BLOB)) AS messageLength
      FROM Finding f JOIN FindingIdentity i ON i.id = f.identityId
      JOIN Scan s ON s.id = f.scanId AND s.projectId = i.projectId
      WHERE i.projectId = ${context.projectId} AND i.id IN (${Prisma.join(batch)})
        AND f.scanId = i.lastSeenScanId
      ORDER BY f.id LIMIT ${limit - retainedCount + 1}
    `);
    retainedCount += rows.length;
    if (retainedCount > limit) return reviewAll();
    for (const row of rows) {
      if (Number(row.snippetLength) > 16_384 || Number(row.messageLength) > 16_384) {
        incomplete.add(row.identityId);
        continue;
      }
      const occurrences = retained.get(row.identityId) || [];
      occurrences.push(row);
      retained.set(row.identityId, occurrences);
    }
  }

  const matches = new Map<string, Set<string>>();
  const reverse = new Map<string, Set<string>>();
  const reviewScopes = new Set<string>();
  const addMatch = (row: IncomingIdentity, legacy: FindingIdentity) => {
    if (scopeKey(row) !== scopeKey(legacy)) return;
    const ids = matches.get(row.fingerprint) || new Set<string>();
    ids.add(legacy.id);
    matches.set(row.fingerprint, ids);
    const fingerprints = reverse.get(legacy.id) || new Set<string>();
    fingerprints.add(row.fingerprint);
    reverse.set(legacy.id, fingerprints);
  };
  for (const legacy of candidates.values()) {
    const occurrences = retained.get(legacy.id) || [];
    // Scope is backfilled only when every historical occurrence agrees. Empty
    // scope or unavailable evidence cannot justify moving a triage decision.
    if (!legacy.modulePath || incomplete.has(legacy.id) || !occurrences.length) {
      reviewScopes.add(scopeKey(legacy));
      for (const row of byHint.get(legacy.fingerprint) || []) reviews.add(row.fingerprint);
      continue;
    }
    // Hash each retained occurrence once, avoiding a finding-by-candidate join.
    const sourceKeys = new Set(occurrences.filter((item) => item.ruleId === legacy.ruleId).map((item) =>
      sourceFindingFingerprint({ ...item, repositoryId: legacy.repositoryId, modulePath: legacy.modulePath })));
    for (const fingerprint of sourceKeys) {
      const row = byFingerprint.get(fingerprint);
      if (!row || scopeKey(row) !== scopeKey(legacy)) continue;
      if (sourceKeys.size !== 1) reviews.add(fingerprint);
      else addMatch(row, legacy);
    }
    const hasMatchingRule = occurrences.some((item) => item.ruleId === legacy.ruleId);
    for (const row of byHint.get(legacy.fingerprint) || []) {
      if (row.fingerprint.startsWith("sarif-finding/v2:") && hasMatchingRule) addMatch(row, legacy);
    }
  }
  for (const scope of reviewScopes) for (const row of byScope.get(scope) || []) reviews.add(row.fingerprint);

  let migrated = 0;
  for (const row of missing) {
    const ids = [...(matches.get(row.fingerprint) || [])];
    if (ids.length > 1 || ids.some((id) => reverse.get(id)!.size > 1)) reviews.add(row.fingerprint);
    if (ids.length !== 1 || reviews.has(row.fingerprint)) continue;
    const legacy = candidates.get(ids[0])!;
    const changed = await tx.findingIdentity.updateMany({
      where: { id: legacy.id, projectId: context.projectId, fingerprint: legacy.fingerprint },
      data: { fingerprint: row.fingerprint, filePath: row.filePath, repositoryId: row.repositoryId, modulePath: row.modulePath },
    });
    if (changed.count !== 1) throw new Error("Finding identity changed during publication.");
    await tx.auditEvent.create({ data: { projectId: context.projectId, actorId: context.actorId,
      action: "finding.identity.migrated", targetId: legacy.id,
      details: JSON.stringify({ scanId: context.scanId, previousFingerprint: legacy.fingerprint, fingerprint: row.fingerprint }) } });
    migrated += 1;
  }
  if (reviews.size) await recordMigrationReview(tx, context, [...reviews], "ambiguous_legacy_identity");
  return { migrated, reviewRequired: reviews.size };
}

async function recordMigrationReview(tx: Prisma.TransactionClient,
  context: { projectId: string; scanId: string; actorId: string }, fingerprints: string[], reason: string): Promise<void> {
  await tx.auditEvent.create({ data: {
    projectId: context.projectId, actorId: context.actorId, action: "scan.identity_migration.review_required", targetId: context.scanId,
    details: JSON.stringify({ reason, findings: fingerprints.length, fingerprints: fingerprints.sort().slice(0, 50) }),
  } });
}
