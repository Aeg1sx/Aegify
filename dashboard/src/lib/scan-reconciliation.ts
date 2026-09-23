import type { Prisma, PrismaClient } from "@prisma/client";
import { canReconcileScanAbsence, type ScanHealth } from "./sarif-evidence.ts";

interface ImportedScan {
  scanId: string;
  projectId: string | null;
  branch: string;
  defaultBranch: string;
  health: ScanHealth;
  audit?: { actorId: string; findings: number };
  publishBaseline?: boolean;
}

function chunks<T>(items: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) result.push(items.slice(index, index + size));
  return result;
}

/** Publish absence and terminal status together, after every artifact was stored. */
export async function finalizeScanImport(prisma: PrismaClient, imported: ImportedScan): Promise<void> {
  await prisma.$transaction((tx) => publishScanImport(tx, imported), { timeout: 30_000 });
}

/** Compose with the complete artifact publication transaction. */
export async function publishScanImport(tx: Prisma.TransactionClient, imported: ImportedScan): Promise<void> {
  const { scanId, projectId, branch, defaultBranch, health } = imported;
  if (projectId && imported.publishBaseline !== false) {
    const previous = { scanId: { not: scanId }, scan: { projectId, branch }, isCurrent: true };
    // Observed logical identities supersede their old physical checkouts even
    // during partial scans. Do not rely on the old occurrence's v1 fingerprint.
    const observed = await tx.finding.findMany({ where: { scanId }, select: { fingerprint: true, identityId: true } });
    for (const identities of chunks([...new Set(observed.map((item) => item.identityId).filter(Boolean))], 200)) {
      await tx.finding.updateMany({ where: { ...previous, identityId: { in: identities } }, data: { isCurrent: false } });
    }
    for (const fingerprints of chunks([...new Set(observed.filter((item) => !item.identityId).map((item) => item.fingerprint).filter(Boolean))], 200)) {
      await tx.finding.updateMany({ where: { ...previous, fingerprint: { in: fingerprints } }, data: { isCurrent: false } });
    }
    if (canReconcileScanAbsence(health, branch, defaultBranch)) {
      if (health.sourceIdentityVersion === 1 && health.analyzedSources) {
        const byRepository = new Map<string, Set<string>>();
        for (const source of health.analyzedSources) {
          const paths = byRepository.get(source.repositoryId) || new Set<string>();
          paths.add(source.modulePath);
          byRepository.set(source.repositoryId, paths);
        }
        for (const [repositoryId, modules] of byRepository) {
          for (const paths of chunks([...modules], 200)) {
            for (const rules of chunks(health.evaluatedRules, 100)) {
              const scope = { repositoryId, modulePath: { in: paths }, ruleId: { in: rules } };
              // Identity IDs also retire legacy occurrences whose modulePath
              // column was empty before the scope migration.
              while (true) {
                const absent = await tx.findingIdentity.findMany({
                  where: { projectId, ...scope, absentAt: null, lastSeenScanId: { not: scanId } },
                  select: { id: true }, take: 200, orderBy: { id: "asc" },
                });
                if (!absent.length) break;
                const ids = absent.map((row) => row.id);
                await tx.findingIdentity.updateMany({ where: { projectId, id: { in: ids } }, data: { absentAt: new Date() } });
                await tx.finding.updateMany({ where: { ...previous, identityId: { in: ids } }, data: { isCurrent: false } });
              }
              await tx.finding.updateMany({ where: { ...previous, ...scope }, data: { isCurrent: false } });
            }
          }
        }
      } else {
        // Bound SQL parameter counts. Findings in excluded files or disabled
        // rules remain current; their absence was never measured by this scan.
        for (const files of chunks(health.analyzedFiles, 200)) {
          for (const rules of chunks(health.evaluatedRules, 100)) {
            // A legacy inventory has no repository namespace. It cannot prove
            // absence for repository-qualified identities with the same path.
            const scope = { repositoryId: "", ruleId: { in: rules }, filePath: { in: files } };
            await tx.findingIdentity.updateMany({
              where: { projectId, ...scope, absentAt: null, lastSeenScanId: { not: scanId } },
              data: { absentAt: new Date() },
            });
            await tx.finding.updateMany({ where: { ...previous, ...scope }, data: { isCurrent: false } });
          }
        }
      }
    }
  }
  await tx.scan.update({
    where: { id: scanId },
    data: {
      status: health.status,
      progressPhaseName: health.status,
      progressPercent: 1,
      progressMessage: health.gaps.map((gap) => `${gap.code}: ${gap.message} (${gap.affected_count})`).join("; ").slice(0, 4000),
    },
  });
  if (imported.audit) await tx.auditEvent.create({ data: {
    projectId, actorId: imported.audit.actorId, action: "scan.import.finished", targetId: scanId,
    details: JSON.stringify({ status: health.status, findings: imported.audit.findings }),
  } });
}
