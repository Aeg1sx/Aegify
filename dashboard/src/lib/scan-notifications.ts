import type { PrismaClient } from "@prisma/client";
import type { ImportReceipt } from "./sarif-import.ts";
import { sendSlackNotification } from "./slack.ts";
import { getSlackConfig } from "./settings.ts";

/** Existing configured notifications run only after artifact publication commits. */
export async function notifyImportedScan(db: PrismaClient, receipt: ImportReceipt, repository: string, branch: string): Promise<void> {
  if (receipt.status === "failed") return;
  const findings = await db.finding.findMany({
    where: { scanId: receipt.scanId, isCurrent: true, baselineState: { in: ["new", "regressed"] } },
    select: { ruleId: true, ruleName: true, severity: true, filePath: true, lineStart: true, message: true },
  });
  if (findings.length) await sendSlackNotification({ scanId: receipt.scanId, repository, branch, totalFindings: findings.length, findings }, await getSlackConfig(db));
}
