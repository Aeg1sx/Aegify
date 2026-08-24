ALTER TABLE "Finding" ADD COLUMN "fingerprint" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "baselineState" TEXT NOT NULL DEFAULT 'new';
ALTER TABLE "Finding" ADD COLUMN "identityId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "isCurrent" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "Finding" ADD COLUMN "aiVerdict" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "aiConfidence" REAL;
ALTER TABLE "Finding" ADD COLUMN "aiReviewStatus" TEXT NOT NULL DEFAULT 'unreviewed';
ALTER TABLE "Finding" ADD COLUMN "aiProof" TEXT NOT NULL DEFAULT '{}';
-- Repair legacy migration drift: the Prisma model has always exposed updatedAt,
-- but the historical SQLite migration chain did not add the physical column.
ALTER TABLE "Rule" ADD COLUMN "updatedAt" DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';

CREATE TABLE "FindingIdentity" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "projectId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'open',
    "firstSeenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenScanId" TEXT NOT NULL DEFAULT '',
    "occurrenceCount" INTEGER NOT NULL DEFAULT 1,
    "absentAt" DATETIME,
    "lastSeverity" TEXT NOT NULL DEFAULT '',
    "lastEvidenceState" TEXT NOT NULL DEFAULT '',
    "lastMessageDigest" TEXT NOT NULL DEFAULT '',
    "triageReason" TEXT NOT NULL DEFAULT '',
    "triageActor" TEXT NOT NULL DEFAULT '',
    "triageExpiresAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "FindingIdentity_projectId_fkey"
      FOREIGN KEY ("projectId") REFERENCES "Project" ("id")
      ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "FindingTriageEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "identityId" TEXT NOT NULL,
    "fromStatus" TEXT NOT NULL,
    "toStatus" TEXT NOT NULL,
    "reason" TEXT NOT NULL DEFAULT '',
    "actor" TEXT NOT NULL DEFAULT '',
    "expiresAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "FindingTriageEvent_identityId_fkey"
      FOREIGN KEY ("identityId") REFERENCES "FindingIdentity" ("id")
      ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "FindingIdentity_projectId_fingerprint_key"
  ON "FindingIdentity"("projectId", "fingerprint");
CREATE INDEX "FindingIdentity_projectId_status_idx"
  ON "FindingIdentity"("projectId", "status");
CREATE INDEX "FindingIdentity_lastSeenScanId_idx"
  ON "FindingIdentity"("lastSeenScanId");
CREATE INDEX "FindingTriageEvent_identityId_createdAt_idx"
  ON "FindingTriageEvent"("identityId", "createdAt");
CREATE INDEX "Finding_fingerprint_idx" ON "Finding"("fingerprint");
CREATE INDEX "Finding_baselineState_idx" ON "Finding"("baselineState");
CREATE INDEX "Finding_identityId_idx" ON "Finding"("identityId");
CREATE INDEX "Finding_isCurrent_idx" ON "Finding"("isCurrent");
