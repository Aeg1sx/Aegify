ALTER TABLE "ScanWorker" ADD COLUMN "ruleFixturesVersion" INTEGER NOT NULL DEFAULT 0;

CREATE TABLE "RuleFixtureJob" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "projectId" TEXT NOT NULL,
  "requestedBy" TEXT NOT NULL,
  "contractVersion" INTEGER NOT NULL DEFAULT 1,
  "inputDigest" TEXT NOT NULL,
  "inputCiphertext" TEXT,
  "resultDigest" TEXT NOT NULL DEFAULT '',
  "resultCiphertext" TEXT,
  "status" TEXT NOT NULL DEFAULT 'queued',
  "outcome" TEXT NOT NULL DEFAULT '',
  "activeKey" TEXT,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "maxAttempts" INTEGER NOT NULL DEFAULT 3,
  "leaseToken" TEXT,
  "leaseExpiresAt" DATETIME,
  "heartbeatAt" DATETIME,
  "workerId" TEXT NOT NULL DEFAULT '',
  "nextAttemptAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "errorCode" TEXT NOT NULL DEFAULT '',
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" DATETIME NOT NULL,
  "completedAt" DATETIME,
  "expiresAt" DATETIME NOT NULL,
  CONSTRAINT "RuleFixtureJob_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "RuleFixtureJob_activeKey_key" ON "RuleFixtureJob"("activeKey");
CREATE INDEX "RuleFixtureJob_status_nextAttemptAt_createdAt_idx" ON "RuleFixtureJob"("status", "nextAttemptAt", "createdAt");
CREATE INDEX "RuleFixtureJob_leaseExpiresAt_idx" ON "RuleFixtureJob"("leaseExpiresAt");
CREATE INDEX "RuleFixtureJob_projectId_createdAt_idx" ON "RuleFixtureJob"("projectId", "createdAt");
CREATE INDEX "RuleFixtureJob_requestedBy_createdAt_idx" ON "RuleFixtureJob"("requestedBy", "createdAt");
CREATE INDEX "RuleFixtureJob_expiresAt_idx" ON "RuleFixtureJob"("expiresAt");
CREATE TABLE "RuleFixtureJobEvent" (
  "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  "jobId" TEXT NOT NULL,
  "code" TEXT NOT NULL,
  "message" TEXT NOT NULL,
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "RuleFixtureJobEvent_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "RuleFixtureJob"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "RuleFixtureJobEvent_jobId_id_idx" ON "RuleFixtureJobEvent"("jobId", "id");
