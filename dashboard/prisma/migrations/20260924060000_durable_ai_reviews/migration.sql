ALTER TABLE "LlmJob" ADD COLUMN "contractVersion" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "projectId" TEXT;
ALTER TABLE "LlmJob" ADD COLUMN "requestedBy" TEXT;
ALTER TABLE "LlmJob" ADD COLUMN "provider" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "model" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "configDigest" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "inputDigest" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "inputCiphertext" TEXT;
ALTER TABLE "LlmJob" ADD COLUMN "attempts" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "maxAttempts" INTEGER NOT NULL DEFAULT 3;
ALTER TABLE "LlmJob" ADD COLUMN "maxCalls" INTEGER NOT NULL DEFAULT 20;
ALTER TABLE "LlmJob" ADD COLUMN "callsStarted" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "promptBytes" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "outputTokensReserved" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "errorCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmJob" ADD COLUMN "errorCode" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "leaseToken" TEXT;
ALTER TABLE "LlmJob" ADD COLUMN "workerId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmJob" ADD COLUMN "leaseExpiresAt" DATETIME;
ALTER TABLE "LlmJob" ADD COLUMN "heartbeatAt" DATETIME;
ALTER TABLE "LlmJob" ADD COLUMN "deadlineAt" DATETIME;
ALTER TABLE "LlmJob" ADD COLUMN "cancelRequestedAt" DATETIME;

CREATE TABLE "LlmJobEvent" (
  "id" TEXT NOT NULL PRIMARY KEY, "jobId" TEXT NOT NULL,
  "code" TEXT NOT NULL, "message" TEXT NOT NULL, "details" TEXT NOT NULL DEFAULT '{}',
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "LlmJobEvent_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "LlmJob" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "LlmJobEvent_jobId_createdAt_idx" ON "LlmJobEvent"("jobId", "createdAt");
CREATE TABLE "LlmCall" (
  "id" TEXT NOT NULL PRIMARY KEY, "jobId" TEXT NOT NULL, "batchIndex" INTEGER NOT NULL,
  "leaseToken" TEXT NOT NULL, "status" TEXT NOT NULL DEFAULT 'dispatched',
  "promptDigest" TEXT NOT NULL, "responseDigest" TEXT NOT NULL DEFAULT '',
  "receipt" TEXT NOT NULL DEFAULT '{}', "errorCode" TEXT NOT NULL DEFAULT '',
  "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, "completedAt" DATETIME,
  CONSTRAINT "LlmCall_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "LlmJob" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "LlmCall_jobId_batchIndex_key" ON "LlmCall"("jobId", "batchIndex");
CREATE INDEX "LlmCall_jobId_status_idx" ON "LlmCall"("jobId", "status");
CREATE TABLE "LlmWorker" (
  "id" TEXT NOT NULL PRIMARY KEY, "version" TEXT NOT NULL,
  "lastSeenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "LlmWorker_lastSeenAt_idx" ON "LlmWorker"("lastSeenAt");
CREATE INDEX "LlmJob_projectId_status_idx" ON "LlmJob"("projectId", "status");
CREATE INDEX "LlmJob_status_leaseExpiresAt_idx" ON "LlmJob"("status", "leaseExpiresAt");

-- Legacy after-tasks have no authenticated requester or publication lease.
-- Stop the old web process before migrating; never infer an actor or retry a paid call.
INSERT INTO "LlmJobEvent" ("id", "jobId", "code", "message")
SELECT 'legacy-ai-' || "id", "id", 'legacy_interrupted',
  'Legacy review interrupted by upgrade; provider outcome may be unknown. Start a new review explicitly.'
FROM "LlmJob" WHERE "status" IN ('pending', 'running');
UPDATE "LlmJob" SET "status" = 'failed', "activeKey" = NULL,
  "errorCode" = 'legacy_interrupted', "completedAt" = CURRENT_TIMESTAMP,
  "errorMessage" = 'Legacy review interrupted by upgrade; provider outcome may be unknown. Start a new review explicitly.'
WHERE "status" IN ('pending', 'running');
