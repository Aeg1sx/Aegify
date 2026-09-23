CREATE TABLE "ScanJob" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "scanId" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "requestedBy" TEXT NOT NULL,
  "provider" TEXT NOT NULL CHECK ("provider" IN ('github','gitlab')),
  "ownerSlug" TEXT NOT NULL,
  "providerRepoId" TEXT NOT NULL DEFAULT '',
  "requestedRef" TEXT NOT NULL,
  "commitSha" TEXT NOT NULL DEFAULT '',
  "sourceDigest" TEXT NOT NULL DEFAULT '',
  "sourceManifest" TEXT NOT NULL DEFAULT '{}',
  "sourceCiphertext" TEXT,
  "resultDigest" TEXT NOT NULL DEFAULT '',
  "resultManifest" TEXT NOT NULL DEFAULT '{}',
  "status" TEXT NOT NULL DEFAULT 'queued' CHECK ("status" IN ('queued','running','completed','partial','failed','cancelled')),
  "activeKey" TEXT,
  "attempts" INTEGER NOT NULL DEFAULT 0 CHECK ("attempts" >= 0),
  "maxAttempts" INTEGER NOT NULL DEFAULT 3 CHECK ("maxAttempts" BETWEEN 1 AND 5),
  "leaseToken" TEXT,
  "leaseExpiresAt" DATETIME,
  "heartbeatAt" DATETIME,
  "workerId" TEXT NOT NULL DEFAULT '',
  "nextAttemptAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "cancelRequestedAt" DATETIME,
  "errorCode" TEXT NOT NULL DEFAULT '',
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" DATETIME NOT NULL,
  "completedAt" DATETIME,
  CONSTRAINT "ScanJob_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ScanJob_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "ScanJob_scanId_key" ON "ScanJob"("scanId");
CREATE UNIQUE INDEX "ScanJob_activeKey_key" ON "ScanJob"("activeKey");
CREATE INDEX "ScanJob_status_nextAttemptAt_createdAt_idx" ON "ScanJob"("status", "nextAttemptAt", "createdAt");
CREATE INDEX "ScanJob_leaseExpiresAt_idx" ON "ScanJob"("leaseExpiresAt");
CREATE INDEX "ScanJob_projectId_createdAt_idx" ON "ScanJob"("projectId", "createdAt");

CREATE TABLE "ScanJobEvent" (
  "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  "jobId" TEXT NOT NULL,
  "code" TEXT NOT NULL,
  "message" TEXT NOT NULL,
  "details" TEXT NOT NULL DEFAULT '{}',
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ScanJobEvent_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "ScanJob"("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "ScanJobEvent_jobId_id_idx" ON "ScanJobEvent"("jobId", "id");
CREATE TABLE "ScanWorker" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "version" TEXT NOT NULL,
  "lastSeenAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "ScanWorker_lastSeenAt_idx" ON "ScanWorker"("lastSeenAt");
