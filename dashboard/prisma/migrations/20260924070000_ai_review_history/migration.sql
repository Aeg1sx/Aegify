ALTER TABLE "LlmJob" ADD COLUMN "historyVersion" INTEGER NOT NULL DEFAULT 0;

CREATE TABLE "LlmReview" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "jobId" TEXT NOT NULL,
  "callId" TEXT NOT NULL,
  "findingId" TEXT NOT NULL,
  "batchIndex" INTEGER NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "publication" TEXT NOT NULL,
  "ruleId" TEXT NOT NULL,
  "ruleName" TEXT NOT NULL,
  "severity" TEXT NOT NULL,
  "filePath" TEXT NOT NULL,
  "lineStart" INTEGER NOT NULL,
  "metadataTruncated" BOOLEAN NOT NULL DEFAULT false,
  "verdict" TEXT NOT NULL,
  "confidence" REAL NOT NULL,
  "evidenceDigest" TEXT NOT NULL,
  "payloadDigest" TEXT NOT NULL,
  "payloadCiphertext" TEXT NOT NULL,
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "LlmReview_jobId_fkey" FOREIGN KEY ("jobId") REFERENCES "LlmJob" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "LlmReview_callId_fkey" FOREIGN KEY ("callId") REFERENCES "LlmCall" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "LlmReview_jobId_findingId_key" ON "LlmReview"("jobId", "findingId");
CREATE INDEX "LlmReview_jobId_batchIndex_ordinal_id_idx" ON "LlmReview"("jobId", "batchIndex", "ordinal", "id");
CREATE INDEX "LlmReview_callId_idx" ON "LlmReview"("callId");

-- Retained records are append-only. Parent scan deletion still cascades for
-- operator retention. This is not protection against a database administrator.
CREATE TRIGGER "LlmReview_no_update" BEFORE UPDATE ON "LlmReview"
BEGIN SELECT RAISE(ABORT, 'Saved AI reviews are immutable'); END;

-- Do not invent missing historical output from the mutable Finding projection.
