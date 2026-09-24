-- Existing single-turn reviews retain round zero and all history foreign keys.
ALTER TABLE "LlmCall" ADD COLUMN "roundIndex" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "LlmCall" ADD COLUMN "responseKind" TEXT NOT NULL DEFAULT 'review';
ALTER TABLE "LlmCall" ADD COLUMN "continuationDigest" TEXT NOT NULL DEFAULT '';
ALTER TABLE "LlmCall" ADD COLUMN "continuationCiphertext" TEXT;
DROP INDEX "LlmCall_jobId_batchIndex_key";
CREATE UNIQUE INDEX "LlmCall_jobId_batchIndex_roundIndex_key" ON "LlmCall"("jobId", "batchIndex", "roundIndex");
