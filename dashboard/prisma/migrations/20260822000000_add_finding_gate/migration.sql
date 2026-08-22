-- Preserve scanner evidence classification and CI gate disposition.
ALTER TABLE "Finding" ADD COLUMN "evidenceState" TEXT NOT NULL DEFAULT 'candidate';
ALTER TABLE "Finding" ADD COLUMN "disposition" TEXT NOT NULL DEFAULT 'advisory';

CREATE INDEX "Finding_disposition_idx" ON "Finding"("disposition");
