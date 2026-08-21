ALTER TABLE "Scan" ADD COLUMN "workspaceSnapshot" TEXT NOT NULL DEFAULT '';

ALTER TABLE "Finding" ADD COLUMN "evidenceId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "repositoryId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "modulePath" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Finding" ADD COLUMN "provenance" TEXT NOT NULL DEFAULT '{}';

CREATE INDEX "Finding_evidenceId_idx" ON "Finding"("evidenceId");
CREATE INDEX "Finding_repositoryId_idx" ON "Finding"("repositoryId");
