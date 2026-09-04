-- A nullable unique key provides a database-enforced single active AI review
-- per scan. Terminal jobs clear the lease and retain their history.
ALTER TABLE "LlmJob" ADD COLUMN "activeKey" TEXT;

CREATE UNIQUE INDEX "LlmJob_activeKey_key" ON "LlmJob"("activeKey");
