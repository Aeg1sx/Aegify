ALTER TABLE "FindingIdentity" ADD COLUMN "owner" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "dueAt" DATETIME;
ALTER TABLE "FindingIdentity" ADD COLUMN "priority" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "tags" TEXT NOT NULL DEFAULT '[]';
ALTER TABLE "FindingIdentity" ADD COLUMN "ticketProvider" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "ticketKey" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "ticketUrl" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "lastNotifiedAt" DATETIME;
ALTER TABLE "FindingIdentity" ADD COLUMN "workflowRevision" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "FindingIdentity" ADD COLUMN "workflowNeedsReview" BOOLEAN NOT NULL DEFAULT false;

-- Preserve every observation. Start nonempty historical management data in
-- review, then copy only a unique, bounded tuple from the latest observation
-- set whose source scope was established by the previous migration.
UPDATE FindingIdentity AS identity SET workflowNeedsReview = true
WHERE EXISTS (
  SELECT 1 FROM Finding f JOIN Scan s ON s.id = f.scanId
  WHERE f.identityId = identity.id AND f.scanId = identity.lastSeenScanId
    AND s.projectId = identity.projectId
    AND (f.owner <> '' OR f.dueAt IS NOT NULL OR f.priority <> '' OR f.tags <> '[]'
      OR f.ticketProvider <> '' OR f.ticketKey <> '' OR f.ticketUrl <> ''
      OR f.lastNotifiedAt IS NOT NULL)
);

WITH candidates AS (
  SELECT DISTINCT i.id AS identityId, f.owner, f.dueAt, f.priority, f.tags,
    f.ticketProvider, f.ticketKey, f.ticketUrl, f.lastNotifiedAt
  FROM FindingIdentity i JOIN Finding f ON f.identityId = i.id
  JOIN Scan s ON s.id = f.scanId AND s.projectId = i.projectId
  WHERE f.scanId = i.lastSeenScanId
    AND (f.owner <> '' OR f.dueAt IS NOT NULL OR f.priority <> '' OR f.tags <> '[]'
      OR f.ticketProvider <> '' OR f.ticketKey <> '' OR f.ticketUrl <> ''
      OR f.lastNotifiedAt IS NOT NULL)
), bounded AS (
  SELECT * FROM candidates c
  WHERE length(c.owner) <= 200 AND instr(c.owner, char(0)) = 0
    AND c.owner NOT GLOB ('*[' || char(1) || '-' || char(31) || ']*')
    AND c.priority IN ('', 'p0', 'p1', 'p2', 'p3')
    AND length(c.tags) <= 4096
    AND CASE WHEN json_valid(c.tags) THEN
      json_type(c.tags) = 'array'
      AND (SELECT count(*) FROM json_each(c.tags)) <= 20
      AND NOT EXISTS (SELECT 1 FROM json_each(c.tags)
        WHERE type <> 'text' OR length(value) > 50)
      ELSE false END
    AND length(c.ticketProvider) <= 50 AND length(c.ticketKey) <= 128
    AND length(c.ticketUrl) <= 4096
    AND (c.dueAt IS NULL OR (typeof(c.dueAt) IN ('integer', 'real') AND c.dueAt BETWEEN -62135596800000 AND 253402300799999)
      OR (typeof(c.dueAt) = 'text' AND julianday(c.dueAt) IS NOT NULL))
    AND (c.lastNotifiedAt IS NULL OR (typeof(c.lastNotifiedAt) IN ('integer', 'real') AND c.lastNotifiedAt BETWEEN -62135596800000 AND 253402300799999)
      OR (typeof(c.lastNotifiedAt) = 'text' AND julianday(c.lastNotifiedAt) IS NOT NULL))
)
UPDATE FindingIdentity AS identity
SET (owner, dueAt, priority, tags, ticketProvider, ticketKey, ticketUrl, lastNotifiedAt) = (
    SELECT owner, dueAt, priority, tags, ticketProvider, ticketKey, ticketUrl, lastNotifiedAt
    FROM bounded WHERE identityId = identity.id
  ), workflowNeedsReview = false
WHERE identity.modulePath <> ''
  AND (SELECT count(*) FROM candidates WHERE identityId = identity.id) = 1
  AND EXISTS (SELECT 1 FROM bounded WHERE identityId = identity.id);
