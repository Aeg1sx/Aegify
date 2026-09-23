ALTER TABLE "FindingIdentity" ADD COLUMN "repositoryId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "FindingIdentity" ADD COLUMN "modulePath" TEXT NOT NULL DEFAULT '';

CREATE INDEX "FindingIdentity_projectId_repositoryId_modulePath_ruleId_idx"
ON "FindingIdentity"("projectId", "repositoryId", "modulePath", "ruleId");

-- Preserve identity IDs, triage, history and fingerprints. Infer logical scope
-- only where every retained occurrence agrees; collisions stay unbound.
WITH raw_scopes AS (
  SELECT DISTINCT i.id AS identityId, f.ruleId, f.repositoryId,
    replace(CASE WHEN f.modulePath <> '' THEN f.modulePath ELSE f.filePath END,
      char(92), '/') AS path
  FROM FindingIdentity i
  JOIN Finding f ON f.identityId = i.id
  JOIN Scan s ON s.id = f.scanId AND s.projectId = i.projectId
), scopes AS (
  SELECT DISTINCT identityId, ruleId, repositoryId,
    CASE WHEN substr(path, 1, 2) = './' THEN substr(path, 3) ELSE path END AS path
  FROM raw_scopes
)
UPDATE FindingIdentity AS identity
SET repositoryId = (SELECT repositoryId FROM scopes WHERE identityId = identity.id LIMIT 1),
    modulePath = (SELECT path FROM scopes WHERE identityId = identity.id LIMIT 1)
WHERE (SELECT count(*) FROM scopes WHERE identityId = identity.id) = 1
  AND EXISTS (
    SELECT 1 FROM scopes scope WHERE scope.identityId = identity.id
      AND scope.ruleId = identity.ruleId
      AND scope.path <> '' AND length(scope.path) <= 4096
      AND substr(scope.path, 1, 1) <> '/' AND instr(scope.path, ':') = 0
      AND instr('/' || scope.path || '/', '/../') = 0
      AND instr('/' || scope.path || '/', '/./') = 0
      AND instr(scope.path, '//') = 0
      AND instr(scope.path, char(0)) = 0
      AND scope.path NOT GLOB ('*[' || char(1) || '-' || char(31) || ']*')
      AND length(scope.repositoryId) <= 128
      AND trim(scope.repositoryId) = scope.repositoryId
      AND instr(scope.repositoryId, char(0)) = 0
      AND scope.repositoryId NOT GLOB ('*[' || char(1) || '-' || char(31) || ']*')
  );
