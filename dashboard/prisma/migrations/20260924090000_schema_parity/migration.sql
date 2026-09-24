-- Only future raw inserts gain the current timestamp. Retain every recorded
-- value, including the legacy epoch sentinel; do not invent historical dates.
-- Rule has no referencing foreign keys, secondary indexes or triggers.
-- Keep the replacement atomic without disabling foreign-key enforcement.
BEGIN IMMEDIATE;

CREATE TABLE "new_Rule" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "cweId" INTEGER,
    "owaspCategory" TEXT,
    "languages" TEXT NOT NULL DEFAULT '',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "findingCount" INTEGER NOT NULL DEFAULT 0,
    "yamlContent" TEXT NOT NULL DEFAULT '',
    "description" TEXT NOT NULL DEFAULT '',
    "sourceFile" TEXT NOT NULL DEFAULT '',
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO "new_Rule" (
    "id", "name", "severity", "cweId", "owaspCategory", "languages", "enabled",
    "findingCount", "yamlContent", "description", "sourceFile", "updatedAt"
)
SELECT
    "id", "name", "severity", "cweId", "owaspCategory", "languages", "enabled",
    "findingCount", "yamlContent", "description", "sourceFile", "updatedAt"
FROM "Rule";
DROP TABLE "Rule";
ALTER TABLE "new_Rule" RENAME TO "Rule";

COMMIT;
