-- CreateTable
CREATE TABLE "Setting" (
    "key" TEXT NOT NULL PRIMARY KEY,
    "value" TEXT NOT NULL,
    "encrypted" BOOLEAN NOT NULL DEFAULT false,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
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
    "description" TEXT NOT NULL DEFAULT ''
);
INSERT INTO "new_Rule" ("cweId", "enabled", "findingCount", "id", "languages", "name", "owaspCategory", "severity") SELECT "cweId", "enabled", "findingCount", "id", "languages", "name", "owaspCategory", "severity" FROM "Rule";
DROP TABLE "Rule";
ALTER TABLE "new_Rule" RENAME TO "Rule";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
