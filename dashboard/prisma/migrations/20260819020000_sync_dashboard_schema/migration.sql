-- Bring the migration history in line with the Prisma schema. Several models
-- and columns were added to schema.prisma without a corresponding migration.

CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT,
    "name" TEXT,
    "image" TEXT,
    "emailVerified" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

CREATE TABLE "Account" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,
    CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "Session" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "sessionToken" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expires" DATETIME NOT NULL,
    CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "VerificationToken" (
    "identifier" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires" DATETIME NOT NULL
);

PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Project" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "repositoryUrl" TEXT NOT NULL DEFAULT '',
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "description" TEXT NOT NULL DEFAULT '',
    "color" TEXT NOT NULL DEFAULT '#6366f1',
    "provider" TEXT NOT NULL DEFAULT '',
    "providerRepoId" TEXT NOT NULL DEFAULT '',
    "ownerSlug" TEXT NOT NULL DEFAULT '',
    "archived" BOOLEAN NOT NULL DEFAULT false,
    "archivedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "userId" TEXT,
    CONSTRAINT "Project_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE NO ACTION ON UPDATE CASCADE
);
INSERT INTO "new_Project" (
    "id", "name", "repositoryUrl", "defaultBranch", "description", "color",
    "createdAt", "updatedAt"
)
SELECT
    "id", "name", "repositoryUrl", "defaultBranch", "description", "color",
    "createdAt", "updatedAt"
FROM "Project";
DROP TABLE "Project";
ALTER TABLE "new_Project" RENAME TO "Project";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

ALTER TABLE "Scan" ADD COLUMN "progressPhase" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Scan" ADD COLUMN "progressPhaseName" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Scan" ADD COLUMN "progressPercent" REAL NOT NULL DEFAULT 0;
ALTER TABLE "Scan" ADD COLUMN "progressMessage" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Scan" ADD COLUMN "progressEta" REAL;
ALTER TABLE "Scan" ADD COLUMN "progressUpdatedAt" DATETIME;

ALTER TABLE "Finding" ADD COLUMN "defenseContext" TEXT;
ALTER TABLE "Rule" ADD COLUMN "sourceFile" TEXT NOT NULL DEFAULT '';

CREATE TABLE "LlmJob" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "totalFindings" INTEGER NOT NULL DEFAULT 0,
    "reviewedCount" INTEGER NOT NULL DEFAULT 0,
    "falsePositives" INTEGER NOT NULL DEFAULT 0,
    "currentBatch" INTEGER NOT NULL DEFAULT 0,
    "totalBatches" INTEGER NOT NULL DEFAULT 0,
    "errorMessage" TEXT NOT NULL DEFAULT '',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" DATETIME,
    "completedAt" DATETIME,
    CONSTRAINT "LlmJob_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "Account_provider_providerAccountId_key" ON "Account"("provider", "providerAccountId");
CREATE UNIQUE INDEX "Session_sessionToken_key" ON "Session"("sessionToken");
CREATE UNIQUE INDEX "VerificationToken_token_key" ON "VerificationToken"("token");
CREATE UNIQUE INDEX "VerificationToken_identifier_token_key" ON "VerificationToken"("identifier", "token");
CREATE INDEX "Project_name_idx" ON "Project"("name");
CREATE INDEX "Project_userId_idx" ON "Project"("userId");
CREATE INDEX "Project_archived_idx" ON "Project"("archived");
CREATE INDEX "LlmJob_status_idx" ON "LlmJob"("status");
CREATE INDEX "LlmJob_scanId_idx" ON "LlmJob"("scanId");
CREATE INDEX "LlmJob_createdAt_idx" ON "LlmJob"("createdAt");
