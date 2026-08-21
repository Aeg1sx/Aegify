-- CreateTable
CREATE TABLE "Project" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "repositoryUrl" TEXT NOT NULL DEFAULT '',
    "defaultBranch" TEXT NOT NULL DEFAULT 'main',
    "description" TEXT NOT NULL DEFAULT '',
    "color" TEXT NOT NULL DEFAULT '#6366f1',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "Endpoint" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "handlerFunction" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "lineStart" INTEGER NOT NULL DEFAULT 0,
    "lineEnd" INTEGER NOT NULL DEFAULT 0,
    "framework" TEXT NOT NULL DEFAULT '',
    "authRequired" BOOLEAN NOT NULL DEFAULT false,
    "parameters" TEXT NOT NULL DEFAULT '[]',
    "middleware" TEXT NOT NULL DEFAULT '[]',
    CONSTRAINT "Endpoint_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "ruleName" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "confidence" REAL NOT NULL DEFAULT 0.8,
    "status" TEXT NOT NULL DEFAULT 'open',
    "source" TEXT NOT NULL DEFAULT 'sast',
    "filePath" TEXT NOT NULL,
    "lineStart" INTEGER NOT NULL,
    "lineEnd" INTEGER NOT NULL,
    "codeSnippet" TEXT NOT NULL DEFAULT '',
    "message" TEXT NOT NULL,
    "cweId" INTEGER,
    "owaspCategory" TEXT,
    "taintFlow" TEXT,
    "callChain" TEXT,
    "remediation" TEXT,
    "llmAnalysis" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Finding" ("callChain", "codeSnippet", "confidence", "createdAt", "cweId", "filePath", "id", "lineEnd", "lineStart", "message", "owaspCategory", "remediation", "ruleId", "ruleName", "scanId", "severity", "status", "taintFlow") SELECT "callChain", "codeSnippet", "confidence", "createdAt", "cweId", "filePath", "id", "lineEnd", "lineStart", "message", "owaspCategory", "remediation", "ruleId", "ruleName", "scanId", "severity", "status", "taintFlow" FROM "Finding";
DROP TABLE "Finding";
ALTER TABLE "new_Finding" RENAME TO "Finding";
CREATE INDEX "Finding_scanId_idx" ON "Finding"("scanId");
CREATE INDEX "Finding_severity_idx" ON "Finding"("severity");
CREATE INDEX "Finding_status_idx" ON "Finding"("status");
CREATE INDEX "Finding_ruleId_idx" ON "Finding"("ruleId");
CREATE INDEX "Finding_filePath_idx" ON "Finding"("filePath");
CREATE INDEX "Finding_source_idx" ON "Finding"("source");
CREATE TABLE "new_Scan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "repository" TEXT NOT NULL DEFAULT '',
    "branch" TEXT NOT NULL DEFAULT '',
    "commitSha" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'completed',
    "scanType" TEXT NOT NULL DEFAULT 'sast',
    "filesScanned" INTEGER NOT NULL DEFAULT 0,
    "duration" REAL NOT NULL DEFAULT 0,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "projectId" TEXT,
    CONSTRAINT "Scan_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Scan" ("branch", "commitSha", "createdAt", "duration", "filesScanned", "id", "repository", "status") SELECT "branch", "commitSha", "createdAt", "duration", "filesScanned", "id", "repository", "status" FROM "Scan";
DROP TABLE "Scan";
ALTER TABLE "new_Scan" RENAME TO "Scan";
CREATE INDEX "Scan_createdAt_idx" ON "Scan"("createdAt");
CREATE INDEX "Scan_repository_idx" ON "Scan"("repository");
CREATE INDEX "Scan_projectId_idx" ON "Scan"("projectId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE INDEX "Project_name_idx" ON "Project"("name");

-- CreateIndex
CREATE INDEX "Endpoint_scanId_idx" ON "Endpoint"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "Endpoint_scanId_path_method_key" ON "Endpoint"("scanId", "path", "method");
