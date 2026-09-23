CREATE TABLE "ProjectMember" (
  "projectId" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "role" TEXT NOT NULL CHECK ("role" IN ('viewer', 'triager', 'maintainer', 'admin')),
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" DATETIME NOT NULL,
  PRIMARY KEY ("projectId", "userId"),
  CONSTRAINT "ProjectMember_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT "ProjectMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE INDEX "ProjectMember_userId_idx" ON "ProjectMember"("userId");
-- Only a recorded owner receives membership. Unowned legacy data is admin-only.
INSERT INTO "ProjectMember" ("projectId", "userId", "role", "updatedAt")
SELECT p."id", p."userId", 'admin', CURRENT_TIMESTAMP FROM "Project" p
INNER JOIN "User" u ON u."id" = p."userId";

CREATE TABLE "ProjectServiceToken" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "projectId" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "prefix" TEXT NOT NULL,
  "scope" TEXT NOT NULL DEFAULT 'scan:upload' CHECK ("scope" = 'scan:upload'),
  "createdBy" TEXT NOT NULL,
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" DATETIME NOT NULL,
  "revokedAt" DATETIME,
  "lastUsedAt" DATETIME,
  CONSTRAINT "ProjectServiceToken_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "ProjectServiceToken_tokenHash_key" ON "ProjectServiceToken"("tokenHash");
CREATE INDEX "ProjectServiceToken_projectId_createdAt_idx" ON "ProjectServiceToken"("projectId", "createdAt");
CREATE INDEX "ProjectServiceToken_expiresAt_idx" ON "ProjectServiceToken"("expiresAt");

CREATE TABLE "AuditEvent" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "projectId" TEXT,
  "actorId" TEXT NOT NULL,
  "action" TEXT NOT NULL,
  "targetId" TEXT NOT NULL,
  "details" TEXT NOT NULL DEFAULT '{}',
  "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX "AuditEvent_projectId_createdAt_idx" ON "AuditEvent"("projectId", "createdAt");
CREATE INDEX "AuditEvent_actorId_createdAt_idx" ON "AuditEvent"("actorId", "createdAt");
