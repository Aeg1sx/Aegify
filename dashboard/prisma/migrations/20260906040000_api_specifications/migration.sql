CREATE TABLE "ApiSpecification" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL DEFAULT '',
    "sourceType" TEXT NOT NULL,
    "sourceName" TEXT NOT NULL,
    "sourceUrl" TEXT NOT NULL DEFAULT '',
    "contentHash" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "specVersion" TEXT NOT NULL,
    "apiVersion" TEXT NOT NULL,
    "contract" TEXT NOT NULL,
    "operationCount" INTEGER NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ApiSpecification_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "ApiSpecification_scanId_repositoryId_contentHash_key" ON "ApiSpecification"("scanId", "repositoryId", "contentHash");
CREATE INDEX "ApiSpecification_scanId_repositoryId_createdAt_idx" ON "ApiSpecification"("scanId", "repositoryId", "createdAt");
