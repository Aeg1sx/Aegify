CREATE TABLE "ScanRepositoryCoverage" (
    "scanId" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "analyzedFiles" INTEGER NOT NULL,
    "discoveryErrors" INTEGER NOT NULL,
    PRIMARY KEY ("scanId", "repositoryId"),
    CONSTRAINT "ScanRepositoryCoverage_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
