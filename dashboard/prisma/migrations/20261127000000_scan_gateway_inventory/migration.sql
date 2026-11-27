CREATE TABLE "ScanGatewayInventory" (
    "scanId" TEXT NOT NULL PRIMARY KEY,
    "inputStatus" TEXT NOT NULL,
    "fileCount" INTEGER NOT NULL,
    "resolved" INTEGER NOT NULL,
    "ambiguous" INTEGER NOT NULL,
    "unresolved" INTEGER NOT NULL,
    "omittedFiles" INTEGER NOT NULL,
    "omittedRoutes" INTEGER NOT NULL,
    "details" TEXT NOT NULL,
    CONSTRAINT "ScanGatewayInventory_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
