-- CreateTable
CREATE TABLE "CallGraphNode" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "qualifiedName" TEXT NOT NULL,
    "filePath" TEXT NOT NULL,
    "lineStart" INTEGER NOT NULL DEFAULT 0,
    "lineEnd" INTEGER NOT NULL DEFAULT 0,
    "nodeType" TEXT NOT NULL DEFAULT 'function',
    "hasFinding" BOOLEAN NOT NULL DEFAULT false,
    "findingSeverity" TEXT,
    CONSTRAINT "CallGraphNode_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateTable
CREATE TABLE "CallGraphEdge" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "sourceNodeId" TEXT NOT NULL,
    "targetNodeId" TEXT NOT NULL,
    "callSiteLine" INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "CallGraphEdge_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "CallGraphEdge_sourceNodeId_fkey" FOREIGN KEY ("sourceNodeId") REFERENCES "CallGraphNode" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "CallGraphEdge_targetNodeId_fkey" FOREIGN KEY ("targetNodeId") REFERENCES "CallGraphNode" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "CallGraphNode_scanId_idx" ON "CallGraphNode"("scanId");

-- CreateIndex
CREATE UNIQUE INDEX "CallGraphNode_scanId_qualifiedName_key" ON "CallGraphNode"("scanId", "qualifiedName");

-- CreateIndex
CREATE INDEX "CallGraphEdge_scanId_idx" ON "CallGraphEdge"("scanId");

-- CreateIndex
CREATE INDEX "CallGraphEdge_sourceNodeId_idx" ON "CallGraphEdge"("sourceNodeId");

-- CreateIndex
CREATE INDEX "CallGraphEdge_targetNodeId_idx" ON "CallGraphEdge"("targetNodeId");
