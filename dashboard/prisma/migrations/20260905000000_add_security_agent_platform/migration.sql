-- Evidence-bound multi-agent security operations and approval audit trail.
CREATE TABLE "AgentRun" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "mode" TEXT NOT NULL DEFAULT 'deep',
    "provider" TEXT NOT NULL DEFAULT 'deterministic',
    "status" TEXT NOT NULL DEFAULT 'running',
    "currentRole" TEXT NOT NULL DEFAULT 'surface',
    "workspaceSnapshot" TEXT NOT NULL DEFAULT '',
    "requestPayload" TEXT NOT NULL DEFAULT '{}',
    "artifactDigest" TEXT NOT NULL DEFAULT '',
    "errorMessage" TEXT NOT NULL DEFAULT '',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" DATETIME,
    CONSTRAINT "AgentRun_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "AgentStage" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "runId" TEXT NOT NULL,
    "sequence" INTEGER NOT NULL,
    "role" TEXT NOT NULL,
    "agentCode" TEXT NOT NULL,
    "agentName" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "summary" TEXT NOT NULL DEFAULT '',
    "facts" TEXT NOT NULL DEFAULT '{}',
    "evidenceIds" TEXT NOT NULL DEFAULT '[]',
    "reachability" TEXT NOT NULL DEFAULT '[]',
    "dynamicPlans" TEXT NOT NULL DEFAULT '[]',
    "cveAssessments" TEXT NOT NULL DEFAULT '[]',
    "improvementProposals" TEXT NOT NULL DEFAULT '[]',
    "narrative" TEXT NOT NULL DEFAULT '{}',
    "promptDigest" TEXT NOT NULL DEFAULT '',
    "errorMessage" TEXT NOT NULL DEFAULT '',
    "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" DATETIME,
    CONSTRAINT "AgentStage_runId_fkey" FOREIGN KEY ("runId") REFERENCES "AgentRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "AgentApproval" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "runId" TEXT NOT NULL,
    "action" TEXT NOT NULL DEFAULT 'dynamic_validation',
    "resourceId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "scopeDigest" TEXT NOT NULL,
    "requestedBy" TEXT NOT NULL DEFAULT '',
    "decidedBy" TEXT NOT NULL DEFAULT '',
    "decisionNote" TEXT NOT NULL DEFAULT '',
    "requestedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "decidedAt" DATETIME,
    "expiresAt" DATETIME,
    CONSTRAINT "AgentApproval_runId_fkey" FOREIGN KEY ("runId") REFERENCES "AgentRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "AgentEvent" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "runId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "actor" TEXT NOT NULL DEFAULT 'system',
    "message" TEXT NOT NULL,
    "payload" TEXT NOT NULL DEFAULT '{}',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AgentEvent_runId_fkey" FOREIGN KEY ("runId") REFERENCES "AgentRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE "AgentEvidenceRecord" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "runId" TEXT NOT NULL,
    "approvalId" TEXT,
    "kind" TEXT NOT NULL,
    "producer" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "digest" TEXT NOT NULL,
    "payload" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AgentEvidenceRecord_runId_fkey" FOREIGN KEY ("runId") REFERENCES "AgentRun" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AgentEvidenceRecord_approvalId_fkey" FOREIGN KEY ("approvalId") REFERENCES "AgentApproval" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX "AgentRun_scanId_idx" ON "AgentRun"("scanId");
CREATE INDEX "AgentRun_status_idx" ON "AgentRun"("status");
CREATE INDEX "AgentRun_createdAt_idx" ON "AgentRun"("createdAt");
CREATE UNIQUE INDEX "AgentStage_runId_sequence_key" ON "AgentStage"("runId", "sequence");
CREATE INDEX "AgentStage_runId_role_idx" ON "AgentStage"("runId", "role");
CREATE INDEX "AgentStage_status_idx" ON "AgentStage"("status");
CREATE UNIQUE INDEX "AgentApproval_runId_resourceId_key" ON "AgentApproval"("runId", "resourceId");
CREATE INDEX "AgentApproval_runId_status_idx" ON "AgentApproval"("runId", "status");
CREATE INDEX "AgentApproval_expiresAt_idx" ON "AgentApproval"("expiresAt");
CREATE INDEX "AgentEvent_runId_createdAt_idx" ON "AgentEvent"("runId", "createdAt");
CREATE UNIQUE INDEX "AgentEvidenceRecord_runId_digest_key" ON "AgentEvidenceRecord"("runId", "digest");
CREATE INDEX "AgentEvidenceRecord_runId_kind_idx" ON "AgentEvidenceRecord"("runId", "kind");
CREATE INDEX "AgentEvidenceRecord_approvalId_idx" ON "AgentEvidenceRecord"("approvalId");
