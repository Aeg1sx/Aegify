CREATE INDEX "AuditEvent_targetId_action_projectId_createdAt_idx"
ON "AuditEvent"("targetId", "action", "projectId", "createdAt");
