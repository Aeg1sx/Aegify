-- Include the event ID so pages and exports can order collisions on the timestamp.
CREATE INDEX "AuditEvent_projectId_createdAt_id_idx" ON "AuditEvent"("projectId", "createdAt", "id");
DROP INDEX "AuditEvent_projectId_createdAt_idx";
