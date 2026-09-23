-- Preserve existing sessions during the upgrade. Restore assigns a fresh epoch
-- so a session version from before/after the backup cannot become valid again.
ALTER TABLE "User" ADD COLUMN "sessionEpoch" TEXT NOT NULL DEFAULT '';
