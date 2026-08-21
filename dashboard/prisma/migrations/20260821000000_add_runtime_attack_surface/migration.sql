ALTER TABLE "Endpoint" ADD COLUMN "runtimeObserved" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Endpoint" ADD COLUMN "runtimeObservationCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Endpoint" ADD COLUMN "runtimeEvidence" TEXT NOT NULL DEFAULT '[]';
