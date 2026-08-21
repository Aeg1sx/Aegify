ALTER TABLE "Endpoint" ADD COLUMN "repositoryId" TEXT NOT NULL DEFAULT '';
ALTER TABLE "Endpoint" ADD COLUMN "calledByFrontend" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Endpoint" ADD COLUMN "frontendCallCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "Endpoint" ADD COLUMN "frontendEvidence" TEXT NOT NULL DEFAULT '[]';
ALTER TABLE "Endpoint" ADD COLUMN "exposedViaGateway" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Endpoint" ADD COLUMN "gatewayRouteIds" TEXT NOT NULL DEFAULT '[]';
ALTER TABLE "Endpoint" ADD COLUMN "gatewayEvidence" TEXT NOT NULL DEFAULT '[]';

DROP INDEX "Endpoint_scanId_path_method_key";
CREATE UNIQUE INDEX "Endpoint_scanId_repositoryId_path_method_key"
ON "Endpoint"("scanId", "repositoryId", "path", "method");
