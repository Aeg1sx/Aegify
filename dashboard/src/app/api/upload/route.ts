import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireUploadAccess } from "@/lib/upload-access";
import { AccessDenied, authorizeProject, resolvePrincipal } from "@/lib/project-access";
import { authenticateUploadToken } from "@/lib/project-tokens";
import { accessError } from "@/lib/access";
import { readSpecBody } from "@/lib/openapi-import";
import { uploadValidationError } from "@/lib/upload-validation";
import { importSarif, SarifValidationError, validateSarifReport } from "@/lib/sarif-import";
import { notifyImportedScan } from "@/lib/scan-notifications";

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

export async function POST(request: NextRequest) {
  const principal = await requireUploadAccess(request);
  if (principal instanceof Response) return principal;
  try {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > MAX_UPLOAD_BYTES) {
      return NextResponse.json(
        { error: "SARIF upload exceeds the 100 MB limit" },
        { status: 413 },
      );
    }

    const contentType = request.headers.get("content-type") || "";

    let sarif: unknown;
    let formProjectName: string | null = null;

    const uploadBytes = await readSpecBody(request, MAX_UPLOAD_BYTES);
    if (contentType.includes("multipart/form-data")) {
      const formData = await new Response(uploadBytes, { headers: { "Content-Type": contentType } }).formData();
      const file = formData.get("file") as File;
      if (!file) {
        return NextResponse.json({ error: "No file provided" }, { status: 400 });
      }
      const uploadError = uploadValidationError(file, "sarif");
      if (uploadError) {
        const status = uploadError.includes("exceeds") ? 413 : 415;
        return NextResponse.json({ error: uploadError }, { status });
      }
      const text = await file.text();
      sarif = JSON.parse(text);
      formProjectName = (formData.get("projectName") as string) || null;
    } else {
      const text = new TextDecoder().decode(uploadBytes);
      if (Buffer.byteLength(text, "utf8") > MAX_UPLOAD_BYTES) {
        return NextResponse.json(
          { error: "SARIF upload exceeds the 100 MB limit" },
          { status: 413 },
        );
      }
      sarif = JSON.parse(text);
    }

    validateSarifReport(sarif);

    // Check for projectId query param or auto-match by repository/projectName
    const reqUrl = new URL(request.url);
    const repository = reqUrl.searchParams.get("repository") || "";
    let projectId = principal.kind === "service" ? principal.projectId : reqUrl.searchParams.get("projectId") || null;
    const canManageWorkspace = principal.kind === "user" && principal.access.workspaceAdmin;
    if (!projectId && !canManageWorkspace) return NextResponse.json({ error: "Choose an existing project for this upload." }, { status: 400 });

    // Auto-link to project by repository URL if not explicitly provided
    if (!projectId && repository && canManageWorkspace) {
      const matchedProject = await prisma.project.findFirst({
        where: { repositoryUrl: repository },
      });
      if (matchedProject) projectId = matchedProject.id;
    }

    // Auto-create/link project from multipart projectName field or query param
    if (!projectId && canManageWorkspace) {
      const projectName = formProjectName || reqUrl.searchParams.get("projectName");
      if (projectName) {
        const existing = await prisma.project.findFirst({
          where: { name: projectName },
        });
        if (existing) {
          projectId = existing.id;
        } else {
          const created = await prisma.project.create({
            data: { name: projectName, repositoryUrl: repository, ...(principal.kind === "user" && principal.access.userId ? { userId: principal.access.userId, members: { create: { userId: principal.access.userId, role: "admin" } } } : {}) },
          });
          projectId = created.id;
        }
      }
    }

    if (projectId && principal.kind === "user") {
      try { await authorizeProject(prisma, principal.access, projectId, "maintainer"); }
      catch (error) { return accessError(error); }
    }
    const branch = reqUrl.searchParams.get("branch") || "";
    const project = projectId ? await prisma.project.findUnique({ where: { id: projectId } }) : null;
    if (projectId && (!project || project.archived)) return NextResponse.json({ error: "Select an active project." }, { status: 409 });
    const receipt = await importSarif(prisma, sarif, {
      projectId, repository, branch, commitSha: reqUrl.searchParams.get("commit") || "",
      actorId: principal.kind === "service" ? principal.actorId : principal.access.userId || "development",
      canManageWorkspace,
      authorize: async (tx) => {
        if (principal.kind === "service") {
          const authorization = request.headers.get("authorization");
          const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : request.headers.get("x-aegify-token") || "";
          const current = await authenticateUploadToken(tx, token, process.env);
          if (!current || current.projectId !== projectId) throw new AccessDenied(401, "Upload credential expired or was revoked.");
        } else {
          const current = await resolvePrincipal(tx, principal.access.userId || undefined, process.env);
          if (projectId) await authorizeProject(tx, current, projectId, "maintainer");
          else if (!current.workspaceAdmin) throw new AccessDenied();
        }
      },
    });
    notifyImportedScan(prisma, receipt, repository, branch).catch(() => console.error("Scan notification delivery failed."));
    return NextResponse.json(receipt);
  } catch (error) {
    if (error instanceof AccessDenied) return accessError(error);
    if (error instanceof Error && error.message === "Specification request exceeds the size limit.") return NextResponse.json({ error: "SARIF upload exceeds the 100 MB limit" }, { status: 413 });
    if (error instanceof SyntaxError) return NextResponse.json({ error: "SARIF must contain valid JSON." }, { status: 400 });
    if (error instanceof SarifValidationError) return NextResponse.json({ error: error.message }, { status: 400 });
    console.error("Evidence publication failed; transaction rolled back.");
    return NextResponse.json({ error: "Upload failed; no findings or baselines were published." }, { status: 500 });
  }
}
