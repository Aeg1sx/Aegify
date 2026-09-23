import { requireResource } from "@/lib/access";
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { parseApiContract, record, SPEC_MAX_BYTES, type ApiContract } from "@/lib/openapi-contract";
import { contractRepositoryIds, fetchApiContract, importApiContract, inspectApiContract, readSpecBody, specMutationOriginAllowed } from "@/lib/openapi-import";
import { uploadValidationError } from "@/lib/upload-validation";

const headers = { "Cache-Control": "no-store" };
export async function GET(request: NextRequest) {
  const scanId = request.nextUrl.searchParams.get("scanId");
  const access = await requireResource(request, "scan", scanId, "viewer");
  if (access instanceof Response) return access;
  if (!scanId || !await prisma.scan.findUnique({ where: { id: scanId }, select: { id: true } })) return NextResponse.json({ error: "Select an existing scan." }, { status: 404, headers });
  const id = request.nextUrl.searchParams.get("id");
  if (id) {
    const spec = await prisma.apiSpecification.findFirst({ where: { id, scanId } });
    if (!spec) return NextResponse.json({ error: "Specification not found in this scan." }, { status: 404, headers });
    const contract = JSON.parse(spec.contract) as ApiContract;
    return NextResponse.json({ spec: { ...spec, contract }, comparison: await inspectApiContract(prisma, scanId, spec.repositoryId, contract) }, { headers });
  }
  const repositoryIds = await contractRepositoryIds(prisma, scanId);
  const specifications = await prisma.apiSpecification.findMany({ where: { scanId }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], take: 100, select: { id: true, scanId: true, repositoryId: true, sourceType: true, sourceName: true, sourceUrl: true, contentHash: true, title: true, apiVersion: true, specVersion: true, operationCount: true, createdAt: true } });
  return NextResponse.json({ repositoryIds, specifications, total: await prisma.apiSpecification.count({ where: { scanId } }) }, { headers });
}
export async function POST(request: NextRequest) {
  if (!specMutationOriginAllowed(request, process.env)) return NextResponse.json({ error: "Same-origin request required." }, { status: 403, headers });
  const scanId = request.nextUrl.searchParams.get("scanId");
  const access = await requireResource(request, "scan", scanId, "maintainer");
  if (access instanceof Response) return access;
  if (!scanId || !await prisma.scan.findUnique({ where: { id: scanId }, select: { id: true } })) return NextResponse.json({ error: "Select an existing scan." }, { status: 404, headers });
  const repositoryId = request.nextUrl.searchParams.get("repositoryId");
  if (repositoryId === null || !(await contractRepositoryIds(prisma, scanId)).includes(repositoryId)) return NextResponse.json({ error: "Select a repository belonging to this scan." }, { status: 400, headers });
  try {
    const contentType = request.headers.get("content-type") || "";
    const bytes = await readSpecBody(request, SPEC_MAX_BYTES + 64 * 1024);
    let contract: ApiContract; let sourceType = "upload"; let sourceName = "inline-specification"; let sourceUrl = "";
    if (contentType.includes("multipart/form-data")) {
      const form = await new Response(bytes, { headers: { "Content-Type": contentType } }).formData();
      const file = form.get("file");
      if (!(file instanceof File)) throw new Error("Choose a JSON or YAML specification file.");
      const error = uploadValidationError(file, "openapi"); if (error) throw new Error(error);
      sourceName = file.name.split(/[\\/]/).pop()?.slice(0, 200) || "uploaded-specification";
      contract = parseApiContract(await file.text());
    } else {
      const source = new TextDecoder().decode(bytes);
      let json: Record<string, unknown> = {}; try { json = record(JSON.parse(source)); } catch { /* YAML may be posted directly. */ }
      if (Object.hasOwn(json, "url") && !json.openapi && !json.swagger) {
        if (json.authorized !== true) throw new Error("Confirm you may retrieve this specification URL.");
        if (typeof json.url !== "string") throw new Error("Enter a specification URL.");
        const fetched = await fetchApiContract(json.url); contract = fetched.contract;
        sourceType = "url"; sourceUrl = fetched.source; sourceName = new URL(sourceUrl).hostname + new URL(sourceUrl).pathname;
      } else contract = parseApiContract(source);
    }
    const comparison = await inspectApiContract(prisma, scanId, repositoryId, contract);
    if (request.nextUrl.searchParams.get("preview") === "true") return NextResponse.json({ contract, comparison, sourceName }, { headers });
    const expectedHash = request.nextUrl.searchParams.get("expectedHash");
    if (expectedHash !== contract.digest) return NextResponse.json({ error: "Preview this exact specification before importing. If its contents changed, preview it again." }, { status: 409, headers });
    if (!contract.operations.length) throw new Error("No supported path operations found. No snapshot was saved.");
    const result = await importApiContract(prisma, { scanId, repositoryId, sourceType, sourceName, sourceUrl, contract });
    return NextResponse.json({ ...result, total: contract.operations.length, specVersion: contract.version, warnings: contract.warnings }, { status: 200, headers });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error && error.name === "Error" ? error.message.slice(0, 350) : "Specification import failed." }, { status: 400, headers });
  }
}
