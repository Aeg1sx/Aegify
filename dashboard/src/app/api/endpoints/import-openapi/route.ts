import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { uploadValidationError } from "@/lib/upload-validation";

interface OpenAPIPath {
  [method: string]: {
    operationId?: string;
    summary?: string;
    tags?: string[];
    security?: Record<string, string[]>[];
    parameters?: Array<{
      name: string;
      in: string;
      schema?: { type?: string };
      type?: string;
    }>;
  };
}

interface OpenAPISpec {
  openapi?: string;
  swagger?: string;
  basePath?: string;
  servers?: Array<{ url: string }>;
  paths?: Record<string, OpenAPIPath>;
  security?: Record<string, string[]>[];
}

const HTTP_METHODS = new Set([
  "get", "post", "put", "delete", "patch", "head", "options",
]);

/**
 * POST /api/endpoints/import-openapi
 * Import endpoints from an OpenAPI/Swagger spec file.
 * Accepts JSON body or multipart form data with file upload.
 * Query param: scanId (required) - which scan to associate endpoints with.
 */
export async function POST(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const scanId = url.searchParams.get("scanId");

    if (!scanId) {
      return NextResponse.json(
        { error: "scanId query parameter is required" },
        { status: 400 },
      );
    }

    // Verify scan exists
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    // Parse spec from request body
    let spec: OpenAPISpec;
    const contentType = request.headers.get("content-type") || "";

    if (contentType.includes("multipart/form-data")) {
      const formData = await request.formData();
      const file = formData.get("file") as File;
      if (!file) {
        return NextResponse.json({ error: "No file provided" }, { status: 400 });
      }
      const uploadError = uploadValidationError(file, "openapi");
      if (uploadError) {
        const status = uploadError.includes("exceeds") ? 413 : 415;
        return NextResponse.json({ error: uploadError }, { status });
      }
      const text = await file.text();
      // Try JSON first, then YAML
      try {
        spec = JSON.parse(text);
      } catch {
        // Simple YAML parsing for common OpenAPI patterns
        // In production, use a proper YAML library
        return NextResponse.json(
          { error: "Only JSON OpenAPI specs are supported via upload. Convert YAML to JSON first." },
          { status: 400 },
        );
      }
    } else {
      spec = await request.json();
    }

    // Validate it's an OpenAPI spec
    if (!spec.openapi && !spec.swagger) {
      return NextResponse.json(
        { error: "Invalid OpenAPI/Swagger specification: missing openapi or swagger version field" },
        { status: 400 },
      );
    }

    // Extract base path
    let basePath = "";
    if (spec.swagger && spec.basePath) {
      basePath = spec.basePath.replace(/\/$/, "");
    } else if (spec.servers?.[0]?.url) {
      try {
        const serverUrl = new URL(spec.servers[0].url);
        basePath = serverUrl.pathname.replace(/\/$/, "");
      } catch {
        basePath = spec.servers[0].url.replace(/\/$/, "");
      }
    }

    // Parse endpoints
    const globalSecurity = spec.security || [];
    const endpoints: Array<{
      scanId: string;
      path: string;
      method: string;
      handlerFunction: string;
      filePath: string;
      framework: string;
      authRequired: boolean;
      parameters: string;
      middleware: string;
    }> = [];

    const paths = spec.paths || {};
    for (const [pathStr, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== "object") continue;

      const fullPath = basePath + pathStr;

      for (const [methodStr, operation] of Object.entries(pathItem)) {
        if (!HTTP_METHODS.has(methodStr) || !operation || typeof operation !== "object") continue;

        // Check auth
        const opSecurity = operation.security || globalSecurity;
        const authRequired = Array.isArray(opSecurity) && opSecurity.some(
          (s: Record<string, string[]>) => Object.keys(s).length > 0,
        );

        // Extract parameters
        const params = (operation.parameters || []).map(
          (p: { name: string; in: string; schema?: { type?: string }; type?: string }) => ({
            name: p.name,
            location: p.in || "unknown",
            paramType: p.schema?.type || p.type || "",
          }),
        );

        const handler = operation.operationId || operation.summary || `${methodStr.toUpperCase()} ${fullPath}`;
        const tags = operation.tags || [];

        endpoints.push({
          scanId,
          path: fullPath,
          method: methodStr.toUpperCase(),
          handlerFunction: handler,
          filePath: "openapi-import",
          framework: "OpenAPI",
          authRequired,
          parameters: JSON.stringify(params),
          middleware: JSON.stringify(tags),
        });
      }
    }

    if (endpoints.length === 0) {
      return NextResponse.json(
        { error: "No endpoints found in specification", imported: 0 },
        { status: 200 },
      );
    }

    // Deduplicate against existing endpoints for this scan
    const existing = await prisma.endpoint.findMany({
      where: { scanId },
      select: { path: true, method: true },
    });
    const existingKeys = new Set(existing.map((e) => `${e.method}:${e.path}`));

    const newEndpoints = endpoints.filter(
      (ep) => !existingKeys.has(`${ep.method}:${ep.path}`),
    );

    if (newEndpoints.length > 0) {
      await prisma.endpoint.createMany({ data: newEndpoints });
    }

    return NextResponse.json({
      imported: newEndpoints.length,
      skipped: endpoints.length - newEndpoints.length,
      total: endpoints.length,
      specVersion: spec.openapi || spec.swagger,
    });
  } catch (error) {
    console.error("OpenAPI import error:", error);
    return NextResponse.json(
      { error: "Import failed" },
      { status: 500 },
    );
  }
}
