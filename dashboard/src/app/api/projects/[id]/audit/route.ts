import { Readable } from "node:stream";
import { NextRequest, NextResponse } from "next/server";
import { accessError, requireResource } from "@/lib/access";
import { createPrismaClient, prisma } from "@/lib/prisma";
import { AccessDenied } from "@/lib/project-access";
import { exportAuditSnapshot, readAuditPage } from "@/lib/project-audit";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const access = await requireResource(request, "project", id, "admin");
  if (access instanceof Response) return access;
  const query = request.nextUrl.searchParams;
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  try {
    if (!query.has("format")) {
      return NextResponse.json(await readAuditPage(prisma, id, access.userId, process.env, query), { headers });
    }
    if (query.get("format") !== "jsonl" || query.size !== 1) {
      throw new AccessDenied(400, "Use format=jsonl to download the complete project audit log.");
    }
    // The libSQL adapter locks its client during transactions. Keep the shared
    // dashboard connection free while the export reads its own WAL snapshot.
    const reader = createPrismaClient();
    const snapshot = await exportAuditSnapshot(reader, id, access.userId, process.env, request.signal)
      .finally(() => reader.$disconnect());
    try {
      // The read snapshot can outlive a role or session change; recheck before handing it off.
      const current = await requireResource(request, "project", id, "admin");
      if (current instanceof Response) { await snapshot.file.close(); return current; }
      const downloadHeaders = {
        ...headers, "Content-Type": "application/x-ndjson; charset=utf-8",
        "Content-Disposition": 'attachment; filename="aegify-project-audit.jsonl"',
        "X-Aegify-Export-Bytes": String(snapshot.bytes), "X-Aegify-Event-Count": String(snapshot.count),
      };
      if (request.method === "HEAD" || snapshot.bytes === 0) {
        await snapshot.file.close();
        return new Response(null, { headers: downloadHeaders });
      }
      const body = snapshot.file.createReadStream({ start: 0, autoClose: true, signal: request.signal });
      return new Response(Readable.toWeb(body) as ReadableStream<Uint8Array>, { headers: downloadHeaders });
    } catch (error) {
      await snapshot.file.close();
      throw error;
    }
  } catch (error) { return accessError(error); }
}
