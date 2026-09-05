"use client";

import Link from "next/link";
import { CodeHighlight } from "@/components/code-highlight";

export interface ApiContractContextView {
  endpointId: string; boundary: string; snapshotLimit: number;
  references: Array<{ specificationId: string; title: string; contentHash: string; pointer: string; reviewNote: string; security: unknown; parameters: unknown; requestBody: unknown; responses: unknown }>;
}
export function ApiContractPanel({ contexts, scanId }: { contexts: ApiContractContextView[]; scanId: string }) {
  if (!contexts.length) return null;
  return <section className="workbench-panel min-w-0 overflow-hidden"><div className="workbench-heading"><h2 className="text-sm font-semibold">API contract context</h2><Link href={"/api-specs?scanId=" + scanId} className="text-xs text-primary">Specifications →</Link></div><div className="space-y-4 p-5">{contexts.map((context) => <div key={context.endpointId}><p className="text-xs leading-6 text-muted-foreground">{context.boundary}</p><Link className="mt-2 block text-xs text-primary" href={"/endpoints/" + context.endpointId}>Inspect associated handler →</Link>{context.references.map((reference) => <details key={reference.specificationId + reference.pointer} className="mt-4 min-w-0 rounded-md border"><summary className="cursor-pointer break-all p-3 text-xs font-medium">{reference.title}<span className="ml-2 font-mono text-muted-foreground">{reference.contentHash.slice(0, 12)}</span></summary><p className="px-3 pb-3 text-xs leading-6 text-muted-foreground">{reference.reviewNote}</p><CodeHighlight code={JSON.stringify({ pointer: reference.pointer, security: reference.security, parameters: reference.parameters, requestBody: reference.requestBody, responses: reference.responses }, null, 2)} language="json" filePath="api-contract-context.json" /></details>)}</div>)}</div></section>;
}
