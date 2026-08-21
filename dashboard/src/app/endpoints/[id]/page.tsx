"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ArrowLeft,
  Globe,
  Shield,
  ShieldOff,
  AlertTriangle,
  MonitorSmartphone,
  Route,
  Activity,
} from "lucide-react";

interface EndpointDetail {
  id: string;
  scanId: string;
  path: string;
  method: string;
  handlerFunction: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  framework: string;
  authRequired: boolean;
  parameters: string;
  middleware: string;
  repositoryId: string;
  calledByFrontend: boolean;
  frontendCallCount: number;
  frontendEvidence: string;
  exposedViaGateway: boolean;
  gatewayRouteIds: string;
  gatewayEvidence: string;
  runtimeObserved: boolean;
  runtimeObservationCount: number;
  runtimeEvidence: string;
  scan: { id: string; repository: string; branch: string; createdAt: string };
}

interface FrontendEvidence {
  id?: string;
  path?: string;
  method?: string;
  filePath?: string;
  line?: number;
  client?: string;
  repositoryId?: string;
  dynamic?: boolean;
  confidence?: number;
  matchKind?: string;
  linkConfidence?: number;
}

interface GatewayEvidence {
  id?: string;
  uri?: string;
  path_patterns?: string[];
  methods?: string[];
  filters?: string[];
  file_path?: string;
  line?: number;
  repository_id?: string;
  matchKind?: string;
  linkConfidence?: number;
}

interface RuntimeEvidence {
  id?: string;
  kind?: string;
  method?: string;
  path?: string;
  statusCode?: number | null;
  durationMs?: number | null;
  traceId?: string;
  spanId?: string;
  repositoryId?: string;
  passed?: boolean | null;
  matchKind?: string;
  linkConfidence?: number;
}

interface RelatedFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  message: string;
  lineStart: number;
}

function parseJsonArray<T>(value: string): T[] {
  try {
    const parsed: unknown = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

export default function EndpointDetailPage() {
  const params = useParams();
  const [endpoint, setEndpoint] = useState<EndpointDetail | null>(null);
  const [findings, setFindings] = useState<RelatedFinding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`/api/endpoints/${params.id}`)
      .then((r) => r.json())
      .then((data) => {
        setEndpoint(data.endpoint);
        setFindings(data.relatedFindings || []);
      })
      .finally(() => setLoading(false));
  }, [params.id]);

  if (loading || !endpoint) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const endpointParams = parseJsonArray<{
    name: string;
    location: string;
    paramType?: string;
  }>(endpoint.parameters);
  const middlewareList = parseJsonArray<string>(endpoint.middleware);
  const frontendEvidence = parseJsonArray<FrontendEvidence>(
    endpoint.frontendEvidence,
  );
  const gatewayEvidence = parseJsonArray<GatewayEvidence>(
    endpoint.gatewayEvidence,
  );
  const runtimeEvidence = parseJsonArray<RuntimeEvidence>(
    endpoint.runtimeEvidence,
  );

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-start gap-3">
        <Link
          href="/endpoints"
          className="text-muted-foreground hover:text-foreground mt-1"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Badge className="text-sm font-mono">{endpoint.method}</Badge>
            <h1 className="text-xl font-bold font-mono">{endpoint.path}</h1>
          </div>
          <p className="text-sm text-muted-foreground">
            {endpoint.framework ? `${endpoint.framework} endpoint` : "API endpoint"} in{" "}
            <span className="font-mono">{endpoint.filePath}</span>
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Endpoint Details
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-muted-foreground">Handler</p>
              <p className="text-sm font-mono">{endpoint.handlerFunction}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">File</p>
              <p className="text-sm font-mono">
                {endpoint.filePath}:{endpoint.lineStart}
              </p>
            </div>
            {endpoint.framework && (
              <div>
                <p className="text-xs text-muted-foreground">Framework</p>
                <p className="text-sm">{endpoint.framework}</p>
              </div>
            )}
            {endpoint.repositoryId && (
              <div>
                <p className="text-xs text-muted-foreground">Repository</p>
                <p className="text-sm font-mono">{endpoint.repositoryId}</p>
              </div>
            )}
            <div>
              <p className="text-xs text-muted-foreground">Authentication</p>
              <div className="flex items-center gap-2 mt-1">
                {endpoint.authRequired ? (
                  <>
                    <Shield className="h-4 w-4 text-[var(--status-fixed)]" />
                    <span className="text-sm text-[var(--status-fixed)]">Required</span>
                  </>
                ) : (
                  <>
                    <ShieldOff className="h-4 w-4 text-[var(--status-open)]" />
                    <span className="text-sm text-[var(--status-open)]">Not required</span>
                  </>
                )}
              </div>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Scan</p>
              <Link
                href={`/scans/${endpoint.scanId}`}
                className="text-sm text-primary hover:underline"
              >
                {endpoint.scan.repository || endpoint.scanId.slice(0, 8)}
              </Link>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Attack Surface Evidence</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {endpoint.calledByFrontend && (
                  <Badge variant="secondary" className="gap-1">
                    <MonitorSmartphone className="h-3.5 w-3.5" />
                    Called by frontend ({endpoint.frontendCallCount})
                  </Badge>
                )}
                {endpoint.exposedViaGateway && (
                  <Badge variant="outline" className="gap-1">
                    <Route className="h-3.5 w-3.5" />
                    Exposed via gateway
                  </Badge>
                )}
                {endpoint.runtimeObserved && (
                  <Badge variant="outline" className="gap-1">
                    <Activity className="h-3.5 w-3.5" />
                    Runtime observed ({endpoint.runtimeObservationCount})
                  </Badge>
                )}
                {!endpoint.calledByFrontend &&
                  !endpoint.exposedViaGateway &&
                  !endpoint.runtimeObserved && (
                  <span className="text-sm text-muted-foreground">
                    No correlated frontend, gateway, or runtime evidence was found.
                    This does not prove that the endpoint is unused or unreachable.
                  </span>
                )}
              </div>

              {frontendEvidence.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-muted-foreground">
                    Frontend calls
                  </p>
                  {frontendEvidence.map((evidence, index) => (
                    <div
                      key={evidence.id || index}
                      className="rounded-md border border-border p-2 text-xs"
                    >
                      <p className="font-mono">
                        {evidence.method || "ANY"} {evidence.path || endpoint.path}
                      </p>
                      <p className="mt-1 font-mono text-muted-foreground break-all">
                        {evidence.filePath || "unknown source"}
                        {evidence.line ? `:${evidence.line}` : ""}
                      </p>
                      <p className="mt-1 text-muted-foreground">
                        {evidence.client || "HTTP client"} · {evidence.matchKind || "path"}
                        {evidence.dynamic ? " · dynamic URL" : ""}
                      </p>
                    </div>
                  ))}
                </div>
              )}

              {gatewayEvidence.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-muted-foreground">
                    Gateway routes
                  </p>
                  {gatewayEvidence.map((evidence, index) => (
                    <div
                      key={`${evidence.id || "route"}-${index}`}
                      className="rounded-md border border-border p-2 text-xs"
                    >
                      <p className="font-mono">
                        {evidence.id || "route"} → {evidence.uri || "unknown upstream"}
                      </p>
                      <p className="mt-1 font-mono text-muted-foreground">
                        {(evidence.path_patterns || []).join(", ") || "dynamic path"}
                      </p>
                      <p className="mt-1 font-mono text-muted-foreground break-all">
                        {evidence.file_path || "unknown source"}
                        {evidence.line ? `:${evidence.line}` : ""}
                      </p>
                      {(evidence.filters || []).length > 0 && (
                        <p className="mt-1 text-muted-foreground">
                          Filters: {(evidence.filters || []).join(", ")}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {runtimeEvidence.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-medium text-muted-foreground">
                    Runtime observations
                  </p>
                  {runtimeEvidence.map((evidence, index) => (
                    <div
                      key={evidence.id || index}
                      className="rounded-md border border-border p-2 text-xs"
                    >
                      <p className="font-mono">
                        {evidence.method || "ANY"} {evidence.path || endpoint.path}
                        {evidence.statusCode ? ` → ${evidence.statusCode}` : ""}
                      </p>
                      <p className="mt-1 text-muted-foreground">
                        {evidence.kind || "runtime"} · {evidence.matchKind || "path"}
                        {evidence.durationMs != null
                          ? ` · ${evidence.durationMs.toFixed(1)} ms`
                          : ""}
                        {evidence.passed != null
                          ? evidence.passed
                            ? " · passed"
                            : " · failed"
                          : ""}
                      </p>
                      {evidence.traceId && (
                        <p className="mt-1 font-mono text-muted-foreground break-all">
                          trace {evidence.traceId}
                          {evidence.spanId ? ` / span ${evidence.spanId}` : ""}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {endpointParams.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">
                  Parameters ({endpointParams.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {endpointParams.map((p, i) => (
                    <div key={i} className="flex items-center gap-3 text-sm">
                      <span className="font-mono">{p.name}</span>
                      <Badge variant="outline" className="text-xs">
                        {p.location}
                      </Badge>
                      {p.paramType && (
                        <span className="text-xs text-muted-foreground">
                          {p.paramType}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {middlewareList.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Middleware</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  {middlewareList.map((m: string, i: number) => (
                    <p key={i} className="text-sm font-mono">
                      {m}
                    </p>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {findings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Related Findings ({findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {findings.map((f) => (
                <Link
                  key={f.id}
                  href={`/findings/${f.id}`}
                  className="block p-3 rounded-md border border-border hover:bg-accent/30 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-xs font-mono text-muted-foreground">
                      {f.ruleId}
                    </span>
                  </div>
                  <p className="text-sm truncate">{f.message}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Line {f.lineStart}
                  </p>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
