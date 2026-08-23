"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Globe,
  Shield,
  ShieldOff,
  FileCode,
  Upload,
  Search,
  List,
  FolderOpen,
  ChevronDown,
  ChevronRight,
  MonitorSmartphone,
  Route,
  Activity,
} from "lucide-react";

interface EndpointItem {
  id: string;
  scanId: string;
  path: string;
  method: string;
  handlerFunction: string;
  filePath: string;
  lineStart: number;
  framework: string;
  authRequired: boolean;
  parameters: string;
  repositoryId: string;
  calledByFrontend: boolean;
  frontendCallCount: number;
  exposedViaGateway: boolean;
  gatewayRouteIds: string;
  runtimeObserved: boolean;
  runtimeObservationCount: number;
  scan: { id: string; repository: string; createdAt: string };
}

const METHOD_COLORS: Record<string, string> = {
  GET: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
  POST: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
  PUT: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
  DELETE: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  PATCH: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400",
  ALL: "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400",
};

type ViewMode = "flat" | "handler";

export default function EndpointsPage() {
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [frameworks, setFrameworks] = useState<string[]>([]);
  const [filterFramework, setFilterFramework] = useState("");
  const [filterMethod, setFilterMethod] = useState("");
  const [filterAuth, setFilterAuth] = useState("");
  const [filterExposure, setFilterExposure] = useState("");
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const [totalUnfiltered, setTotalUnfiltered] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("flat");
  const [expandedHandlers, setExpandedHandlers] = useState<Set<string>>(new Set());

  useEffect(() => {
    const params = new URLSearchParams();
    if (filterFramework) params.set("framework", filterFramework);
    if (filterMethod) params.set("method", filterMethod);
    if (filterAuth) params.set("authOnly", filterAuth);

    if (!showAll) params.set("quality", "api");
    fetch(`/api/endpoints?${params}`)
      .then((r) => r.json())
      .then((data) => {
        setEndpoints(data.endpoints || []);
        setFrameworks(data.frameworks || []);
        setTotalUnfiltered(data.totalUnfiltered || data.endpoints?.length || 0);
      })
      .finally(() => setLoading(false));
  }, [filterFramework, filterMethod, filterAuth, showAll]);

  // Client-side search filter
  const filtered = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return endpoints.filter((ep) => {
      const matchesSearch =
        !q ||
        ep.path.toLowerCase().includes(q) ||
        ep.handlerFunction.toLowerCase().includes(q) ||
        ep.framework.toLowerCase().includes(q) ||
        ep.filePath.toLowerCase().includes(q) ||
        ep.repositoryId.toLowerCase().includes(q) ||
        ep.method.toLowerCase().includes(q);
      const matchesExposure =
        !filterExposure ||
        (filterExposure === "frontend" && ep.calledByFrontend) ||
        (filterExposure === "gateway" && ep.exposedViaGateway) ||
        (filterExposure === "runtime" && ep.runtimeObserved) ||
        (filterExposure === "unlinked" &&
          !ep.calledByFrontend &&
          !ep.exposedViaGateway &&
          !ep.runtimeObserved);
      return matchesSearch && matchesExposure;
    });
  }, [endpoints, searchQuery, filterExposure]);

  // Group by handler for grouped view
  const handlerGroups = useMemo(() => {
    const groups = new Map<string, { handler: string; filePath: string; framework: string; endpoints: EndpointItem[] }>();
    for (const ep of filtered) {
      // Use filePath as grouping key (handler name can be duplicated across files)
      const key = ep.filePath || ep.handlerFunction;
      const existing = groups.get(key);
      if (existing) {
        existing.endpoints.push(ep);
      } else {
        groups.set(key, {
          handler: ep.handlerFunction,
          filePath: ep.filePath,
          framework: ep.framework,
          endpoints: [ep],
        });
      }
    }
    // Sort by endpoint count descending
    return Array.from(groups.values()).sort((a, b) => b.endpoints.length - a.endpoints.length);
  }, [filtered]);

  const toggleHandler = (key: string) => {
    setExpandedHandlers((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const expandAll = () => {
    setExpandedHandlers(new Set(handlerGroups.map((g) => g.filePath)));
  };

  const collapseAll = () => {
    setExpandedHandlers(new Set());
  };

  const handleOpenAPIUpload = async () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,.yaml,.yml";
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      setImporting(true);
      setImportResult(null);

      try {
        const scansRes = await fetch("/api/scans?limit=1");
        const scansData = await scansRes.json();
        const latestScan = scansData.scans?.[0];

        if (!latestScan) {
          setImportResult("No scan found. Run a scan first to import endpoints.");
          setImporting(false);
          return;
        }

        const text = await file.text();
        let spec;
        try {
          spec = JSON.parse(text);
        } catch {
          setImportResult("Only JSON format is supported. Convert YAML to JSON first.");
          setImporting(false);
          return;
        }

        const res = await fetch(
          `/api/endpoints/import-openapi?scanId=${latestScan.id}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(spec),
          },
        );
        const data = await res.json();
        if (res.ok) {
          setImportResult(
            `Imported ${data.imported} endpoints (${data.skipped} duplicates skipped)`,
          );
          const params = new URLSearchParams();
          if (filterFramework) params.set("framework", filterFramework);
          if (filterMethod) params.set("method", filterMethod);
          if (filterAuth) params.set("authOnly", filterAuth);
          const refreshRes = await fetch(`/api/endpoints?${params}`);
          const refreshData = await refreshRes.json();
          setEndpoints(refreshData.endpoints || []);
          setFrameworks(refreshData.frameworks || []);
        } else {
          setImportResult(`Import failed: ${data.error}`);
        }
      } catch (err) {
        setImportResult(`Import error: ${err}`);
      } finally {
        setImporting(false);
      }
    };
    input.click();
  };

  const authCount = filtered.filter((e) => e.authRequired).length;
  const noAuthCount = filtered.filter((e) => !e.authRequired).length;
  const frontendCount = filtered.filter((e) => e.calledByFrontend).length;
  const gatewayCount = filtered.filter((e) => e.exposedViaGateway).length;
  const runtimeCount = filtered.filter((e) => e.runtimeObserved).length;

  // Extract short filename from full path
  const shortFile = (filePath: string) => {
    const parts = filePath.split("/");
    // Show last 3 segments for context
    return parts.length > 3 ? ".../" + parts.slice(-3).join("/") : filePath;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Endpoints</h1>
          <p className="text-muted-foreground">
            API attack surface detected from scans
          </p>
        </div>
        <div className="flex items-center gap-2">
          {importResult && (
            <span className="text-xs text-muted-foreground">{importResult}</span>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenAPIUpload}
            disabled={importing}
            className="flex items-center gap-2"
          >
            <Upload className="h-4 w-4" />
            {importing ? "Importing..." : "Import OpenAPI"}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Endpoints</p>
                <p className="text-3xl font-bold">{filtered.length}</p>
              </div>
              <Globe className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Exposure Evidence</p>
                <p className="text-3xl font-bold">
                  {frontendCount + gatewayCount + runtimeCount}
                </p>
                <p className="text-xs text-muted-foreground">
                  {frontendCount} UI · {gatewayCount} gateway · {runtimeCount} runtime
                </p>
              </div>
              <MonitorSmartphone className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Auth Required</p>
                <p className="text-3xl font-bold text-[var(--status-fixed)]">
                  {authCount}
                </p>
              </div>
              <Shield className="h-8 w-8 text-[var(--status-fixed)]" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">No Auth</p>
                <p className="text-3xl font-bold text-[var(--status-open)]">
                  {noAuthCount}
                </p>
              </div>
              <ShieldOff className="h-8 w-8 text-[var(--status-open)]" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">
                  {viewMode === "handler" ? "Files" : "Frameworks"}
                </p>
                <p className="text-3xl font-bold">
                  {viewMode === "handler" ? handlerGroups.length : frameworks.length}
                </p>
              </div>
              <FileCode className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search + Filters */}
      <div className="flex flex-col gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by path, handler, framework, file..."
            className="w-full h-9 rounded-md border border-input bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          />
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <select
            value={filterFramework}
            onChange={(e) => {
              setLoading(true);
              setFilterFramework(e.target.value);
            }}
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">All frameworks</option>
            {frameworks.map((fw) => (
              <option key={fw} value={fw}>
                {fw}
              </option>
            ))}
          </select>
          <select
            value={filterMethod}
            onChange={(e) => {
              setLoading(true);
              setFilterMethod(e.target.value);
            }}
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">All methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>
          <select
            value={filterAuth}
            onChange={(e) => {
              setLoading(true);
              setFilterAuth(e.target.value);
            }}
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">All auth states</option>
            <option value="true">Auth required</option>
            <option value="false">No auth</option>
          </select>
          <select
            value={filterExposure}
            onChange={(e) => setFilterExposure(e.target.value)}
            className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          >
            <option value="">All exposure evidence</option>
            <option value="frontend">Called by frontend</option>
            <option value="gateway">Exposed via gateway</option>
            <option value="runtime">Observed at runtime</option>
            <option value="unlinked">No correlated evidence</option>
          </select>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={showAll}
              onChange={(e) => {
                setLoading(true);
                setShowAll(e.target.checked);
              }}
              className="rounded border-input"
            />
            Show all ({totalUnfiltered})
          </label>

          <div className="ml-auto flex items-center gap-1 border border-input rounded-md">
            <button
              onClick={() => setViewMode("flat")}
              className={`p-1.5 rounded-sm ${viewMode === "flat" ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:text-foreground"}`}
              title="Flat list"
            >
              <List className="h-4 w-4" />
            </button>
            <button
              onClick={() => setViewMode("handler")}
              className={`p-1.5 rounded-sm ${viewMode === "handler" ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:text-foreground"}`}
              title="Group by file"
            >
              <FolderOpen className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Endpoint List */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              {filtered.length} endpoints
              {searchQuery && (
                <span className="text-sm font-normal text-muted-foreground">
                  (filtered from {endpoints.length})
                </span>
              )}
            </span>
            {viewMode === "handler" && (
              <span className="flex items-center gap-2">
                <Button variant="ghost" size="sm" onClick={expandAll} className="text-xs h-7">
                  Expand all
                </Button>
                <Button variant="ghost" size="sm" onClick={collapseAll} className="text-xs h-7">
                  Collapse all
                </Button>
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-pulse text-muted-foreground">Loading...</div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Globe className="h-12 w-12 mb-4 opacity-50" />
              <p>{searchQuery ? "No endpoints match your search" : "No endpoints detected"}</p>
              {!searchQuery && (
                <p className="text-xs mt-1">
                  Endpoints are detected from scans that include framework-specific route patterns
                </p>
              )}
            </div>
          ) : viewMode === "flat" ? (
            /* Flat list view */
            <div className="space-y-1">
              <div className="grid grid-cols-[80px_1fr_180px_100px_140px_60px] gap-4 px-3 py-2 text-xs text-muted-foreground font-medium border-b border-border">
                <span>Method</span>
                <span>Path</span>
                <span>Handler</span>
                <span>Framework</span>
                <span>Exposure evidence</span>
                <span>Auth</span>
              </div>
              {filtered.map((ep) => (
                <Link
                  key={ep.id}
                  href={`/endpoints/${ep.id}`}
                  className="grid grid-cols-[80px_1fr_180px_100px_140px_60px] gap-4 px-3 py-2 rounded-md hover:bg-accent/30 items-center cursor-pointer"
                >
                  <Badge
                    className={`text-xs font-mono justify-center ${
                      METHOD_COLORS[ep.method] || METHOD_COLORS.ALL
                    }`}
                  >
                    {ep.method}
                  </Badge>
                  <span className="text-sm font-mono truncate">{ep.path}</span>
                  <span className="text-xs font-mono text-muted-foreground truncate">
                    {ep.handlerFunction}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {ep.framework || "-"}
                  </span>
                  <span className="flex items-center gap-1.5">
                    {ep.calledByFrontend && (
                      <Badge variant="secondary" className="gap-1 text-[10px]">
                        <MonitorSmartphone className="h-3 w-3" />
                        UI {ep.frontendCallCount}
                      </Badge>
                    )}
                    {ep.exposedViaGateway && (
                      <Badge variant="outline" className="gap-1 text-[10px]">
                        <Route className="h-3 w-3" />
                        GW
                      </Badge>
                    )}
                    {ep.runtimeObserved && (
                      <Badge variant="outline" className="gap-1 text-[10px]">
                        <Activity className="h-3 w-3" />
                        RT {ep.runtimeObservationCount}
                      </Badge>
                    )}
                    {!ep.calledByFrontend &&
                      !ep.exposedViaGateway &&
                      !ep.runtimeObserved && (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </span>
                  <span>
                    {ep.authRequired ? (
                      <Shield className="h-4 w-4 text-[var(--status-fixed)]" />
                    ) : (
                      <ShieldOff className="h-4 w-4 text-muted-foreground/40" />
                    )}
                  </span>
                </Link>
              ))}
            </div>
          ) : (
            /* Handler/File grouped view */
            <div className="space-y-1">
              {handlerGroups.map((group) => {
                const isExpanded = expandedHandlers.has(group.filePath);
                const groupAuthCount = group.endpoints.filter((e) => e.authRequired).length;
                return (
                  <div key={group.filePath} className="border border-border rounded-md">
                    <button
                      onClick={() => toggleHandler(group.filePath)}
                      className="w-full flex items-center gap-3 px-3 py-2.5 hover:bg-accent/30 text-left"
                    >
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">
                            {shortFile(group.filePath)}
                          </span>
                          {group.framework && (
                            <Badge variant="outline" className="text-[10px] shrink-0">
                              {group.framework}
                            </Badge>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        {group.endpoints.some((e) => e.calledByFrontend) && (
                          <MonitorSmartphone className="h-3.5 w-3.5 text-primary" />
                        )}
                        {group.endpoints.some((e) => e.exposedViaGateway) && (
                          <Route className="h-3.5 w-3.5 text-primary" />
                        )}
                        {group.endpoints.some((e) => e.runtimeObserved) && (
                          <Activity className="h-3.5 w-3.5 text-primary" />
                        )}
                        {groupAuthCount > 0 && (
                          <span className="flex items-center gap-1 text-xs text-[var(--status-fixed)]">
                            <Shield className="h-3 w-3" />
                            {groupAuthCount}
                          </span>
                        )}
                        <Badge variant="secondary" className="text-xs">
                          {group.endpoints.length} endpoint{group.endpoints.length > 1 ? "s" : ""}
                        </Badge>
                      </div>
                    </button>
                    {isExpanded && (
                      <div className="border-t border-border">
                        {group.endpoints.map((ep) => (
                          <Link
                            key={ep.id}
                            href={`/endpoints/${ep.id}`}
                            className="grid grid-cols-[80px_1fr_160px_100px_50px] gap-3 px-3 pl-10 py-1.5 hover:bg-accent/30 items-center cursor-pointer text-sm"
                          >
                            <Badge
                              className={`text-[10px] font-mono justify-center ${
                                METHOD_COLORS[ep.method] || METHOD_COLORS.ALL
                              }`}
                            >
                              {ep.method}
                            </Badge>
                            <span className="font-mono truncate text-xs">{ep.path}</span>
                            <span className="text-[11px] font-mono text-muted-foreground truncate">
                              {ep.handlerFunction}
                            </span>
                            <span className="flex items-center gap-1">
                              {ep.calledByFrontend && (
                                <MonitorSmartphone className="h-3.5 w-3.5 text-primary" />
                              )}
                              {ep.exposedViaGateway && (
                                <Route className="h-3.5 w-3.5 text-primary" />
                              )}
                              {ep.runtimeObserved && (
                                <Activity className="h-3.5 w-3.5 text-primary" />
                              )}
                            </span>
                            <span className="flex justify-center">
                              {ep.authRequired ? (
                                <Shield className="h-3.5 w-3.5 text-[var(--status-fixed)]" />
                              ) : (
                                <ShieldOff className="h-3.5 w-3.5 text-muted-foreground/40" />
                              )}
                            </span>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
