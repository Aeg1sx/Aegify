"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { SeverityChart } from "@/components/severity-chart";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft,
  Search,
  FileCode,
  Clock,
  AlertTriangle,
  GitBranch,
} from "lucide-react";
import { format } from "date-fns";

interface Finding {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  confidence: number;
  status: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  message: string;
  cweId: number | null;
  owaspCategory: string | null;
}

interface ScanDetail {
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  status: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  findings: Finding[];
  severities: Record<string, number>;
  statuses: Record<string, number>;
  topRules: Array<{ ruleId: string; ruleName: string; count: number }>;
  hasCallGraph?: boolean;
  callGraphNodeCount?: number;
}

export default function ScanDetailPage() {
  const params = useParams();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState<string>("");

  useEffect(() => {
    fetch(`/api/scans/${params.id}`)
      .then((r) => r.json())
      .then(setScan)
      .finally(() => setLoading(false));
  }, [params.id]);

  if (loading || !scan) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  const filteredFindings = (scan.findings || []).filter((f) => {
    if (filterSeverity && f.severity !== filterSeverity) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        f.message.toLowerCase().includes(q) ||
        f.filePath.toLowerCase().includes(q) ||
        f.ruleId.toLowerCase().includes(q) ||
        f.ruleName.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/scans" className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold">
            {scan.repository || "Scan Detail"}
          </h1>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {format(new Date(scan.createdAt), "PPp")}
            </span>
            {scan.branch && <span>{scan.branch}</span>}
            {scan.commitSha && (
              <span className="font-mono">{scan.commitSha.slice(0, 7)}</span>
            )}
            <span>{scan.filesScanned} files scanned</span>
            <span>{scan.duration.toFixed(1)}s</span>
          </div>
        </div>
        {scan.hasCallGraph && (
          <Link href={`/graph/${scan.id}`}>
            <Button variant="outline" className="flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              Call Graph
              {scan.callGraphNodeCount ? (
                <span className="text-xs text-muted-foreground">
                  ({scan.callGraphNodeCount} nodes)
                </span>
              ) : null}
            </Button>
          </Link>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityChart severities={scan.severities} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Status Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(scan.statuses).map(([status, count]) => (
                <div key={status} className="flex items-center justify-between">
                  <StatusBadge status={status} />
                  <span className="font-mono text-sm">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Top Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {scan.topRules.slice(0, 5).map((rule) => (
                <div
                  key={rule.ruleId}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="truncate max-w-[180px]">{rule.ruleName}</span>
                  <span className="font-mono text-muted-foreground">
                    {rule.count}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Findings ({filteredFindings.length})
            </CardTitle>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search findings..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 w-64"
                />
              </div>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {filteredFindings.map((finding) => (
              <Link
                key={finding.id}
                href={`/findings/${finding.id}`}
                className="block p-3 rounded-md border border-border hover:bg-accent/30 transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={finding.severity} />
                      <StatusBadge status={finding.status} />
                      <span className="text-xs font-mono text-muted-foreground">
                        {finding.ruleId}
                      </span>
                      {finding.cweId && (
                        <span className="text-xs text-muted-foreground">
                          CWE-{finding.cweId}
                        </span>
                      )}
                    </div>
                    <p className="text-sm truncate">{finding.message}</p>
                    <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                      <FileCode className="h-3 w-3" />
                      <span className="font-mono">
                        {finding.filePath}:{finding.lineStart}
                      </span>
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {(finding.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
