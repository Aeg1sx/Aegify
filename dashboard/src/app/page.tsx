"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { SeverityChart } from "@/components/severity-chart";
import {
  Shield,
  ScanSearch,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileCode,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";

interface Stats {
  totalScans: number;
  totalFindings: number;
  severities: Record<string, number>;
  statuses: Record<string, number>;
  recentScans: Array<{
    id: string;
    repository: string;
    branch: string;
    status: string;
    filesScanned: number;
    duration: number;
    createdAt: string;
    findingsCount: number;
  }>;
  topRules: Array<{
    ruleId: string;
    ruleName: string;
    severity: string;
    count: number;
  }>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/stats")
      .then((r) => r.json())
      .then(setStats)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!stats || stats.totalScans === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
        <Shield className="h-16 w-16 text-muted-foreground" />
        <h2 className="text-xl font-semibold">No scans yet</h2>
        <p className="text-muted-foreground text-center max-w-md">
          Upload a SARIF report from your CodeGuard scan to get started.
        </p>
        <Link
          href="/upload"
          className="mt-2 px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm"
        >
          Upload SARIF
        </Link>
      </div>
    );
  }

  const openCount = stats.statuses?.open || 0;
  const fixedCount = stats.statuses?.fixed || 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Security posture overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Scans</p>
                <p className="text-3xl font-bold">{stats.totalScans}</p>
              </div>
              <ScanSearch className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Findings</p>
                <p className="text-3xl font-bold">{stats.totalFindings}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-muted-foreground" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Open</p>
                <p className="text-3xl font-bold text-[var(--status-open)]">{openCount}</p>
              </div>
              <FileCode className="h-8 w-8 text-[var(--status-open)]" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Fixed</p>
                <p className="text-3xl font-bold text-[var(--status-fixed)]">{fixedCount}</p>
              </div>
              <CheckCircle className="h-8 w-8 text-[var(--status-fixed)]" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityChart severities={stats.severities} />
            <div className="grid grid-cols-2 gap-3 mt-4">
              {Object.entries(stats.severities).map(([sev, count]) => (
                <div
                  key={sev}
                  className="flex items-center justify-between p-2 rounded-md bg-muted/50"
                >
                  <SeverityBadge severity={sev} />
                  <span className="font-mono text-sm">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Recent scans */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Recent Scans</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {stats.recentScans.slice(0, 5).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="block p-3 rounded-md border border-border hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ScanSearch className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm font-medium">
                        {scan.repository || "unnamed"}
                      </span>
                    </div>
                    <span className="text-sm font-mono">
                      {scan.findingsCount} findings
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatDistanceToNow(new Date(scan.createdAt), {
                        addSuffix: true,
                      })}
                    </span>
                    <span>{scan.filesScanned} files</span>
                    <span>{scan.duration.toFixed(1)}s</span>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Top rules */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Top Triggered Rules</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {stats.topRules.map((rule, i) => (
              <div
                key={`${rule.ruleId}-${i}`}
                className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-muted-foreground w-24 truncate">
                    {rule.ruleId}
                  </span>
                  <span className="text-sm">{rule.ruleName}</span>
                  <SeverityBadge severity={rule.severity} />
                </div>
                <span className="font-mono text-sm">{rule.count}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
