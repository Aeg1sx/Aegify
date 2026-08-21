"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanSearch, Clock, ChevronRight, RefreshCw } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

const REFRESH_OPTIONS = [
  { label: "Off", value: 0 },
  { label: "15s", value: 15_000 },
  { label: "30s", value: 30_000 },
  { label: "1m", value: 60_000 },
  { label: "5m", value: 300_000 },
  { label: "15m", value: 900_000 },
  { label: "30m", value: 1_800_000 },
] as const;

interface Scan {
  id: string;
  repository: string;
  branch: string;
  commitSha: string;
  status: string;
  filesScanned: number;
  duration: number;
  createdAt: string;
  findingsCount: number;
  severities: Record<string, number>;
  progressPhase?: number;
  progressPhaseName?: string;
  progressPercent?: number;
  progressMessage?: string;
  progressEta?: number | null;
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("scans_refresh_interval");
      return saved ? Number(saved) : 0;
    }
    return 0;
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchScans = useCallback(() => {
    fetch("/api/scans?limit=50")
      .then((r) => r.json())
      .then((data) => setScans(data.scans))
      .finally(() => setLoading(false));
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Configurable polling
  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (refreshInterval > 0) {
      intervalRef.current = setInterval(fetchScans, refreshInterval);
    }
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [refreshInterval, fetchScans]);

  const handleRefreshChange = (ms: number) => {
    setRefreshInterval(ms);
    localStorage.setItem("scans_refresh_interval", String(ms));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-muted-foreground">All scan history</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { fetchScans(); }}
            className="h-8 w-8 flex items-center justify-center rounded-md border border-input hover:bg-accent transition-colors"
            title="Refresh now"
          >
            <RefreshCw className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
          <div className="flex items-center rounded-md border border-input overflow-hidden text-xs">
            {REFRESH_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => handleRefreshChange(opt.value)}
                className={`px-2.5 py-1.5 transition-colors ${
                  refreshInterval === opt.value
                    ? "bg-primary text-primary-foreground"
                    : "hover:bg-accent text-muted-foreground"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {scans.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ScanSearch className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No scans yet</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Link key={scan.id} href={`/scans/${scan.id}`}>
              <Card className="hover:bg-accent/30 transition-colors cursor-pointer">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <ScanSearch className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium">
                          {scan.repository || "unnamed scan"}
                        </p>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDistanceToNow(new Date(scan.createdAt), {
                              addSuffix: true,
                            })}
                          </span>
                          {scan.branch && <span>{scan.branch}</span>}
                          {scan.commitSha && (
                            <span className="font-mono">
                              {scan.commitSha.slice(0, 7)}
                            </span>
                          )}
                          <span>{scan.filesScanned} files</span>
                          <span>{scan.duration.toFixed(1)}s</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {scan.status === "running" ? (
                        <div className="flex items-center gap-3">
                          <div className="flex flex-col items-end gap-1">
                            <span className="text-xs text-blue-500 font-medium animate-pulse">
                              {scan.progressMessage || "Scanning..."}
                            </span>
                            <div className="w-32 h-1.5 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-blue-500 rounded-full transition-all duration-500"
                                style={{ width: `${(scan.progressPercent || 0) * 100}%` }}
                              />
                            </div>
                            {scan.progressEta != null && scan.progressEta > 0 && (
                              <span className="text-[10px] text-muted-foreground">
                                ETA {Math.floor(scan.progressEta / 60)}m{Math.floor(scan.progressEta % 60)}s
                              </span>
                            )}
                          </div>
                        </div>
                      ) : (
                        <>
                          <div className="flex items-center gap-2">
                            {Object.entries(scan.severities)
                              .filter(([, c]) => c > 0)
                              .map(([sev, count]) => (
                                <div key={sev} className="flex items-center gap-1">
                                  <SeverityBadge severity={sev} />
                                  <span className="text-xs font-mono">{count}</span>
                                </div>
                              ))}
                          </div>
                          <span className="text-sm font-mono text-muted-foreground">
                            {scan.findingsCount} total
                          </span>
                        </>
                      )}
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
