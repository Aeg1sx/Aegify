"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import { Search, BookOpen, Plus, RefreshCw, Loader2 } from "lucide-react";

interface Rule {
  id: string;
  name: string;
  severity: string;
  cweId: number | null;
  owaspCategory: string | null;
  languages: string;
  enabled: boolean;
  findingCount: number;
}

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState("");

  const loadRules = () => {
    fetch("/api/rules")
      .then((r) => r.json())
      .then((data) => setRules(data.rules || []))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadRules();
  }, []);

  const syncRules = async () => {
    setSyncing(true);
    setSyncMsg("");
    try {
      const res = await fetch("/api/rules/sync", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ direction: "yaml-to-db" }),
      });
      const data = await res.json();
      setSyncMsg(`Synced ${data.synced} rules${data.errors?.length ? ` (${data.errors.length} errors)` : ""}`);
      loadRules();
    } catch {
      setSyncMsg("Sync failed");
    } finally {
      setSyncing(false);
    }
  };

  const filtered = rules.filter((r) => {
    if (filterSeverity && r.severity !== filterSeverity) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        r.id.toLowerCase().includes(q) ||
        r.name.toLowerCase().includes(q) ||
        (r.owaspCategory || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Rules</h1>
          <p className="text-muted-foreground">
            {rules.length} security rules loaded
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={syncRules}
            disabled={syncing}
            className="flex items-center gap-2"
          >
            {syncing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Sync Rules
          </Button>
          <Link href="/rules/new">
            <Button className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Create Rule
            </Button>
          </Link>
        </div>
      </div>

      {syncMsg && (
        <div className="text-sm text-muted-foreground bg-muted/50 rounded-md px-3 py-2">
          {syncMsg}
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
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

      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            {filtered.length} rules
          </CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-pulse text-muted-foreground">Loading...</div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              No rules found
            </div>
          ) : (
            <div className="max-h-[68vh] overflow-auto">
              <table className="data-table compact"><caption className="sr-only">Vulnerability detection rules</caption><thead><tr><th>Rule / identity</th><th>Severity</th><th>Languages</th><th>CWE</th><th>State</th><th>Findings</th></tr></thead><tbody>
                {filtered.map((rule) => <tr key={rule.id}><td><Link href={`/rules/${encodeURIComponent(rule.id)}`} className="font-medium hover:text-primary">{rule.name}</Link><p className="mt-1 font-mono text-[11px] text-muted-foreground">{rule.id}</p></td><td><SeverityBadge severity={rule.severity} /></td><td className="max-w-44 text-xs text-muted-foreground">{rule.languages || "Not specified"}</td><td className="whitespace-nowrap font-mono text-xs text-muted-foreground">{rule.cweId ? `CWE-${rule.cweId}` : "—"}</td><td className="text-xs text-muted-foreground">{rule.enabled ? "Enabled" : "Disabled"}</td><td><Link className="font-mono text-xs text-primary" href={`/findings?ruleId=${encodeURIComponent(rule.id)}`}>{rule.findingCount}</Link></td></tr>)}
              </tbody></table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
