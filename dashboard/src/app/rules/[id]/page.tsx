"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ArrowLeft,
  BookOpen,
  ExternalLink,
  FileCode,
  Shield,
  ToggleLeft,
  ToggleRight,
  Code,
  Save,
  Pencil,
  X,
  FileDown,
} from "lucide-react";
import { YamlHighlight } from "@/components/code-highlight";

interface RuleDetail {
  id: string;
  name: string;
  severity: string;
  cweId: number | null;
  owaspCategory: string | null;
  languages: string;
  enabled: boolean;
  findingCount: number;
  yamlContent: string;
  description: string;
  sourceFile: string;
}

interface RuleStats {
  totalFindings: number;
  severityBreakdown: Record<string, number>;
  statusBreakdown: Record<string, number>;
  avgConfidence: number;
  topFiles: Array<{ path: string; count: number }>;
}

export default function RuleDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [rule, setRule] = useState<RuleDetail | null>(null);
  const [stats, setStats] = useState<RuleStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [editingYaml, setEditingYaml] = useState(false);
  const [yamlDraft, setYamlDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    fetch(`/api/rules/${encodeURIComponent(id)}`)
      .then((r) => r.json())
      .then((data) => {
        setRule(data.rule);
        setStats(data.stats);
      })
      .finally(() => setLoading(false));
  }, [id]);

  const toggleEnabled = async () => {
    if (!rule) return;
    setToggling(true);
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !rule.enabled }),
    });
    if (res.ok) {
      const data = await res.json();
      setRule(data.rule);
    }
    setToggling(false);
  };

  const startEditYaml = () => {
    setYamlDraft(rule?.yamlContent || "");
    setEditingYaml(true);
    setSaveMsg("");
  };

  const saveYaml = async () => {
    if (!rule) return;
    setSaving(true);
    setSaveMsg("");
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ yamlContent: yamlDraft }),
    });
    if (res.ok) {
      const data = await res.json();
      setRule(data.rule);
      setEditingYaml(false);
      setSaveMsg("Saved");
    } else {
      setSaveMsg("Save failed");
    }
    setSaving(false);
  };

  const saveToYamlFile = async () => {
    if (!rule) return;
    setSaving(true);
    setSaveMsg("");
    const res = await fetch("/api/rules/sync", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ direction: "db-to-yaml", ruleId: rule.id }),
    });
    if (res.ok) {
      setSaveMsg("Saved to YAML file");
    } else {
      const data = await res.json();
      setSaveMsg(data.error || "Failed to save to YAML");
    }
    setSaving(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!rule) {
    return (
      <div className="space-y-4">
        <Link href="/rules" className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1">
          <ArrowLeft className="h-4 w-4" /> Back to rules
        </Link>
        <p className="text-muted-foreground">Rule not found</p>
      </div>
    );
  }

  const languages = rule.languages ? rule.languages.split(",").map((l) => l.trim()).filter(Boolean) : [];

  return (
    <div className="space-y-6">
      <Link href="/rules" className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1">
        <ArrowLeft className="h-4 w-4" /> Back to rules
      </Link>

      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Shield className="h-6 w-6" />
            <h1 className="text-2xl font-bold">{rule.name}</h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm text-muted-foreground">{rule.id}</span>
            <SeverityBadge severity={rule.severity} />
            {rule.cweId && (
              <a
                href={`https://cwe.mitre.org/data/definitions/${rule.cweId}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
              >
                CWE-{rule.cweId} <ExternalLink className="h-3 w-3" />
              </a>
            )}
            {rule.owaspCategory && (
              <span className="text-xs text-muted-foreground">{rule.owaspCategory}</span>
            )}
          </div>
          {rule.description && (
            <p className="text-sm text-muted-foreground mt-2 max-w-2xl">
              {rule.description}
            </p>
          )}
        </div>
        <Button
          variant={rule.enabled ? "outline" : "secondary"}
          onClick={toggleEnabled}
          disabled={toggling}
          className="flex items-center gap-2"
        >
          {rule.enabled ? (
            <ToggleRight className="h-4 w-4 text-green-400" />
          ) : (
            <ToggleLeft className="h-4 w-4 text-muted-foreground" />
          )}
          {rule.enabled ? "Enabled" : "Disabled"}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{stats?.totalFindings || 0}</div>
            <div className="text-xs text-muted-foreground">Total Findings</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">
              {stats?.avgConfidence ? `${(stats.avgConfidence * 100).toFixed(0)}%` : "-"}
            </div>
            <div className="text-xs text-muted-foreground">Avg Confidence</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{languages.length || "-"}</div>
            <div className="text-xs text-muted-foreground">Languages</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-2xl font-bold">{stats?.topFiles.length || 0}</div>
            <div className="text-xs text-muted-foreground">Affected Files</div>
          </CardContent>
        </Card>
      </div>

      {/* YAML Rule Definition */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <Code className="h-4 w-4" />
              Rule Definition (YAML)
            </CardTitle>
            {!editingYaml ? (
              <div className="flex items-center gap-2">
                {saveMsg && (
                  <span className="text-xs text-muted-foreground">{saveMsg}</span>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={saveToYamlFile}
                  disabled={saving}
                  className="flex items-center gap-1"
                >
                  <FileDown className="h-3 w-3" />
                  Save to YAML
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={startEditYaml}
                  className="flex items-center gap-1"
                >
                  <Pencil className="h-3 w-3" />
                  Edit
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                {saveMsg && (
                  <span className="text-xs text-muted-foreground">{saveMsg}</span>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setEditingYaml(false)}
                >
                  <X className="h-3 w-3" />
                </Button>
                <Button
                  size="sm"
                  onClick={saveYaml}
                  disabled={saving}
                  className="flex items-center gap-1"
                >
                  <Save className="h-3 w-3" />
                  {saving ? "Saving..." : "Save"}
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {editingYaml ? (
            <textarea
              value={yamlDraft}
              onChange={(e) => setYamlDraft(e.target.value)}
              className="w-full h-80 bg-[#0d1117] text-[#c9d1d9] font-mono text-xs p-4 rounded-md border border-border resize-y focus:outline-none focus:ring-1 focus:ring-primary"
              spellCheck={false}
            />
          ) : rule.yamlContent ? (
            <YamlHighlight code={rule.yamlContent} />
          ) : (
            <div className="bg-muted rounded-md p-4 text-sm text-muted-foreground italic">
              No rule definition available.
              <Button
                variant="link"
                size="sm"
                onClick={startEditYaml}
                className="ml-2 text-xs"
              >
                Add YAML definition
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Rule Configuration */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <BookOpen className="h-4 w-4" />
              Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-sm">
              <span className="text-muted-foreground">ID</span>
              <span className="font-mono">{rule.id}</span>
              <span className="text-muted-foreground">Severity</span>
              <SeverityBadge severity={rule.severity} />
              <span className="text-muted-foreground">CWE</span>
              <span>{rule.cweId ? `CWE-${rule.cweId}` : "-"}</span>
              <span className="text-muted-foreground">OWASP</span>
              <span>{rule.owaspCategory || "-"}</span>
              <span className="text-muted-foreground">Languages</span>
              <span>{languages.length > 0 ? languages.join(", ") : "All"}</span>
              <span className="text-muted-foreground">Enabled</span>
              <span>{rule.enabled ? "Yes" : "No"}</span>
              <span className="text-muted-foreground">Source</span>
              <span className="font-mono text-xs truncate">{rule.sourceFile || "Manual"}</span>
            </div>
          </CardContent>
        </Card>

        {/* Finding Status Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Finding Status</CardTitle>
          </CardHeader>
          <CardContent>
            {stats && Object.keys(stats.statusBreakdown).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(stats.statusBreakdown).map(([status, count]) => (
                  <div key={status} className="flex items-center justify-between text-sm">
                    <span className="capitalize">{status.replace("_", " ")}</span>
                    <span className="font-mono">{count}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No findings yet</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Affected Files */}
      {stats && stats.topFiles.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <FileCode className="h-4 w-4" />
              Top Affected Files
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {stats.topFiles.map((file) => (
                <div
                  key={file.path}
                  className="flex items-center justify-between py-1.5 text-sm"
                >
                  <span className="font-mono text-xs truncate flex-1 mr-4">
                    {file.path}
                  </span>
                  <span className="text-muted-foreground font-mono">
                    {file.count}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* View Findings Link */}
      <div className="flex justify-center">
        <Link href={`/findings?ruleId=${encodeURIComponent(rule.id)}`}>
          <Button variant="outline">
            View all findings for this rule
          </Button>
        </Link>
      </div>
    </div>
  );
}
