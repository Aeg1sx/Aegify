"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Plus, Code } from "lucide-react";

const YAML_TEMPLATE = `id: CG-CUSTOM-001
name: Custom Rule Name
description: Describe what this rule detects
severity: medium
confidence: 0.7
languages:
  - python
cwe_id: null
owasp_category: null

# Pattern-based detection
patterns:
  - callee: "dangerous_function"
    args_match: "(user_input|request)"

# OR taint-based detection
# taint:
#   sources:
#     - type: function_parameter
#       pattern: "request"
#   sinks:
#     - type: sql_query
#       pattern: "execute"

message: "Security finding: {sink} called with untrusted input at line {sink_line}"
`;

export default function NewRulePage() {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    id: "",
    name: "",
    severity: "medium",
    cweId: "",
    owaspCategory: "",
    languages: "",
    description: "",
    yamlContent: "",
    enabled: true,
  });

  const update = (field: string, value: string | boolean) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const loadTemplate = () => {
    update("yamlContent", YAML_TEMPLATE);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!form.id.trim() || !form.name.trim()) {
      setError("ID and Name are required");
      return;
    }

    setSaving(true);
    try {
      const res = await fetch("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: form.id.trim(),
          name: form.name.trim(),
          severity: form.severity,
          cweId: form.cweId ? parseInt(form.cweId, 10) : null,
          owaspCategory: form.owaspCategory.trim() || null,
          languages: form.languages.trim(),
          description: form.description.trim(),
          yamlContent: form.yamlContent,
          enabled: form.enabled,
        }),
      });

      if (!res.ok) {
        const data = await res.json();
        setError(data.error || "Failed to create rule");
        setSaving(false);
        return;
      }

      const data = await res.json();
      router.push(`/rules/${encodeURIComponent(data.rule.id)}`);
    } catch {
      setError("Network error");
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <Link
        href="/rules"
        className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
      >
        <ArrowLeft className="h-4 w-4" /> Back to rules
      </Link>

      <div>
        <h1 className="text-2xl font-bold">Create Rule</h1>
        <p className="text-muted-foreground">Add a new security rule</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Rule Metadata</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Rule ID <span className="text-red-400">*</span>
                </label>
                <Input
                  placeholder="e.g. CG-CUSTOM-001"
                  value={form.id}
                  onChange={(e) => update("id", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">
                  Name <span className="text-red-400">*</span>
                </label>
                <Input
                  placeholder="e.g. Hardcoded API Key"
                  value={form.name}
                  onChange={(e) => update("name", e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <textarea
                placeholder="Describe what this rule detects and why it matters..."
                value={form.description}
                onChange={(e) => update("description", e.target.value)}
                className="w-full h-20 rounded-md border border-input bg-background px-3 py-2 text-sm resize-y focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Severity</label>
                <select
                  value={form.severity}
                  onChange={(e) => update("severity", e.target.value)}
                  className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">CWE ID</label>
                <Input
                  type="number"
                  placeholder="e.g. 79"
                  value={form.cweId}
                  onChange={(e) => update("cweId", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">OWASP</label>
                <Input
                  placeholder="e.g. A03:2021"
                  value={form.owaspCategory}
                  onChange={(e) => update("owaspCategory", e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Languages</label>
              <Input
                placeholder="e.g. python, javascript (leave empty for all)"
                value={form.languages}
                onChange={(e) => update("languages", e.target.value)}
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="enabled"
                checked={form.enabled}
                onChange={(e) => update("enabled", e.target.checked)}
                className="rounded border-input"
              />
              <label htmlFor="enabled" className="text-sm font-medium">
                Enabled
              </label>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg flex items-center gap-2">
                <Code className="h-5 w-5" />
                Rule Definition (YAML)
              </CardTitle>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={loadTemplate}
              >
                Load Template
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <textarea
              value={form.yamlContent}
              onChange={(e) => update("yamlContent", e.target.value)}
              placeholder="Paste or write your YAML rule definition here..."
              className="w-full h-96 bg-[#0d1117] text-[#c9d1d9] font-mono text-xs p-4 rounded-md border border-border resize-y focus:outline-none focus:ring-1 focus:ring-primary"
              spellCheck={false}
            />
            <p className="text-xs text-muted-foreground mt-2">
              Define detection patterns, taint sources/sinks, and message templates.
              Click &quot;Load Template&quot; for an example structure.
            </p>
          </CardContent>
        </Card>

        {error && (
          <div className="text-sm text-red-400 bg-red-400/10 rounded-md px-3 py-2">
            {error}
          </div>
        )}

        <div className="flex items-center gap-3">
          <Button type="submit" disabled={saving} className="flex items-center gap-2">
            <Plus className="h-4 w-4" />
            {saving ? "Creating..." : "Create Rule"}
          </Button>
          <Link href="/rules">
            <Button type="button" variant="outline">
              Cancel
            </Button>
          </Link>
        </div>
      </form>
    </div>
  );
}
