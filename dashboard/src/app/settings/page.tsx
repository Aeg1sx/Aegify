"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Brain,
  Bot,
  Key,
  Save,
  MessageSquare,
  Shield,
  CheckCircle,
  AlertCircle,
  Globe,
  Plus,
  Trash2,
} from "lucide-react";

interface SettingsMap {
  [key: string]: { value: string; masked?: string };
}

interface HeaderEntry {
  key: string;
  value: string;
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<SettingsMap>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testingLLM, setTestingLLM] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  // LLM form
  const [llmProvider, setLlmProvider] = useState("anthropic");
  const [llmModel, setLlmModel] = useState("claude-opus-5");
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [llmAutoVerify, setLlmAutoVerify] = useState(false);
  const [llmThreshold, setLlmThreshold] = useState("0.7");
  const [anthropicKey, setAnthropicKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");
  const [googleKey, setGoogleKey] = useState("");
  const [llmLanguage, setLlmLanguage] = useState("en");
  const [customEndpoint, setCustomEndpoint] = useState("");
  const [customHeaders, setCustomHeaders] = useState<HeaderEntry[]>([]);

  // Slack form
  const [slackWebhook, setSlackWebhook] = useState("");
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [slackChannel, setSlackChannel] = useState("#security-alerts");
  const [slackSeverity, setSlackSeverity] = useState("high");

  useEffect(() => {
    fetch("/api/settings")
      .then((r) => r.json())
      .then((data) => {
        const s = data.settings || {};
        setSettings(s);
        setLlmProvider(s["llm.provider"]?.value || "anthropic");
        setLlmModel(s["llm.model"]?.value || "claude-opus-5");
        setLlmEnabled(s["llm.enabled"]?.value === "true");
        setLlmAutoVerify(s["llm.auto_verify"]?.value === "true");
        setLlmThreshold(s["llm.verify_threshold"]?.value || "0.7");
        setLlmLanguage(s["llm.language"]?.value || "en");
        setCustomEndpoint(s["llm.custom_endpoint"]?.value || "");
        // Parse custom headers from JSON
        const headersStr = s["llm.custom_headers"]?.value || "";
        if (headersStr) {
          try {
            const obj = JSON.parse(headersStr);
            setCustomHeaders(
              Object.entries(obj).map(([k, v]) => ({
                key: k,
                value: v as string,
              }))
            );
          } catch {
            setCustomHeaders([]);
          }
        }
        setSlackEnabled(s["slack.enabled"]?.value === "true");
        setSlackChannel(s["slack.channel"]?.value || "#security-alerts");
        setSlackSeverity(s["slack.notify_severity"]?.value || "high");
      })
      .finally(() => setLoading(false));
  }, []);

  const addHeader = () => {
    setCustomHeaders([...customHeaders, { key: "", value: "" }]);
  };

  const removeHeader = (index: number) => {
    setCustomHeaders(customHeaders.filter((_, i) => i !== index));
  };

  const updateHeader = (
    index: number,
    field: "key" | "value",
    val: string
  ) => {
    const updated = [...customHeaders];
    updated[index] = { ...updated[index], [field]: val };
    setCustomHeaders(updated);
  };

  const headersToJson = (): string => {
    const obj: Record<string, string> = {};
    for (const h of customHeaders) {
      if (h.key.trim()) {
        obj[h.key.trim()] = h.value;
      }
    }
    return Object.keys(obj).length > 0 ? JSON.stringify(obj) : "";
  };

  const saveLLM = async () => {
    setSaving(true);
    setSaveMsg(null);

    const updates: Record<string, string> = {
      "llm.provider": llmProvider,
      "llm.model": llmModel,
      "llm.enabled": llmEnabled ? "true" : "false",
      "llm.auto_verify": llmAutoVerify ? "true" : "false",
      "llm.verify_threshold": llmThreshold,
      "llm.language": llmLanguage,
      "llm.custom_endpoint": customEndpoint,
      "llm.custom_headers": headersToJson(),
    };

    if (anthropicKey) updates["llm.anthropic_api_key"] = anthropicKey;
    if (openaiKey) updates["llm.openai_api_key"] = openaiKey;
    if (googleKey) updates["llm.google_api_key"] = googleKey;

    const res = await fetch("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings: updates }),
    });

    if (res.ok) {
      setSaveMsg({ type: "success", text: "LLM settings saved" });
      setAnthropicKey("");
      setOpenaiKey("");
      setGoogleKey("");
      const data = await (await fetch("/api/settings")).json();
      setSettings(data.settings || {});
    } else {
      const err = await res.json();
      setSaveMsg({
        type: "error",
        text: err.error || "Failed to save LLM settings",
      });
    }
    setSaving(false);
  };

  const saveSlack = async () => {
    setSaving(true);
    setSaveMsg(null);

    const updates: Record<string, string> = {
      "slack.enabled": slackEnabled ? "true" : "false",
      "slack.channel": slackChannel,
      "slack.notify_severity": slackSeverity,
    };
    if (slackWebhook) updates["slack.webhook_url"] = slackWebhook;

    const res = await fetch("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ settings: updates }),
    });

    if (res.ok) {
      setSaveMsg({ type: "success", text: "Slack settings saved" });
      setSlackWebhook("");
      const data = await (await fetch("/api/settings")).json();
      setSettings(data.settings || {});
    } else {
      const err = await res.json();
      setSaveMsg({
        type: "error",
        text: err.error || "Failed to save Slack settings",
      });
    }
    setSaving(false);
  };

  const testSlack = async () => {
    setSaveMsg(null);
    const res = await fetch("/api/settings/test-slack", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      setSaveMsg({ type: "success", text: "Test message sent to Slack" });
    } else {
      setSaveMsg({
        type: "error",
        text: data.error || "Failed to send test",
      });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground">
          Configure integrations and API keys
        </p>
      </div>

      {saveMsg && (
        <div
          className={`flex items-center gap-2 text-sm px-3 py-2 rounded-md ${
            saveMsg.type === "success"
              ? "bg-[var(--status-fixed-bg)] text-[var(--status-fixed)]"
              : "bg-[var(--status-open-bg)] text-[var(--status-open)]"
          }`}
        >
          {saveMsg.type === "success" ? (
            <CheckCircle className="h-4 w-4" />
          ) : (
            <AlertCircle className="h-4 w-4" />
          )}
          {saveMsg.text}
        </div>
      )}

      {/* LLM Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Brain className="h-5 w-5" />
            LLM Verification
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Configure LLM to automatically verify findings, reduce false
            positives, and generate remediation suggestions.
          </p>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="llm-enabled"
              checked={llmEnabled}
              onChange={(e) => setLlmEnabled(e.target.checked)}
              className="rounded border-input"
            />
            <label htmlFor="llm-enabled" className="text-sm font-medium">
              Enable LLM Verification
            </label>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Provider</label>
              <select
                value={llmProvider}
                onChange={(e) => {
                  const p = e.target.value;
                  setLlmProvider(p);
                  if (p === "anthropic") setLlmModel("claude-opus-5");
                  else if (p === "openai") setLlmModel("gpt-5.2");
                  else if (p === "google") setLlmModel("gemini-2.5-flash");
                }}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="anthropic">Anthropic (Claude)</option>
                <option value="openai">OpenAI (GPT)</option>
                <option value="google">Google (Gemini)</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Model</label>
              <select
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                {llmProvider === "anthropic" ? (
                  <>
                    <optgroup label="Latest">
                      <option value="claude-opus-5">
                        Claude Opus 5
                      </option>
                      <option value="claude-sonnet-5">
                        Claude Sonnet 5
                      </option>
                      <option value="claude-opus-4-8">
                        Claude Opus 4.8
                      </option>
                    </optgroup>
                    <optgroup label="Previous">
                      <option value="claude-opus-4-6">
                        Claude Opus 4.6
                      </option>
                      <option value="claude-sonnet-4-5-20250929">
                        Claude Sonnet 4.5
                      </option>
                      <option value="claude-haiku-4-5-20251001">
                        Claude Haiku 4.5
                      </option>
                    </optgroup>
                    <optgroup label="Legacy">
                      <option value="claude-opus-4-5">
                        Claude Opus 4.5
                      </option>
                      <option value="claude-sonnet-4-0">
                        Claude Sonnet 4
                      </option>
                      <option value="claude-opus-4-0">Claude Opus 4</option>
                      <option value="claude-3-7-sonnet-latest">
                        Claude Sonnet 3.7
                      </option>
                    </optgroup>
                  </>
                ) : llmProvider === "openai" ? (
                  <>
                    <optgroup label="GPT Series">
                      <option value="gpt-5.2">GPT-5.2 Thinking</option>
                      <option value="gpt-5.2-pro">GPT-5.2 Pro</option>
                      <option value="gpt-5">GPT-5</option>
                      <option value="gpt-4.1">GPT-4.1</option>
                      <option value="gpt-4o">GPT-4o</option>
                      <option value="gpt-4o-mini">GPT-4o mini</option>
                    </optgroup>
                    <optgroup label="Reasoning (o-series)">
                      <option value="o3">o3</option>
                      <option value="o3-pro">o3 Pro</option>
                      <option value="o4-mini">o4-mini</option>
                      <option value="o3-mini">o3-mini</option>
                    </optgroup>
                  </>
                ) : (
                  <>
                    <optgroup label="Latest">
                      <option value="gemini-2.5-flash">
                        Gemini 2.5 Flash
                      </option>
                      <option value="gemini-2.5-pro">
                        Gemini 2.5 Pro
                      </option>
                    </optgroup>
                    <optgroup label="Preview">
                      <option value="gemini-3-pro">Gemini 3 Pro</option>
                      <option value="gemini-3-flash">
                        Gemini 3 Flash
                      </option>
                    </optgroup>
                    <optgroup label="Legacy (retiring Mar 2026)">
                      <option value="gemini-2.0-flash">
                        Gemini 2.0 Flash
                      </option>
                      <option value="gemini-2.0-flash-lite">
                        Gemini 2.0 Flash Lite
                      </option>
                    </optgroup>
                  </>
                )}
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Analysis Language</label>
              <select
                value={llmLanguage}
                onChange={(e) => setLlmLanguage(e.target.value)}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="en">English</option>
                <option value="ko">한국어</option>
                <option value="ja">日本語</option>
                <option value="zh">中文</option>
              </select>
            </div>
          </div>

          {/* API Keys */}
          <div className="space-y-4 border-t border-border pt-4">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Key className="h-4 w-4" />
              API Keys
              <span className="text-xs text-muted-foreground font-normal">
                (encrypted with AES-256-GCM)
              </span>
            </h3>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Anthropic API Key
              </label>
              <div className="flex items-center gap-2">
                <Input
                  type="password"
                  placeholder={
                    settings["llm.anthropic_api_key"]?.value === "configured"
                      ? `Configured (${settings["llm.anthropic_api_key"]?.masked})`
                      : "sk-ant-..."
                  }
                  value={anthropicKey}
                  onChange={(e) => setAnthropicKey(e.target.value)}
                />
                {settings["llm.anthropic_api_key"]?.value ===
                  "configured" && (
                  <Shield className="h-4 w-4 text-[var(--status-fixed)] shrink-0" />
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                OpenAI API Key
              </label>
              <div className="flex items-center gap-2">
                <Input
                  type="password"
                  placeholder={
                    settings["llm.openai_api_key"]?.value === "configured"
                      ? `Configured (${settings["llm.openai_api_key"]?.masked})`
                      : "sk-..."
                  }
                  value={openaiKey}
                  onChange={(e) => setOpenaiKey(e.target.value)}
                />
                {settings["llm.openai_api_key"]?.value === "configured" && (
                  <Shield className="h-4 w-4 text-[var(--status-fixed)] shrink-0" />
                )}
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Google AI API Key
              </label>
              <div className="flex items-center gap-2">
                <Input
                  type="password"
                  placeholder={
                    settings["llm.google_api_key"]?.value === "configured"
                      ? `Configured (${settings["llm.google_api_key"]?.masked})`
                      : "AIza..."
                  }
                  value={googleKey}
                  onChange={(e) => setGoogleKey(e.target.value)}
                />
                {settings["llm.google_api_key"]?.value === "configured" && (
                  <Shield className="h-4 w-4 text-[var(--status-fixed)] shrink-0" />
                )}
              </div>
            </div>
          </div>

          {/* Custom Endpoint */}
          <div className="space-y-4 border-t border-border pt-4">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Custom Endpoint
              <span className="text-xs text-muted-foreground font-normal">
                (AI Gateway / Proxy)
              </span>
            </h3>
            <p className="text-xs text-muted-foreground">
              Route LLM requests through an AI gateway (e.g. Portkey, LiteLLM,
              Cloudflare AI Gateway). Leave empty to use provider defaults.
              HTTPS only.
            </p>

            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Endpoint URL
              </label>
              <Input
                type="url"
                placeholder="https://gateway.example.com/v1"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
              />
              {customEndpoint && !customEndpoint.startsWith("https://") && (
                <p className="text-xs text-destructive">
                  Only HTTPS URLs are allowed
                </p>
              )}
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm text-muted-foreground">
                  Custom Headers
                </label>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={addHeader}
                  className="flex items-center gap-1 h-7 text-xs"
                >
                  <Plus className="h-3 w-3" />
                  Add Header
                </Button>
              </div>
              {customHeaders.length === 0 && (
                <p className="text-xs text-muted-foreground italic">
                  No custom headers configured
                </p>
              )}
              <div className="space-y-2">
                {customHeaders.map((header, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Input
                      placeholder="X-Gateway-Key"
                      value={header.key}
                      onChange={(e) => updateHeader(i, "key", e.target.value)}
                      className="flex-1"
                    />
                    <Input
                      placeholder="value"
                      value={header.value}
                      onChange={(e) => updateHeader(i, "value", e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => removeHeader(i)}
                      className="h-9 w-9 p-0 text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Auto-verify & Threshold */}
          <div className="grid grid-cols-2 gap-4 border-t border-border pt-4">
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="llm-auto"
                checked={llmAutoVerify}
                onChange={(e) => setLlmAutoVerify(e.target.checked)}
                className="rounded border-input"
              />
              <label htmlFor="llm-auto" className="text-sm">
                Auto-verify on upload
              </label>
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">
                Confidence threshold (below = send to LLM)
              </label>
              <Input
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={llmThreshold}
                onChange={(e) => setLlmThreshold(e.target.value)}
              />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button
              onClick={saveLLM}
              disabled={saving}
              className="flex items-center gap-2"
            >
              <Save className="h-4 w-4" />
              {saving ? "Saving..." : "Save LLM Settings"}
            </Button>
            <Button
              variant="outline"
              onClick={async () => {
                setTestingLLM(true);
                setSaveMsg(null);
                try {
                  const res = await fetch("/api/settings/test-llm", { method: "POST" });
                  const data = await res.json();
                  setSaveMsg({
                    type: res.ok ? "success" : "error",
                    text: data.message,
                  });
                } catch {
                  setSaveMsg({ type: "error", text: "Connection test failed" });
                } finally {
                  setTestingLLM(false);
                }
              }}
              disabled={testingLLM}
            >
              {testingLLM ? "Testing..." : "Test Connection"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* LLM Scanning */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-5 w-5" />
            LLM Scanning
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            The LLM Scan feature uses your configured LLM provider to perform
            AI-powered security analysis on source code files. It supports two
            modes:
          </p>
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 rounded-md border border-border">
              <p className="text-sm font-medium mb-1">Quick Scan</p>
              <p className="text-xs text-muted-foreground">
                Analyzes individual files for common security vulnerabilities.
                Fast and suitable for spot-checking specific files.
              </p>
            </div>
            <div className="p-3 rounded-md border border-border">
              <p className="text-sm font-medium mb-1">Deep Scan</p>
              <p className="text-xs text-muted-foreground">
                Uses call graph context from a previous SAST scan to perform
                cross-function analysis. Detects data flow and business logic
                vulnerabilities.
              </p>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            LLM scanning uses the same provider and API key configured above.
            Findings are stored with source &quot;llm&quot; and can be filtered
            in the Findings page.
          </p>
        </CardContent>
      </Card>

      {/* Slack Settings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageSquare className="h-5 w-5" />
            Slack Notifications
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Receive notifications about new vulnerabilities via Slack webhook.
          </p>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="slack-enabled"
              checked={slackEnabled}
              onChange={(e) => setSlackEnabled(e.target.checked)}
              className="rounded border-input"
            />
            <label htmlFor="slack-enabled" className="text-sm font-medium">
              Enable Slack Notifications
            </label>
          </div>

          <div className="space-y-2">
            <label className="text-sm text-muted-foreground">Webhook URL</label>
            <Input
              type="password"
              placeholder={
                settings["slack.webhook_url"]?.value === "configured"
                  ? `Configured (${settings["slack.webhook_url"]?.masked})`
                  : "https://hooks.slack.com/services/..."
              }
              value={slackWebhook}
              onChange={(e) => setSlackWebhook(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">Channel</label>
              <Input
                placeholder="#security-alerts"
                value={slackChannel}
                onChange={(e) => setSlackChannel(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Minimum Severity
              </label>
              <select
                value={slackSeverity}
                onChange={(e) => setSlackSeverity(e.target.value)}
                className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="critical">Critical only</option>
                <option value="high">High and above</option>
                <option value="medium">Medium and above</option>
                <option value="low">All</option>
              </select>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Button
              onClick={saveSlack}
              disabled={saving}
              className="flex items-center gap-2"
            >
              <Save className="h-4 w-4" />
              {saving ? "Saving..." : "Save Slack Settings"}
            </Button>
            <Button variant="outline" onClick={testSlack}>
              Test Webhook
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
