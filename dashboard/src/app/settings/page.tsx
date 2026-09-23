"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Brain, MessageSquare, TicketCheck, ShieldCheck, Save, RotateCcw, Eye, EyeOff, Check, AlertCircle, Loader2, PlugZap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SECRET_SETTINGS, settingsChanges, settingsDraft, settingTypeError, type SettingsView } from "@/lib/settings-contract";
import { PROVIDER_PRESETS, PROVIDER_PROTOCOLS, providerProtocol, providerUrl } from "@/lib/provider-catalog";

type Section = "llm" | "slack" | "jira" | "security";
interface Field {
  key: string; label: string; hint?: string; kind?: "boolean" | "secret" | "number" | "select";
  options?: Array<[string, string]>; placeholder?: string;
  min?: number; max?: number; step?: number;
}
const SECTIONS = [
  { id: "llm", label: "AI review", description: "Providers, credentials, and review policy", icon: Brain },
  { id: "slack", label: "Slack", description: "Notification delivery", icon: MessageSquare },
  { id: "jira", label: "Jira", description: "Remediation issue tracking", icon: TicketCheck },
  { id: "security", label: "Security", description: "Server configuration readiness", icon: ShieldCheck },
] as const;
const FIELDS: Record<Exclude<Section, "security">, Field[]> = {
  llm: [
    { key: "llm.enabled", label: "Enable AI review", kind: "boolean", hint: "AI recommendations do not automatically confirm findings or change triage status." },
    { key: "llm.provider", label: "Provider protocol", kind: "select", options: PROVIDER_PROTOCOLS.map(([id, name]) => [id, name]), hint: "Native request and response adapters. Provider presets configure compatible services without inventing a new protocol." },
    { key: "llm.model", label: "Model ID", placeholder: "Exact model identifier from your provider", hint: "Use an identifier available to your account. Changing providers does not overwrite this field." },
    { key: "llm.anthropic_api_key", label: "Anthropic API key", kind: "secret" },
    { key: "llm.openai_api_key", label: "OpenAI API key", kind: "secret" },
    { key: "llm.google_api_key", label: "Google Gemini API key", kind: "secret" },
    { key: "llm.custom_endpoint", label: "Custom HTTPS endpoint", placeholder: "https://your-provider.example/api", hint: "Optional protocol-compatible endpoint. Private network addresses are blocked; direct-provider keys are never forwarded to custom endpoints." },
    { key: "llm.custom_headers", label: "Custom request headers", kind: "secret", placeholder: '{"Authorization":"Bearer …"}', hint: "JSON object with string values; at most 20 headers. Stored header values are never returned to the browser. Enter a complete replacement or leave blank to keep them." },
    { key: "llm.max_output_tokens", label: "Output token budget", kind: "number", min: 128, max: 32768, step: 128, hint: "Maximum generated tokens per review request. Model-specific limits still apply." },
    { key: "llm.timeout_seconds", label: "Request timeout (seconds)", kind: "number", min: 5, max: 300, step: 5, hint: "No automatic retry: a timeout may still incur provider usage." },
    { key: "llm.chat_token_parameter", label: "Chat token parameter", kind: "select", options: [["max_tokens", "max_tokens · compatible APIs"], ["max_completion_tokens", "max_completion_tokens · reasoning models"]], hint: "Used only by Chat Completions. Choose the parameter accepted by your model/provider." },
    { key: "llm.auto_verify", label: "Automatically request AI review", kind: "boolean", hint: "Uses the saved review policy. Model suggestions remain separate from scanner evidence." },
    { key: "llm.verify_threshold", label: "Review confidence threshold", kind: "number", min: 0, max: 1, step: 0.05, hint: "A value from 0 to 1. This is a review setting, not proof of runtime impact." },
    { key: "llm.language", label: "Finding analysis language", kind: "select", options: [["en", "English"], ["ko", "Korean"], ["ja", "Japanese"], ["zh", "Chinese"], ["es", "Spanish"], ["de", "German"], ["fr", "French"], ["pt", "Portuguese"]], hint: "Applies to finding-analysis prose. Agent interface labels and generated agent explanations use English." },
  ],
  slack: [
    { key: "slack.enabled", label: "Enable Slack notifications", kind: "boolean" },
    { key: "slack.webhook_url", label: "Incoming webhook", kind: "secret", placeholder: "https://hooks.slack.com/services/…", hint: "Only official Slack incoming webhook URLs are accepted." },
    { key: "slack.channel", label: "Channel label", placeholder: "#security-alerts", hint: "The webhook configuration ultimately controls where Slack delivers the message." },
    { key: "slack.notify_severity", label: "Minimum severity", kind: "select", options: [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]] },
  ],
  jira: [
    { key: "jira.enabled", label: "Enable Jira integration", kind: "boolean" },
    { key: "jira.base_url", label: "Jira site origin", placeholder: "https://your-team.atlassian.net", hint: "Use the site origin without an API path. Self-hosted domains require the server-side allowlist." },
    { key: "jira.email", label: "Account email", kind: "secret", placeholder: "security@example.com" },
    { key: "jira.api_token", label: "API token", kind: "secret" },
    { key: "jira.project_key", label: "Project key", placeholder: "SEC" },
    { key: "jira.issue_type", label: "Issue type", placeholder: "Bug" },
  ],
};
interface Security { encryptionConfigured: boolean; authenticationConfigured: boolean; production: boolean; accessPolicyConfigured: boolean; localAuthentication: boolean; emailConfigured: boolean; authOrigin: string | null }
interface Notice { ok: boolean; text: string }
export default function SettingsPage() {
  const [saved, setSaved] = useState<SettingsView>({});
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [removed, setRemoved] = useState<Set<string>>(new Set());
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [section, setSection] = useState<Section>("llm");
  const [security, setSecurity] = useState<Security | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [tests, setTests] = useState<Record<string, Notice & { time: string }>>({});
  const reload = useCallback(async () => {
    setLoading(true); setLoadError("");
    try {
      const response = await fetch("/api/settings", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok || !data.settings) throw new Error(data.error || "Unable to load settings.");
      setSaved(data.settings); setDraft(settingsDraft(data.settings)); setSecurity(data.security);
      setRemoved(new Set()); setNotice(null);
    } catch (error) { setLoadError(error instanceof Error ? error.message : "Unable to load settings."); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => {
    const frame = requestAnimationFrame(() => { void reload(); });
    return () => cancelAnimationFrame(frame);
  }, [reload]);
  const changes = useMemo(() => Object.assign({}, ...["llm", "slack", "jira"].map((key) => settingsChanges(draft, saved, removed, key))) as Record<string, string>, [draft, saved, removed]);
  const dirty = !loading && Object.keys(changes).length > 0;
  const sectionChanges = section === "security" ? {} : settingsChanges(draft, saved, removed, section);
  const pending = Object.keys(sectionChanges).length;
  useEffect(() => {
    if (!dirty) return;
    const unload = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    const navigate = (event: MouseEvent) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
      const link = (event.target as Element)?.closest("a[href]") as HTMLAnchorElement | null;
      if (link && link.target !== "_blank" && new URL(link.href).pathname !== window.location.pathname && !window.confirm("Discard unsaved settings and leave this page?")) { event.preventDefault(); event.stopPropagation(); }
    };
    window.addEventListener("beforeunload", unload); document.addEventListener("click", navigate, true);
    return () => { window.removeEventListener("beforeunload", unload); document.removeEventListener("click", navigate, true); };
  }, [dirty]);
  const edit = (key: string, value: string) => {
    setDraft((current) => ({ ...current, [key]: value }));
    setFieldErrors((errors) => { const next = { ...errors }; delete next[key]; return next; });
    setNotice(null);
  };
  const discard = () => {
    const baseline = settingsDraft(saved);
    setDraft((current) => ({ ...current, ...Object.fromEntries(Object.entries(baseline).filter(([key]) => key.startsWith(section + "."))) }));
    setRemoved((current) => new Set([...current].filter((key) => !key.startsWith(section + "."))));
    setNotice(null); setFieldErrors({});
  };
  const save = async () => {
    const errors = Object.fromEntries(Object.entries(sectionChanges).map(([key, value]) => [key, settingTypeError(key, value)]).filter(([, error]) => error)) as Record<string, string>;
    if (Object.keys(errors).length) { setFieldErrors(errors); setNotice({ ok: false, text: "Review the highlighted fields." }); return; }
    if (Object.keys(sectionChanges).some((key) => removed.has(key)) && !window.confirm("Remove the selected stored credentials? Integrations that use them may stop working.")) return;
    setBusy(true); setNotice(null);
    try {
      const response = await fetch("/api/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ settings: sectionChanges }) });
      const data = await response.json();
      if (!response.ok) { setFieldErrors(data.fields || {}); throw new Error(data.error || "Save failed."); }
      // Apply only this section so drafts in other sections cannot be lost on save.
      const nextSaved = { ...saved };
      for (const [key, value] of Object.entries(sectionChanges)) nextSaved[key] = SECRET_SETTINGS.has(key) ? { value: value ? "configured" : "", masked: value ? "••••••••" : "", encrypted: true } : { value };
      setSaved(nextSaved);
      setDraft((current) => ({ ...current, ...Object.fromEntries(Object.entries(settingsDraft(nextSaved)).filter(([key]) => key.startsWith(section + "."))) }));
      setRemoved((current) => new Set([...current].filter((key) => !key.startsWith(section + "."))));
      setRevealed(new Set()); setFieldErrors({});
      setTests((current) => { const next = { ...current }; delete next[section]; return next; });
      setNotice({ ok: true, text: "Settings saved. Connection status has not been verified." });
    } catch (error) { setNotice({ ok: false, text: error instanceof Error ? error.message : "Unable to save settings. Your draft is preserved." }); }
    finally { setBusy(false); }
  };
  const testConnection = async () => {
    const question = section === "slack" ? "Send a test notification to the saved Slack webhook?" : section === "llm" ? "Send a small test request using the saved AI configuration? Provider usage may be billed." : "Check account connectivity with the saved Jira configuration? No issue will be created.";
    if (!window.confirm(question)) return;
    setBusy(true); setNotice(null);
    try {
      const response = await fetch("/api/settings/test-" + (section === "llm" ? "llm" : section), { method: "POST" });
      const data = await response.json();
      const result = { ok: response.ok && data.success !== false, text: data.message || data.error || (response.ok ? "Connection test completed." : "Connection test failed."), time: new Date().toLocaleTimeString() };
      setTests((current) => ({ ...current, [section]: result }));
    } catch { setTests((current) => ({ ...current, [section]: { ok: false, text: "Connection request failed. No success has been recorded.", time: new Date().toLocaleTimeString() } })); }
    finally { setBusy(false); }
  };

  if (loading) return <p role="status" className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading settings…</p>;
  if (loadError) return <div role="alert" className="workbench-panel p-6">{loadError}<Button className="ml-4" variant="outline" onClick={reload}>Retry</Button></div>;
  let resolvedEndpoint = "";
  try { if (providerProtocol(draft["llm.provider"]) && draft["llm.model"]) resolvedEndpoint = providerUrl(draft["llm.provider"], draft["llm.custom_endpoint"], draft["llm.model"]); } catch { resolvedEndpoint = "Complete the model and endpoint fields to preview the request URL."; }
  const active = SECTIONS.find((item) => item.id === section)!;
  const fields = section === "security" ? [] : FIELDS[section];
  const secretCount = [...SECRET_SETTINGS].filter((key) => saved[key]?.value === "configured").length;
  return <div className="space-y-6 pb-10">
    <header className="flex flex-wrap items-end justify-between gap-4"><div><p className="eyebrow mb-2">Workspace configuration</p><h1 className="text-3xl font-semibold tracking-tight">Settings</h1><p className="mt-2 text-sm text-muted-foreground">Configure integrations with explicit saves and verifiable connection state.</p></div><span className="rounded-md border bg-card px-3 py-2 text-xs text-muted-foreground">{dirty ? Object.keys(changes).length + " unsaved changes" : "No unsaved changes"}</span></header>
    <div className="grid items-start gap-5 lg:grid-cols-[220px_minmax(0,1fr)_260px]">
      <nav className="workbench-panel p-2" aria-label="Settings sections">{SECTIONS.map((item) => {
        const count = item.id === "security" ? 0 : Object.keys(settingsChanges(draft, saved, removed, item.id)).length;
        return <button type="button" key={item.id} disabled={busy} onClick={() => { setSection(item.id); setNotice(null); setFieldErrors({}); }} aria-current={section === item.id ? "page" : undefined} className={"mb-1 flex w-full items-center gap-3 rounded-md px-3 py-3 text-left text-sm " + (section === item.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent")}><item.icon className="h-4 w-4 shrink-0" /><span className="flex-1">{item.label}</span>{count > 0 && <span className="font-mono text-xs">{count}</span>}</button>;
      })}</nav>
      <section className="workbench-panel">
        <div className="workbench-heading"><div><h2 className="text-base font-semibold">{active.label}</h2><p className="mt-1 text-xs text-muted-foreground">{active.description}</p></div></div>
        {notice && <p role={notice.ok ? "status" : "alert"} className={"border-b border-border px-5 py-3 text-sm " + (notice.ok ? "text-emerald-700 dark:text-emerald-400" : "text-destructive")}>{notice.text}</p>}
        {section === "security" ? <div className="space-y-5 p-5">
          {[["Encryption secret", security?.encryptionConfigured, "Required to save API keys, incoming webhooks, Jira credentials, or custom headers."], ["Authentication", security?.authenticationConfigured, "Requires an auth secret and a configured password or SSO method. This indicator does not test provider login."], ["Production mode", security?.production, "Production requires authentication, encryption, an access allowlist, and an HTTPS origin (loopback excepted)."]].map(([label, configured, hint]) => <div key={String(label)} className="border-b border-border pb-4"><div className="flex justify-between gap-3 text-sm"><span className="font-medium">{label}</span><span className="text-xs text-muted-foreground">{configured ? "Configured" : "Not configured / development"}</span></div><p className="mt-2 text-xs leading-6 text-muted-foreground">{hint}</p></div>)}
          <div className="space-y-3 rounded-md border p-4 text-xs"><p className="font-medium">Account &amp; identity</p><p className="text-muted-foreground">Access policy: {security?.accessPolicyConfigured ? "Configured" : "Not configured"} · Password sign-in: {security?.localAuthentication ? "Configured" : "Not configured"} · Email delivery: {security?.emailConfigured ? "Configured, not tested" : "Not configured"}</p><p className="break-all font-mono text-[11px] text-muted-foreground">Google callback: {security?.authOrigin || "AUTH_URL"}/api/auth/callback/google</p><p className="break-all font-mono text-[11px] text-muted-foreground">Okta callback: {security?.authOrigin || "AUTH_URL"}/api/auth/callback/okta</p><div className="flex flex-wrap gap-3 pt-2"><a href="/auth/signin" className="text-primary">Sign-in page</a><a href="/auth/forgot-password" className="text-primary">Reset password</a><button type="button" className="text-destructive" disabled={busy || !security?.authenticationConfigured} onClick={async () => { if (!window.confirm("Sign out every session for your account, including this browser? Unsaved changes will be lost.")) return; setBusy(true); try { const response = await fetch("/api/account/revoke-sessions", { method: "POST" }); if (!response.ok) throw new Error("Unable to revoke sessions."); window.location.assign("/auth/signin"); } catch { setNotice({ ok: false, text: "Unable to revoke sessions. No success has been recorded." }); setBusy(false); } }}>Sign out all sessions</button></div></div>
          <p className="text-xs leading-6 text-muted-foreground">Server secrets are managed through the deployment environment, not this page. No secret values are returned by the settings API. Existing plaintext custom headers are masked here; replacing them stores an encrypted value.</p>
        </div> : <fieldset disabled={busy} className="min-w-0">
          <div className="divide-y divide-border px-5">
            {section === "llm" && <div className="space-y-3 py-5"><label htmlFor="provider-preset" className="text-sm font-medium">Service preset</label><select id="provider-preset" className="workbench-select w-full" defaultValue="" onChange={(event) => { const preset = PROVIDER_PRESETS.find((item) => item.id === event.target.value); if (!preset) return; edit("llm.provider", preset.protocol); edit("llm.custom_endpoint", preset.endpoint); edit("llm.chat_token_parameter", preset.tokenParameter); setNotice({ ok: true, text: preset.hint + " Review and save these changes. Model and credential fields are preserved." }); }}><option value="">Choose a service preset…</option>{PROVIDER_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{preset.name}</option>)}</select><p className="text-xs leading-6 text-muted-foreground">Presets change only protocol, endpoint, and token parameter. When changing services, explicitly replace or remove stored custom headers.</p>{resolvedEndpoint && <div className="rounded-md border bg-muted/20 p-3"><p className="eyebrow">Request URL preview</p><p className="mt-2 break-all font-mono text-xs">{resolvedEndpoint}</p></div>}</div>}
            {fields.map((field) => {
            const secret = field.kind === "secret"; const stored = saved[field.key];
            const invalid = fieldErrors[field.key];
            return <div key={field.key} className="grid gap-3 py-5 xl:grid-cols-[180px_minmax(0,1fr)]">
              <div><label htmlFor={field.key} className="text-sm font-medium">{field.label}</label>{secret && <p className={"mt-1 text-[11px] " + (stored?.unreadable ? "text-destructive" : "text-muted-foreground")}>{stored?.unreadable ? "Stored value cannot be decrypted" : stored?.value === "configured" ? stored.encrypted ? "Stored · encrypted" : "Stored · legacy storage" : "Not configured"}</p>}</div>
              <div className="min-w-0 space-y-2">
                {field.kind === "boolean" ? <label className="inline-flex cursor-pointer items-center gap-3 text-sm"><input id={field.key} type="checkbox" checked={draft[field.key] === "true"} onChange={(e) => edit(field.key, e.target.checked ? "true" : "false")} className="h-4 w-4 accent-blue-600" /><span>{draft[field.key] === "true" ? "Enabled" : "Disabled"}</span></label> : field.kind === "select" ? <select id={field.key} className="workbench-select w-full" value={draft[field.key]} aria-invalid={Boolean(invalid)} onChange={(e) => edit(field.key, e.target.value)}>{!field.options?.some(([value]) => value === draft[field.key]) && <option value={draft[field.key]} disabled>{draft[field.key]} (unsupported)</option>}{field.options?.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select> : <div className="flex gap-2"><input id={field.key} autoComplete={secret ? "new-password" : "off"} spellCheck={false} type={secret && !revealed.has(field.key) ? "password" : field.kind === "number" ? "number" : "text"} min={field.min} max={field.max} step={field.step} value={draft[field.key] || ""} disabled={removed.has(field.key) || busy} placeholder={stored?.value === "configured" && secret ? "Leave blank to keep stored value" : field.placeholder} aria-invalid={Boolean(invalid)} aria-describedby={invalid ? field.key + "-error" : undefined} className="h-10 min-w-0 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50" onChange={(e) => edit(field.key, e.target.value)} />{secret && <button type="button" aria-label={revealed.has(field.key) ? "Hide " + field.label : "Show entered " + field.label} className="rounded-md border px-2.5 text-muted-foreground" onClick={() => setRevealed((current) => { const next = new Set(current); if (next.has(field.key)) next.delete(field.key); else next.add(field.key); return next; })}>{revealed.has(field.key) ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>}</div>}
                {invalid && <p id={field.key + "-error"} role="alert" className="text-xs text-destructive">{invalid}</p>}
                {field.hint && <p className="text-xs leading-5 text-muted-foreground">{field.hint}</p>}
                {secret && (stored?.value === "configured" || stored?.unreadable) && <label className="inline-flex items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={removed.has(field.key)} onChange={(e) => setRemoved((current) => { const next = new Set(current); if (e.target.checked) next.add(field.key); else next.delete(field.key); return next; })} />Remove stored value on save</label>}
              </div>
            </div>;
          })}</div>
          <div className="sticky bottom-0 flex flex-wrap items-center justify-between gap-3 border-t border-border bg-card px-5 py-4"><span className="text-xs text-muted-foreground">{pending ? pending + " changes in this section" : "This section is up to date"}</span><div className="flex gap-2"><Button variant="ghost" size="sm" onClick={discard} disabled={!pending || busy}><RotateCcw className="mr-1 h-3.5 w-3.5" />Discard</Button><Button size="sm" onClick={save} disabled={!pending || busy}>{busy ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" /> : <Save className="mr-1 h-3.5 w-3.5" />}Save changes</Button></div></div>
        </fieldset>}
      </section>
      <aside className="space-y-4">
        {section !== "security" && <section className="workbench-panel p-5"><h2 className="flex items-center gap-2 text-sm font-semibold"><PlugZap className="h-4 w-4 text-muted-foreground" />Connection check</h2><p className="mt-3 text-xs leading-6 text-muted-foreground">Checks use saved settings. Save or discard changes in this section before testing. External requests run only after confirmation.</p><Button variant="outline" className="mt-4 w-full" size="sm" disabled={busy || pending > 0} onClick={testConnection}>{busy ? "Working…" : section === "slack" ? "Send test notification" : "Test saved connection"}</Button>{tests[section] ? <div role="status" className={"mt-4 rounded border p-3 text-xs leading-5 " + (tests[section].ok ? "border-emerald-500/20" : "border-destructive/20")}><p className="flex items-center gap-2 font-medium">{tests[section].ok ? <Check className="h-3.5 w-3.5" /> : <AlertCircle className="h-3.5 w-3.5" />}{tests[section].ok ? "Test succeeded" : "Test failed"} · {tests[section].time}</p><p className="mt-2 break-words text-muted-foreground">{tests[section].text}</p></div> : <p className="mt-3 text-[11px] text-muted-foreground">Not tested in this session</p>}</section>}
        <section className="workbench-panel p-5"><p className="eyebrow">Credential storage</p><p className="mt-3 font-mono text-2xl">{secretCount}</p><p className="mt-2 text-xs text-muted-foreground">Configured secret fields · not a connection health score</p>{!security?.encryptionConfigured && <p className="mt-3 text-xs leading-5 text-amber-700 dark:text-amber-300">Encryption is not configured. Saving new credentials is blocked until the server has an encryption secret.</p>}</section>
      </aside>
    </div>
  </div>;
}
