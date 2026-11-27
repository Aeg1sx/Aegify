"use client";
import { Fragment, useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { Eye, EyeOff, Check, AlertCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SECRET_SETTINGS, settingsChanges, settingsDraft, settingTypeError, type SettingsView } from "@/lib/settings-contract";
import { PROVIDER_PRESETS, PROVIDER_PROTOCOLS, providerProtocol, providerUrl } from "@/lib/provider-catalog";

type Section = "llm" | "slack" | "jira" | "security";
interface Field {
  key: string; label: string; hint?: string; kind?: "boolean" | "secret" | "number" | "select";
  options?: Array<[string, string]>; placeholder?: string;
  min?: number; max?: number; step?: number; heading?: string;
}
const SECTIONS = [
  { id: "llm", label: "AI review", heading: "Model provider" },
  { id: "slack", label: "Slack", heading: "Slack notifications" },
  { id: "jira", label: "Jira", heading: "Jira issues" },
  { id: "security", label: "Security", heading: "Server security" },
] as const;
const FIELDS: Record<Exclude<Section, "security">, Field[]> = {
  llm: [
    { key: "llm.provider", label: "Provider protocol", kind: "select", options: PROVIDER_PROTOCOLS.map(([id, name]) => [id, name]) },
    { key: "llm.model", label: "Model ID", placeholder: "Model identifier for your account" },
    { key: "llm.custom_endpoint", label: "Custom HTTPS endpoint", placeholder: "https://your-provider.example/api", hint: "Optional public endpoint. Supply its credentials in Custom request headers." },
    { key: "llm.anthropic_api_key", label: "Anthropic API key", kind: "secret", heading: "Credentials" },
    { key: "llm.openai_api_key", label: "OpenAI API key", kind: "secret" },
    { key: "llm.google_api_key", label: "Google Gemini API key", kind: "secret" },
    { key: "llm.custom_headers", label: "Custom request headers", kind: "secret", placeholder: '{"Authorization":"Bearer …"}', hint: "Enter a JSON object with up to 20 string values. Leave blank to keep stored headers." },
    { key: "llm.max_output_tokens", label: "Output token budget", kind: "number", min: 128, max: 32768, step: 128, heading: "Request limits", hint: "Maximum tokens the model can generate per request." },
    { key: "llm.timeout_seconds", label: "Request timeout (seconds)", kind: "number", min: 5, max: 300, step: 5, hint: "A timed-out request may still incur provider charges." },
    { key: "llm.chat_token_parameter", label: "Chat token parameter", kind: "select", options: [["max_tokens", "max_tokens · compatible APIs"], ["max_completion_tokens", "max_completion_tokens · reasoning models"]], hint: "Choose the parameter your Chat Completions model accepts." },
    { key: "llm.enabled", label: "Enable AI review", kind: "boolean", heading: "Review policy", hint: "Reviewers decide how to triage each finding." },
    { key: "llm.auto_verify", label: "Automatically request AI review", kind: "boolean" },
    { key: "llm.verify_threshold", label: "Review confidence threshold", kind: "number", min: 0, max: 1, step: 0.05, hint: "Enter a value from 0 to 1." },
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
      setNotice({ ok: true, text: "Settings saved." });
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
  const persisted = settingsDraft(saved);
  const savedValue = (key: string) => persisted[key] || "Not set";
  const savedProtocol = PROVIDER_PROTOCOLS.find(([id]) => id === persisted["llm.provider"])?.[1] || savedValue("llm.provider");
  const connection = section === "llm" ? [["Protocol", savedProtocol], ["Model", savedValue("llm.model")]]
    : section === "slack" ? [["Channel", savedValue("slack.channel")], ["Minimum severity", savedValue("slack.notify_severity")]]
    : [["Site", savedValue("jira.base_url")], ["Project", savedValue("jira.project_key")]];
  const selectSection = (next: Section) => {
    setSection(next); setNotice(null); setFieldErrors({}); setRevealed(new Set());
  };
  function navigateSections(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = { ArrowRight: (index + 1) % SECTIONS.length, ArrowLeft: (index + SECTIONS.length - 1) % SECTIONS.length, Home: 0, End: SECTIONS.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    selectSection(SECTIONS[next].id);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }
  return <div className="workspace-settings">
    <header className="settings-heading"><h1 className="workbench-title">Workspace settings</h1>
      {dirty && <span role="status">{Object.keys(changes).length} unsaved {Object.keys(changes).length === 1 ? "change" : "changes"}</span>}
    </header>
    <div className="settings-sections" role="tablist" aria-label="Settings sections">{SECTIONS.map((item, index) => {
        const count = item.id === "security" ? 0 : Object.keys(settingsChanges(draft, saved, removed, item.id)).length;
        return <button type="button" key={item.id} id={"section-" + item.id} role="tab" aria-controls="settings-panel" aria-selected={section === item.id}
          tabIndex={section === item.id ? 0 : -1} disabled={busy} onKeyDown={(event) => navigateSections(event, index)} onClick={() => selectSection(item.id)}>
          {item.label}{count > 0 && <span aria-label={count + " unsaved changes"}> · {count}</span>}
        </button>;
      })}</div>
    <div id="settings-panel" role="tabpanel" tabIndex={0} aria-labelledby={"section-" + section} className="settings-layout">
      <section className="min-w-0" aria-labelledby="settings-form-heading">
        <div className="settings-form-title"><h2 className="settings-subheading" id="settings-form-heading">{active.heading}</h2>
          <a href="#saved-heading" className="settings-jump">{section === "security" ? "Credential storage" : "Saved connection"} <span aria-hidden>↓</span></a>
        </div>
        {notice && <p role={notice.ok ? "status" : "alert"} className={"border-b border-border px-5 py-3 text-sm " + (notice.ok ? "text-emerald-700 dark:text-emerald-400" : "text-destructive")}>{notice.text}</p>}
        {section === "security" ? <div className="settings-security space-y-5 py-4">
          <dl className="settings-readiness">{[
            ["Encryption key", security?.encryptionConfigured, "Configured", "Missing"],
            ["Authentication", security?.authenticationConfigured, "Configured", "Missing"],
            ["Server mode", security?.production, "Production", "Development"],
            ["Access policy", security?.accessPolicyConfigured, "Configured", "Missing"],
            ["Password sign-in", security?.localAuthentication, "Configured", "Off"],
            ["Email delivery", security?.emailConfigured, "Configured", "Off"],
          ].map(([label, value, on, off]) => <div key={String(label)}><dt>{label}</dt><dd>{value === undefined ? "Unavailable" : value ? on : off}</dd></div>)}</dl>
          <h3 className="settings-group">Sign-in callbacks</h3>
          <dl className="settings-readiness">{["Google", "Okta"].map((name) => <div key={name}><dt>{name}</dt>
            <dd><code>{security?.authOrigin || "AUTH_URL"}/api/auth/callback/{name.toLowerCase()}</code></dd></div>)}</dl>
          <div className="flex flex-wrap items-center gap-x-4 text-sm"><a href="/auth/signin" className="text-primary underline underline-offset-4">Sign-in page</a>
            <a href="/auth/forgot-password" className="text-primary underline underline-offset-4">Reset password</a>
            <button type="button" className="text-destructive" disabled={busy || !security?.authenticationConfigured} onClick={async () => {
              if (!window.confirm("Sign out every session for your account, including this browser? Unsaved changes will be lost.")) return;
              setBusy(true);
              try {
                const response = await fetch("/api/account/revoke-sessions", { method: "POST" });
                if (!response.ok) throw new Error();
                window.location.assign("/auth/signin");
              } catch { setNotice({ ok: false, text: "Unable to revoke sessions." }); setBusy(false); }
            }}>Sign out all sessions</button></div>
          <p className="text-xs leading-5 text-muted-foreground">Manage server secrets in the deployment environment.</p>
        </div> : <fieldset disabled={busy} className="min-w-0" aria-labelledby="settings-form-heading">
          <div>
            {section === "llm" && <div className="settings-field"><label htmlFor="provider-preset">Service preset</label>
              <div><select id="provider-preset" className="workbench-select w-full" value="" aria-describedby="preset-hint" onChange={(event) => {
                const preset = PROVIDER_PRESETS.find((item) => item.id === event.target.value);
                if (!preset) return;
                edit("llm.provider", preset.protocol); edit("llm.custom_endpoint", preset.endpoint); edit("llm.chat_token_parameter", preset.tokenParameter);
                setNotice({ ok: true, text: preset.hint + " Save to apply the preset." });
              }}><option value="">Apply a preset…</option>{PROVIDER_PRESETS.map((preset) => <option key={preset.id} value={preset.id}>{preset.name}</option>)}</select>
              <p id="preset-hint" className="settings-hint">Sets the protocol, endpoint and token parameter. When switching services, replace or remove any saved custom headers.</p></div>
            </div>}
            {fields.map((field) => {
            const secret = field.kind === "secret"; const stored = saved[field.key];
            const invalid = fieldErrors[field.key];
            const describedBy = [invalid && field.key + "-error", field.hint && field.key + "-hint"].filter(Boolean).join(" ") || undefined;
            return <Fragment key={field.key}>{field.heading && <h3 className="settings-group">{field.heading}</h3>}
              <div className="settings-field">
              <div><label htmlFor={field.key} className="text-sm font-medium">{field.label}</label>{secret && <p className={"mt-1 text-[11px] " + (stored?.unreadable ? "text-destructive" : "text-muted-foreground")}>{stored?.unreadable ? "Stored value cannot be decrypted" : stored?.value === "configured" ? stored.encrypted ? "Stored · encrypted" : "Stored · legacy storage" : "Not configured"}</p>}</div>
              <div className="min-w-0 space-y-2">
                {field.kind === "boolean" ? <label className="inline-flex cursor-pointer items-center gap-3 text-sm"><input id={field.key} type="checkbox" aria-describedby={describedBy} checked={draft[field.key] === "true"} onChange={(e) => edit(field.key, e.target.checked ? "true" : "false")} className="size-4 accent-primary" /><span>{draft[field.key] === "true" ? "Enabled" : "Disabled"}</span></label> : field.kind === "select" ? <select id={field.key} className="workbench-select w-full" value={draft[field.key]} aria-invalid={Boolean(invalid)} aria-describedby={describedBy} onChange={(e) => edit(field.key, e.target.value)}>{!field.options?.some(([value]) => value === draft[field.key]) && <option value={draft[field.key]} disabled>{draft[field.key]} (unsupported)</option>}{field.options?.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select> : <div className="flex gap-2"><input id={field.key} autoComplete={secret ? "new-password" : "off"} spellCheck={false} type={secret && !revealed.has(field.key) ? "password" : field.kind === "number" ? "number" : "text"} min={field.min} max={field.max} step={field.step} value={draft[field.key] || ""} disabled={removed.has(field.key) || busy} placeholder={stored?.value === "configured" && secret ? "Leave blank to keep stored value" : field.placeholder} aria-invalid={Boolean(invalid)} aria-describedby={describedBy} className="h-10 min-w-0 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50" onChange={(e) => edit(field.key, e.target.value)} />{secret && <button type="button" aria-label={revealed.has(field.key) ? "Hide " + field.label : "Show entered " + field.label} className="rounded-md border px-2.5 text-muted-foreground" onClick={() => setRevealed((current) => { const next = new Set(current); if (next.has(field.key)) next.delete(field.key); else next.add(field.key); return next; })}>{revealed.has(field.key) ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>}</div>}
                {invalid && <p id={field.key + "-error"} role="alert" className="text-xs text-destructive">{invalid}</p>}
                {field.hint && <p id={field.key + "-hint"} className="settings-hint">{field.hint}</p>}
                {secret && (stored?.value === "configured" || stored?.unreadable) && <label className="inline-flex items-center gap-2 text-xs text-muted-foreground"><input type="checkbox" checked={removed.has(field.key)} onChange={(e) => setRemoved((current) => { const next = new Set(current); if (e.target.checked) next.add(field.key); else next.delete(field.key); return next; })} />Remove stored value on save</label>}
              </div>
            </div>
            {field.key === "llm.custom_endpoint" && resolvedEndpoint && <dl className="settings-url">
              <dt>Request URL preview</dt><dd>{resolvedEndpoint}</dd>
            </dl>}
            </Fragment>;
          })}</div>
          <div className="settings-save">
            <span aria-live="polite">{pending ? pending + (pending === 1 ? " change to save" : " changes to save") : "Section up to date"}</span>
            <div className="flex gap-2"><Button variant="ghost" onClick={discard} disabled={!pending || busy}>Discard</Button>
              <Button onClick={save} disabled={!pending || busy}>Save changes</Button></div>
          </div>
        </fieldset>}
      </section>
      <aside className="settings-saved" aria-labelledby="saved-heading">
        {section === "security" ? <>
          <h2 id="saved-heading" tabIndex={-1} className="settings-subheading">Credential storage</h2>
          <dl><div><dt>Stored fields</dt><dd>{[...SECRET_SETTINGS].filter((key) => saved[key]?.value === "configured").length}</dd></div>
            <div><dt>Encryption key</dt><dd>{security?.encryptionConfigured ? "Configured" : "Missing"}</dd></div></dl>
        </> : <>
          <h2 id="saved-heading" tabIndex={-1} className="settings-subheading">Saved connection</h2>
          <dl><div><dt>{section === "llm" ? "AI review" : "Integration"}</dt><dd>{saved[section + ".enabled"]?.value === "true" ? "Enabled" : "Disabled"}</dd></div>
            {connection.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
          </dl>
          <h3 className="mt-5 text-sm font-semibold">Connection check</h3>
          {tests[section] ? <div role="status" className="my-2 text-sm"><p className="flex items-center gap-1.5">
            {tests[section].ok ? <Check aria-hidden className="size-4" /> : <AlertCircle aria-hidden className="size-4 text-destructive" />}
            {tests[section].ok ? "Succeeded" : "Failed"} · {tests[section].time}</p>
            <p className="mt-1 wrap-anywhere text-muted-foreground">{tests[section].text}</p></div>
            : <p className="my-2 text-sm text-muted-foreground">No test recorded this session.</p>}
          {pending > 0 && <p className="settings-hint">Save or discard these changes before testing the connection.</p>}
          <Button variant="outline" className="mt-2" disabled={busy || pending > 0} onClick={testConnection}>
            {busy ? "Working…" : section === "slack" ? "Send test notification" : "Test saved connection"}</Button>
        </>}
        {security && !security.encryptionConfigured && <p className="mt-4 text-sm text-destructive">Configure the encryption key on the server to save credentials.</p>}
      </aside>
    </div>
  </div>;
}
