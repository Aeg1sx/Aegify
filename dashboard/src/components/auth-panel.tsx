"use client";

import { useEffect, useState, type FormEvent } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { ArrowRight, Check, Eye, EyeOff, Fingerprint, KeyRound, Loader2, LockKeyhole, Mail, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { passwordError, safeAuthReturn } from "@/lib/auth-policy";

type Mode = "signin" | "request-access" | "activate" | "forgot-password" | "reset-password";
interface AuthConfig { methods: Array<{ id: string; name: string; enabled: boolean }>; local: boolean; email: boolean; policyConfigured: boolean; development: boolean }
const TITLES: Record<Mode, [string, string]> = {
  signin: ["Welcome back", "Sign in to your security workspace."],
  "request-access": ["Verify your email", "Account creation starts with a one-time email verification link."],
  activate: ["Create your account", "Choose your username and passphrase after verifying your email link."],
  "forgot-password": ["Recover access", "Request a one-time password reset link for your verified account."],
  "reset-password": ["Set a new passphrase", "Changing your password signs you out of every existing session."],
};
export function AuthPanel({ mode }: { mode: Mode }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [token, setToken] = useState("");
  const [callback, setCallback] = useState("/");
  const passwordMode = ["signin", "activate", "reset-password"].includes(mode);
  const completion = mode === "activate" || mode === "reset-password";
  useEffect(() => {
    const controller = new AbortController();
    const frame = requestAnimationFrame(() => {
      const query = new URLSearchParams(window.location.search);
      setCallback(safeAuthReturn(query.get("callbackUrl")));
      if (query.has("error")) setError(query.get("error") === "OAuthAccountNotLinked" ? "This email already uses another sign-in method. Sign in with that method; identities are not merged automatically." : "Sign-in could not be completed. Check your account access policy or try another configured method.");
      const fragment = new URLSearchParams(window.location.hash.slice(1));
      setToken(fragment.get("token") || "");
      if (fragment.has("token")) window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
      void fetch("/api/auth/config", { signal: controller.signal, cache: "no-store" }).then(async (response) => { if (!response.ok) throw new Error(); setConfig(await response.json()); }).catch(() => { if (!controller.signal.aborted) setLoadError("Unable to load sign-in configuration. Reload this page to retry."); });
    });
    return () => { controller.abort(); cancelAnimationFrame(frame); };
  }, []);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError(""); setMessage("");
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") || "");
    if (completion) {
      const invalid = passwordError(password);
      if (invalid) { setError(invalid); return; }
      if (password !== form.get("confirm")) { setError("Passphrases do not match."); return; }
    }
    setBusy(true);
    try {
      if (mode === "signin") {
        const result = await signIn("credentials", { identifier: form.get("identifier"), password, redirect: false, callbackUrl: callback });
        if (!result || result.error) throw new Error("Unable to sign in. Check your credentials and verified account access, or try again later.");
        window.location.assign(callback);
      } else {
        const response = await fetch("/api/auth/local/" + mode, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: form.get("email"), username: form.get("username"), password: passwordMode ? password : undefined, token: completion ? token : undefined }) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "The request could not be completed.");
        setMessage(data.message);
        if (completion) setToken("");
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Sign-in service is unavailable."); }
    finally { setBusy(false); }
  };
  const oauth = async (id: string) => {
    setBusy(true); setError("");
    try { await signIn(id, { callbackUrl: callback }); }
    catch { setError("Unable to start provider sign-in. Please try again."); setBusy(false); }
  };
  const available = config?.policyConfigured && (mode === "signin" || completion ? config.local : config.email);
  return <div className="mx-auto grid min-h-[calc(100dvh-56px)] max-w-6xl items-center gap-12 py-8 lg:grid-cols-[minmax(0,1fr)_460px]">
    <section className="hidden min-w-0 pr-8 lg:block" aria-label="Workspace security">
      <Link href="/" className="inline-flex items-center gap-2 text-xl font-semibold tracking-tight"><Shield className="h-7 w-7 text-primary" />Aegify<span className="text-primary">.</span></Link>
      <p className="eyebrow mt-20">Identity &amp; access</p><h1 className="mt-4 text-5xl font-semibold leading-[1.15] tracking-tight">A clear boundary.<br /><span className="text-muted-foreground">For every identity.</span></h1>
      <p className="mt-6 max-w-md text-sm leading-7 text-muted-foreground">A dedicated entry point for your source, findings, and remediation workflow. Workspace access stays separate from provider identity.</p>
      <div className="mt-10 space-y-0 border-l border-border">{[[Fingerprint, "Verify identity", "Password with verified email, or a configured identity provider."], [Shield, "Check workspace access", "Only explicitly allowed emails or domains can enter."], [LockKeyhole, "Keep sessions bounded", "Eight-hour maximum sessions; password resets revoke existing access."]].map(([Icon, title, description], index) => { const Symbol = Icon as typeof Shield; return <div key={String(title)} className="relative pb-7 pl-8"><span className="absolute -left-3.5 flex h-7 w-7 items-center justify-center rounded-md border bg-background"><Symbol className="h-3.5 w-3.5 text-primary" /></span><p className="text-sm font-medium"><span className="mr-3 font-mono text-[10px] text-muted-foreground">0{index + 1}</span>{String(title)}</p><p className="mt-1.5 max-w-xs text-xs leading-6 text-muted-foreground">{String(description)}</p></div>; })}</div>
    </section>
    <section className="workbench-panel mx-auto w-full max-w-[460px] overflow-hidden">
      <div className="border-b border-border px-7 py-7"><div className="mb-5 flex items-center gap-2 text-sm font-semibold lg:hidden"><Shield className="h-5 w-5 text-primary" />Aegify</div><p className="eyebrow mb-3">Secure workspace access</p><h2 className="text-2xl font-semibold tracking-tight">{TITLES[mode][0]}</h2><p className="mt-2 text-sm leading-6 text-muted-foreground">{TITLES[mode][1]}</p></div>
      <div className="space-y-5 p-7">
        {loadError && <p role="alert" className="text-sm text-destructive">{loadError}</p>}
        {!config && !loadError && <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading sign-in methods…</p>}
        {config?.development && <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs leading-6 text-amber-800 dark:text-amber-200">Local UI preview. Authentication is not enabled on this server; configure server secrets before deployment.</p>}
        {config && !config.development && !config.policyConfigured && <p role="alert" className="text-xs text-destructive">Workspace access policy is not configured. Contact the workspace owner.</p>}
        {error && <p role="alert" className="rounded-md border border-destructive/20 p-3 text-sm leading-6 text-destructive">{error}</p>}
        {message && <div role="status" className="space-y-3 rounded-md border border-emerald-500/20 bg-emerald-500/5 p-4 text-sm leading-6"><Check className="h-5 w-5 text-emerald-600" /><p>{message}</p>{completion && <Link href="/auth/signin" className="block text-primary">Continue to sign in →</Link>}</div>}
        {(!completion || !message) && <form onSubmit={submit} className="space-y-4">
          <fieldset disabled={busy || !available || (completion && !token)} className="min-w-0 space-y-4">
            {mode === "signin" && <div><label htmlFor="identifier" className="mb-2 block text-xs font-medium">Username or email</label><input id="identifier" name="identifier" autoComplete="username" required maxLength={254} className="h-11 w-full rounded-md border bg-background px-3 text-sm disabled:opacity-50" placeholder="Your workspace identity" /></div>}
            {mode === "activate" && <div><label htmlFor="username" className="mb-2 block text-xs font-medium">Username</label><input id="username" name="username" autoComplete="username" required minLength={3} maxLength={32} pattern="[a-zA-Z][a-zA-Z0-9._-]{2,31}" className="h-11 w-full rounded-md border bg-background px-3 text-sm" /><p className="mt-2 text-[11px] text-muted-foreground">3–32 characters: letters, numbers, dots, underscores, or hyphens.</p></div>}
            {!passwordMode && <div><label htmlFor="email" className="mb-2 block text-xs font-medium">Work email</label><input id="email" name="email" type="email" autoComplete="email" required maxLength={254} className="h-11 w-full rounded-md border bg-background px-3 text-sm" placeholder="you@company.com" /></div>}
            {passwordMode && <div><div className="mb-2 flex justify-between gap-2 text-xs"><label htmlFor="password" className="font-medium">{mode === "signin" ? "Password" : "New passphrase"}</label>{mode === "signin" && <Link href="/auth/forgot-password" className="text-muted-foreground hover:text-primary">Forgot password?</Link>}</div><div className="relative"><input id="password" name="password" type={revealed ? "text" : "password"} autoComplete={mode === "signin" ? "current-password" : "new-password"} required minLength={completion ? 15 : undefined} maxLength={128} className="h-11 w-full rounded-md border bg-background pl-3 pr-10 text-sm disabled:opacity-50" /><button type="button" onClick={() => setRevealed(!revealed)} aria-label={revealed ? "Hide password" : "Show password"} className="absolute right-3 top-3.5 text-muted-foreground">{revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div>{completion && <p className="mt-2 text-[11px] leading-5 text-muted-foreground">Use 15–128 characters. Long, unique passphrases are supported; never reuse a password.</p>}</div>}
            {completion && <div><label htmlFor="confirm" className="mb-2 block text-xs font-medium">Confirm passphrase</label><input id="confirm" name="confirm" type="password" autoComplete="new-password" required maxLength={128} className="h-11 w-full rounded-md border bg-background px-3 text-sm" /></div>}
            <Button type="submit" className="h-11 w-full">{busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : passwordMode ? <KeyRound className="mr-2 h-4 w-4" /> : <Mail className="mr-2 h-4 w-4" />}{mode === "signin" ? "Sign in" : mode === "activate" ? "Verify email & create account" : mode === "reset-password" ? "Update password" : "Send verification link"}<ArrowRight className="ml-auto h-4 w-4" /></Button>
          </fieldset>
          {completion && !token && !message && <p className="text-xs leading-6 text-muted-foreground">Open this page using the one-time link from your email. <Link href={mode === "activate" ? "/auth/request-access" : "/auth/forgot-password"} className="text-primary">Request a new link.</Link></p>}
          {config && !available && !config.development && <p className="text-xs leading-6 text-muted-foreground">This method is not ready. The workspace owner must configure password sign-in, email delivery, and an access policy.</p>}
        </form>}
        {mode === "signin" && config && <><div className="flex items-center gap-3 text-[10px] uppercase tracking-wider text-muted-foreground"><span className="h-px flex-1 bg-border" />Or use single sign-on<span className="h-px flex-1 bg-border" /></div><div className="grid grid-cols-2 gap-2">{config.methods.filter((method) => method.enabled || ["google", "okta"].includes(method.id)).map((method) => <Button type="button" key={method.id} variant="outline" className="h-11 text-xs" disabled={busy || !method.enabled || !config.policyConfigured} onClick={() => oauth(method.id)}><Fingerprint className="mr-2 h-4 w-4" />{method.name}{!method.enabled && <span className="sr-only">Not configured</span>}</Button>)}</div><p className="text-[11px] leading-5 text-muted-foreground">Only configured providers are available. Matching email addresses are never automatically merged across sign-in methods.</p></>}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-muted/20 px-7 py-4 text-xs"><Link href={mode === "signin" ? "/auth/request-access" : "/auth/signin"} className="font-medium text-primary">{mode === "signin" ? "Create a verified account" : "Back to sign in"}</Link><span className="flex items-center gap-1.5 text-muted-foreground"><LockKeyhole className="h-3 w-3" />Restricted workspace</span></div>
    </section>
  </div>;
}
