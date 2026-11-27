"use client";

import { useEffect, useState, type FormEvent } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { ArrowRight, Check, Eye, EyeOff, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { WorkspaceBrand } from "@/components/workspace-brand";
import { passwordError, safeAuthReturn } from "@/lib/auth-policy";

type Mode = "signin" | "request-access" | "activate" | "forgot-password" | "reset-password";
interface AuthConfig { methods: Array<{ id: string; name: string; enabled: boolean }>; local: boolean; email: boolean; policyConfigured: boolean; development: boolean }
const TITLES: Record<Mode, [string, string]> = {
  signin: ["Sign in to Aegify", "Use the account approved for your workspace."],
  "request-access": ["Create an account", "We’ll send a verification link to your work email."],
  activate: ["Finish creating your account", "Choose a username and passphrase for this workspace."],
  "forgot-password": ["Reset your password", "Enter your verified email to request a reset link."],
  "reset-password": ["Set a new passphrase", "Changing your password signs you out of all existing sessions."],
};
export function AuthPanel({ mode }: { mode: Mode }) {
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [loadError, setLoadError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [token, setToken] = useState("");
  const [callback, setCallback] = useState("/");
  const passwordMode = ["signin", "activate", "reset-password"].includes(mode);
  const completion = mode === "activate" || mode === "reset-password";
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      const query = new URLSearchParams(window.location.search);
      setCallback(safeAuthReturn(query.get("callbackUrl")));
      if (query.has("error")) setError(query.get("error") === "OAuthAccountNotLinked" ? "This email already uses another sign-in method. Sign in with the original method." : "Sign-in failed. Try again or contact your workspace administrator.");
      const fragment = new URLSearchParams(window.location.hash.slice(1));
      if (fragment.has("token")) {
        setToken(fragment.get("token") || "");
        window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
      }
    });
    return () => cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      try {
        const response = await fetch("/api/auth/config", { signal: controller.signal, cache: "no-store" });
        if (!response.ok) throw new Error();
        const data: AuthConfig = await response.json();
        if (!controller.signal.aborted) setConfig(data);
      } catch {
        if (!controller.signal.aborted) setLoadError("Couldn’t load sign-in methods.");
      }
    }
    void load();
    return () => controller.abort();
  }, [attempt]);

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
  const providers = mode === "signin" && config?.policyConfigured ? config.methods.filter((method) => method.enabled) : [];
  const showBack = mode !== "signin" || (config?.email && config.policyConfigured);
  return <section className="mx-auto w-full max-w-[27rem] px-2 pb-10 pt-[clamp(2rem,12vh,7.5rem)] sm:px-0" aria-labelledby="access-title">
      <div className="mb-8 border-b border-input pb-5"><WorkspaceBrand signIn /></div>
      <h1 id="access-title" className="text-3xl font-semibold tracking-tight">{TITLES[mode][0]}</h1>
      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{TITLES[mode][1]}</p>
      <div className="mt-7 space-y-5">
        {loadError && <div role="alert" className="space-y-2 text-sm"><p>{loadError}</p><Button type="button" variant="outline" onClick={() => { setLoadError(""); setAttempt((value) => value + 1); }}>Retry</Button></div>}
        {!config && !loadError && <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading sign-in methods…</p>}
        {config?.development && <p className="border-l-2 border-input pl-3 text-sm leading-relaxed text-muted-foreground">Local preview. Configure authentication to enable sign-in.</p>}
        {config && !config.development && !config.policyConfigured && <p role="alert" className="text-xs text-destructive">Workspace access policy is not configured. Contact the workspace owner.</p>}
        {error && <p role="alert" className="rounded-md border border-destructive/20 p-3 text-sm leading-6 text-destructive">{error}</p>}
        {message && <div role="status" className="space-y-3 rounded-md border border-emerald-500/20 bg-emerald-500/5 p-4 text-sm leading-6"><Check className="h-5 w-5 text-emerald-600" /><p>{message}</p>{completion && <Link href="/auth/signin" className="block text-primary">Continue to sign in →</Link>}</div>}
        {available && (!completion || !message) && <form onSubmit={submit} className="space-y-4">
          <fieldset disabled={busy || !available || (completion && !token)} className="min-w-0 space-y-4">
            {mode === "signin" && <div><label htmlFor="identifier" className="auth-label">Username or email</label><input id="identifier" name="identifier" autoComplete="username" required maxLength={254} className="auth-input" /></div>}
            {mode === "activate" && <div>
              <label htmlFor="username" className="auth-label">Username</label>
              <input id="username" name="username" autoComplete="username" required minLength={3} maxLength={32} aria-describedby="username-help" pattern="[a-zA-Z][a-zA-Z0-9._\-]{2,31}" className="auth-input" />
              <p id="username-help" className="mt-2 text-xs text-muted-foreground">Start with a letter. Use 3–32 letters, numbers, dots, underscores or hyphens.</p>
            </div>}
            {!passwordMode && <div>
              <label htmlFor="email" className="auth-label">Work email</label>
              <input id="email" name="email" type="email" autoComplete="email" required maxLength={254} className="auth-input" />
            </div>}
            {passwordMode && <div>
              <div className="mb-2 flex items-center justify-between gap-2 text-sm">
                <label htmlFor="password" className="font-medium">{mode === "signin" ? "Password" : "New passphrase"}</label>
                {mode === "signin" && config?.email && <Link href="/auth/forgot-password" className="text-primary hover:underline">Forgot password?</Link>}
              </div>
              <div className="relative"><input id="password" name="password" type={revealed ? "text" : "password"} autoComplete={mode === "signin" ? "current-password" : "new-password"} required minLength={completion ? 15 : undefined} maxLength={128} aria-describedby={completion ? "passphrase-help" : undefined} className="auth-input pr-12" />
                <button type="button" onClick={() => setRevealed(!revealed)} aria-label={revealed ? "Hide password" : "Show password"} className="absolute inset-y-0 right-0 grid w-11 place-items-center text-muted-foreground hover:text-foreground">{revealed ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}</button>
              </div>
              {completion && <p id="passphrase-help" className="mt-2 text-xs text-muted-foreground">Use 15–128 characters.</p>}
            </div>}
            {completion && <div><label htmlFor="confirm" className="auth-label">Confirm passphrase</label><input id="confirm" name="confirm" type="password" autoComplete="new-password" required maxLength={128} className="auth-input" /></div>}
            <Button type="submit" className="h-11 w-full">{busy && <Loader2 aria-hidden className="size-4 animate-spin" />}{mode === "signin" ? "Sign in" : mode === "activate" ? "Create account" : mode === "reset-password" ? "Update password" : mode === "forgot-password" ? "Send reset link" : "Send verification link"}</Button>
          </fieldset>
          {completion && !token && !message && <p className="text-xs leading-6 text-muted-foreground">Open this page using the one-time link from your email. <Link href={mode === "activate" ? "/auth/request-access" : "/auth/forgot-password"} className="text-primary">Request a new link.</Link></p>}
        </form>}
        {providers.length > 0 && <>
          {available && <div className="flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" /></div>}
          <div className="space-y-2">{providers.map((method) =>
            <Button type="button" key={method.id} variant={!available && providers.length === 1 ? "default" : "outline"} className="h-11 w-full justify-between px-4" disabled={busy} onClick={() => oauth(method.id)}>
              Continue with {method.name}<ArrowRight aria-hidden className="size-4" />
            </Button>)}</div>
        </>}
        {config?.policyConfigured && !config.development && !available && !providers.length && <p role="status" className="border-l-2 border-input pl-3 text-sm leading-relaxed text-muted-foreground">{mode === "signin" ? "Contact your workspace administrator to enable a sign-in method." : "Contact your workspace administrator for access to this account."}</p>}
      </div>
      {showBack && <div className="mt-6 border-t pt-3"><Link href={mode === "signin" ? "/auth/request-access" : "/auth/signin"} className="inline-flex min-h-11 items-center text-sm font-medium text-primary hover:underline">{mode === "signin" ? "Create a verified account" : "Back to sign in"}</Link></div>}
  </section>;
}
