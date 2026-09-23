"use client";

import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type Member = { userId: string; role: string; user: { name: string | null; email: string | null; disabled: boolean } };
type Token = { id: string; name: string; prefix: string; expiresAt: string; revokedAt: string | null; lastUsedAt: string | null };
type Event = { id: string; action: string; actorId: string; createdAt: string };
const roles = ["viewer", "triager", "maintainer", "admin"];
const field = "h-9 rounded-md border border-input bg-background px-3 text-sm";

async function requestJson(url: string, method = "GET", body?: unknown) {
  const response = await fetch(url, { method, cache: "no-store", ...(body === undefined ? {} : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

export function ProjectAccessPanel({ projectId }: { projectId: string }) {
  const [members, setMembers] = useState<Member[]>([]);
  const [tokens, setTokens] = useState<Token[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [name, setName] = useState("");
  const [days, setDays] = useState("30");
  const [newToken, setNewToken] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const base = `/api/projects/${projectId}`;
  const load = useCallback(() => Promise.all([requestJson(`${base}/members`), requestJson(`${base}/tokens`), requestJson(`${base}/audit`)]), [base]);
  const refresh = async () => {
    const [people, credentials, audit] = await load();
    setMembers(people.members); setTokens(credentials.tokens); setEvents(audit.events);
  };
  useEffect(() => {
    let active = true;
    load().then(([people, credentials, audit]) => { if (active) { setMembers(people.members); setTokens(credentials.tokens); setEvents(audit.events); } }).catch((error) => { if (active) setError(error.message); });
    return () => { active = false; };
  }, [load]);
  async function mutate(action: () => Promise<void>) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); await refresh(); }
    catch (error) { setError(error instanceof Error ? error.message : "The change could not be saved."); }
    finally { setBusy(false); }
  }
  return <section className="space-y-4" aria-label="Project access and CI">
    {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    {notice && <p role="status" className="text-sm text-muted-foreground">{notice}</p>}
    <Card>
      <CardHeader><CardTitle>Project access</CardTitle><p className="text-sm text-muted-foreground">Viewer: read results. Triager: manage findings. Maintainer: upload and run reviews. Admin: manage access and CI credentials.</p></CardHeader>
      <CardContent className="space-y-4">
        <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); void mutate(async () => { await requestJson(`${base}/members`, "PUT", { email, role }); setEmail(""); setNotice("Project access saved."); }); }}>
          <label className="min-w-48 flex-1 space-y-1 text-sm">Account email<Input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="colleague@company.com" required /></label>
          <label className="space-y-1 text-sm">Role<select className={`${field} block`} value={role} onChange={(event) => setRole(event.target.value)}>{roles.map((value) => <option key={value}>{value}</option>)}</select></label>
          <Button disabled={busy} type="submit">Save access</Button>
        </form>
        <p className="text-xs text-muted-foreground">Add an account that has already signed in through the workspace allowlist. No invitation email is sent.</p>
        <div className="divide-y rounded-md border">
          {members.length === 0 && <p className="p-3 text-sm text-muted-foreground">Only workspace administrators have access. Add a project administrator to delegate management.</p>}
          {members.map((member) => <div key={member.userId} className="flex flex-wrap items-center gap-3 p-3 text-sm">
            <div className="min-w-40 flex-1"><p>{member.user.email || member.user.name || "Workspace account"}</p>{member.user.disabled && <p className="text-xs text-muted-foreground">Account disabled</p>}</div>
            <span className="rounded-md bg-muted px-2 py-1 text-xs">{member.role}</span>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => { if (confirm("Remove this account from the project?")) void mutate(async () => { await requestJson(`${base}/members`, "DELETE", { userId: member.userId }); setNotice("Project membership removed."); }); }}>Remove</Button>
          </div>)}
        </div>
      </CardContent>
    </Card>
    <Card>
      <CardHeader><CardTitle>CI upload tokens</CardTitle><p className="text-sm text-muted-foreground">Each token can upload SARIF to this project. It cannot read findings or change settings.</p></CardHeader>
      <CardContent className="space-y-4">
        <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); void mutate(async () => { const issued = await requestJson(`${base}/tokens`, "POST", { name, expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }); setNewToken(issued.token); setName(""); }); }}>
          <label className="min-w-48 flex-1 space-y-1 text-sm">Token name<Input value={name} onChange={(event) => setName(event.target.value)} maxLength={80} placeholder="main branch CI" required /></label>
          <label className="space-y-1 text-sm">Expires in<select className={`${field} block`} value={days} onChange={(event) => setDays(event.target.value)}>{[7, 30, 90].map((value) => <option value={value} key={value}>{value} days</option>)}</select></label>
          <Button disabled={busy} type="submit">Create token</Button>
        </form>
        {newToken && <div className="space-y-2 rounded-md border border-primary/30 bg-primary/5 p-4">
          <p className="text-sm font-medium">Copy this token now. It is shown once.</p>
          <Input aria-label="New CI upload token" value={newToken} readOnly autoComplete="off" spellCheck={false} className="font-mono" />
          <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => { navigator.clipboard.writeText(newToken).then(() => setNotice("Token copied. Store it in your CI secret manager.")).catch(() => setError("Select and copy the token manually.")); }}>Copy token</Button><Button size="sm" variant="outline" onClick={() => setNewToken("")}>Dismiss</Button></div>
        </div>}
        <p className="text-sm">Store the token as <code>AEGIFY_UPLOAD_TOKEN</code> in CI and send it as a Bearer credential to <code>/api/upload?projectId={projectId}</code>.</p>
        <div className="divide-y rounded-md border">
          {tokens.length === 0 && <p className="p-3 text-sm text-muted-foreground">No CI tokens issued.</p>}
          {tokens.map((token) => <div key={token.id} className="flex flex-wrap items-center gap-3 p-3 text-sm">
            <div className="min-w-48 flex-1"><p className="font-medium">{token.name}</p><p className="text-xs text-muted-foreground">{token.prefix}… · expires {new Date(token.expiresAt).toLocaleDateString()} · {token.lastUsedAt ? `last used ${new Date(token.lastUsedAt).toLocaleString()}` : "never used"}</p></div>
            {token.revokedAt ? <span className="text-xs text-muted-foreground">Revoked</span> : <Button size="sm" variant="outline" disabled={busy} onClick={() => { if (confirm("Revoke this CI token? Future uploads using it will be rejected.")) void mutate(async () => { await requestJson(`${base}/tokens`, "DELETE", { tokenId: token.id }); setNewToken(""); setNotice("CI token revoked."); }); }}>Revoke</Button>}
          </div>)}
        </div>
      </CardContent>
    </Card>
    <Card><CardHeader><CardTitle>Recent access and import events</CardTitle></CardHeader><CardContent><ol className="space-y-2 text-sm">{events.slice(0, 15).map((event) => <li key={event.id} className="flex flex-wrap justify-between gap-2 border-b pb-2"><span>{event.action.replaceAll(".", " ").replaceAll("_", " ")}</span><span className="text-xs text-muted-foreground">{new Date(event.createdAt).toLocaleString()}</span></li>)}</ol>{!events.length && <p className="text-sm text-muted-foreground">No recorded events yet.</p>}</CardContent></Card>
  </section>;
}
