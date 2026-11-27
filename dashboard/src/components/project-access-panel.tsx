"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ProjectAuditHistory, type AuditPage } from "./project-audit-history";

type Member = {
  userId: string;
  role: string;
  user: { name: string | null; email: string | null; disabled: boolean };
};
type Token = {
  id: string;
  name: string;
  prefix: string;
  expiresAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
};
const roles = {
  viewer: "View scans and findings.",
  triager: "Review and assign findings.",
  maintainer: "Run scans and reviews, upload results and triage findings.",
  admin: "Manage project access, CI credentials and scans.",
};
const selectStyle = "h-11 rounded-md border border-input bg-background px-3 text-sm";

async function requestJson(url: string, method = "GET", body?: unknown) {
  const response = await fetch(url, {
    method,
    cache: "no-store",
    ...(body === undefined
      ? {}
      : { headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok || !result)
    throw new Error(typeof result?.error === "string" ? result.error : "The request could not be completed.");
  return result;
}

export function ProjectAccessPanel({ projectId, archived }: { projectId: string; archived: boolean }) {
  const [data, setData] = useState<{ members: Member[]; tokens: Token[]; audit: AuditPage } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<keyof typeof roles>("viewer");
  const [name, setName] = useState("");
  const [days, setDays] = useState("30");
  const [newToken, setNewToken] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const base = "/api/projects/" + encodeURIComponent(projectId);
  const load = useCallback(async () => {
    const [people, credentials, audit] = await Promise.all([
      requestJson(base + "/members"),
      requestJson(base + "/tokens"),
      requestJson(base + "/audit?limit=15"),
    ]);
    return {
      members: people.members as Member[],
      tokens: credentials.tokens as Token[],
      audit: audit as AuditPage,
    };
  }, [base]);

  useEffect(() => {
    let active = true;
    async function read() {
      setError("");
      try {
        const value = await load();
        if (active) setData(value);
      } catch {
        if (active) setError("Project access and credentials could not be loaded.");
      }
    }
    void read();
    return () => {
      active = false;
    };
  }, [load, attempt]);

  async function mutate(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
      setData(await load());
    } catch (reason) {
      setError(
        reason instanceof Error && reason.name === "Error"
          ? reason.message
          : "The change could not be saved.",
      );
    } finally {
      setBusy(false);
    }
  }

  function saveMember(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void mutate(async () => {
      await requestJson(base + "/members", "PUT", { email, role });
      setEmail("");
      setNotice("Project access saved.");
    });
  }
  function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void mutate(async () => {
      const issued = await requestJson(base + "/tokens", "POST", {
        name,
        expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString(),
      });
      setNewToken(issued.token);
      setName("");
    });
  }

  return (
    <section aria-label="Project access and CI" className="project-access">
      {error && (
        <p role="alert" className="py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      {notice && (
        <p role="status" className="py-2 text-sm text-primary">
          {notice}
        </p>
      )}
      {!data ? (
        error ? (
          <Button className="min-h-11" variant="outline" onClick={() => setAttempt((value) => value + 1)}>
            Retry settings
          </Button>
        ) : (
          <p role="status" className="py-3 text-sm text-muted-foreground">
            Loading project access and credentials…
          </p>
        )
      ) : (
        <>
          <section aria-labelledby="project-access-heading">
            <h3 id="project-access-heading">Project access</h3>
            <form onSubmit={saveMember}>
              <label className="grow">
                Account email
                <Input
                  required
                  type="email"
                  placeholder="name@company.com"
                  autoComplete="off"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              </label>
              <label>
                Role
                <select
                  aria-describedby="project-role-description"
                  className={selectStyle}
                  value={role}
                  onChange={(event) => setRole(event.target.value as keyof typeof roles)}
                >
                  {Object.keys(roles).map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
              <Button disabled={busy} type="submit">
                Save access
              </Button>
            </form>
            <p id="project-role-description" className="text-xs text-muted-foreground">
              <span className="capitalize">{role}</span> access. {roles[role]} Use an account that has signed
              in to this workspace.
            </p>
            {data.members.length ? (
              <ul aria-label="Project members" className="divide-y border-y">
                {data.members.map((member) => (
                  <li key={member.userId}>
                    <div className="grow">
                      <p className="font-medium">
                        {member.user.email || member.user.name || "Workspace account"}
                      </p>
                      {member.user.disabled && (
                        <p className="text-xs text-muted-foreground">Account disabled</p>
                      )}
                    </div>
                    <span className="text-sm capitalize text-muted-foreground">{member.role}</span>
                    <Button
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        if (confirm("Remove this account from the project?"))
                          void mutate(async () => {
                            await requestJson(base + "/members", "DELETE", { userId: member.userId });
                            setNotice("Project membership removed.");
                          });
                      }}
                    >
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">Only workspace administrators have access.</p>
            )}
          </section>

          <section aria-labelledby="project-tokens-heading">
            <h3 id="project-tokens-heading">CI upload tokens</h3>
            {archived ? (
              <p className="text-sm text-muted-foreground">
                Restore the project to issue a new upload token.
              </p>
            ) : (
              <>
                <form onSubmit={issue}>
                  <label className="grow">
                    Token name
                    <Input
                      required
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      maxLength={80}
                      placeholder="Release pipeline"
                    />
                  </label>
                  <label>
                    Expires in
                    <select
                      className={selectStyle}
                      value={days}
                      onChange={(event) => setDays(event.target.value)}
                    >
                      {[7, 30, 90].map((value) => (
                        <option value={value} key={value}>
                          {value} days
                        </option>
                      ))}
                    </select>
                  </label>
                  <Button disabled={busy} type="submit">
                    Create token
                  </Button>
                </form>
                {newToken && (
                  <div className="space-y-2 border-l-2 border-primary py-1 pl-3">
                    <label>
                      Copy this token now. It is shown once.
                      <Input
                        aria-label="New CI upload token"
                        value={newToken}
                        readOnly
                        autoComplete="off"
                        spellCheck={false}
                        className="font-mono"
                      />
                    </label>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="outline"
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(newToken);
                            setNotice("Token copied. Store it in your CI secret manager.");
                          } catch {
                            setError("Select and copy the token manually.");
                          }
                        }}
                      >
                        Copy token
                      </Button>
                      <Button variant="outline" onClick={() => setNewToken("")}>
                        Dismiss
                      </Button>
                    </div>
                  </div>
                )}
                <p className="text-sm text-muted-foreground">
                  This token grants SARIF upload access to this project. Store it as{" "}
                  <code>AEGIFY_UPLOAD_TOKEN</code> in CI and send it as a bearer credential to{" "}
                  <code>/api/upload?projectId={projectId}</code>.
                </p>
              </>
            )}
            {data.tokens.length ? (
              <ul aria-label="Project CI tokens" className="divide-y border-y">
                {data.tokens.map((token) => (
                  <li key={token.id}>
                    <div className="grow">
                      <p className="font-medium">{token.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {token.prefix}… · Expires {new Date(token.expiresAt).toLocaleDateString()} ·{" "}
                        {token.lastUsedAt
                          ? "Last used " + new Date(token.lastUsedAt).toLocaleString()
                          : "Never used"}
                      </p>
                    </div>
                    {token.revokedAt ? (
                      <span className="text-sm text-muted-foreground">Revoked</span>
                    ) : (
                      <Button
                        variant="outline"
                        disabled={busy}
                        onClick={() => {
                          if (confirm("Revoke this CI token? Future uploads using it will be rejected."))
                            void mutate(async () => {
                              await requestJson(base + "/tokens", "DELETE", { tokenId: token.id });
                              setNewToken("");
                              setNotice("CI token revoked.");
                            });
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No CI tokens issued.</p>
            )}
          </section>

          <ProjectAuditHistory key={data.audit.events[0]?.id ?? "empty"} url={base + "/audit"} first={data.audit} />
        </>
      )}
    </section>
  );
}
