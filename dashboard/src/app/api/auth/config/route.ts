import { NextResponse } from "next/server";
import { accessPolicyConfigured, localAuthEnabled, mailConfigured, validOktaIssuer } from "@/lib/auth-policy";

export async function GET() {
  const env = process.env;
  const methods = [
    { id: "google", name: "Google", enabled: Boolean(env.AUTH_SECRET && env.AUTH_GOOGLE_ID && env.AUTH_GOOGLE_SECRET) },
    { id: "okta", name: "Okta SSO", enabled: Boolean(env.AUTH_SECRET && env.AUTH_OKTA_ID && env.AUTH_OKTA_SECRET && validOktaIssuer(env.AUTH_OKTA_ISSUER)) },
    { id: "github", name: "GitHub", enabled: Boolean(env.AUTH_SECRET && env.AUTH_GITHUB_ID && env.AUTH_GITHUB_SECRET) },
    { id: "gitlab", name: "GitLab", enabled: Boolean(env.AUTH_SECRET && env.AUTH_GITLAB_ID && env.AUTH_GITLAB_SECRET) },
  ];
  return NextResponse.json({ methods, local: localAuthEnabled(env), email: localAuthEnabled(env) && mailConfigured(env), accessRestricted: true, policyConfigured: accessPolicyConfigured(env), development: !env.AUTH_SECRET && env.NODE_ENV !== "production" }, { headers: { "Cache-Control": "no-store" } });
}
