import NextAuth from "next-auth";
import type { Provider } from "next-auth/providers";
import GitHub from "next-auth/providers/github";
import GitLab from "next-auth/providers/gitlab";
import Google from "next-auth/providers/google";
import Okta from "next-auth/providers/okta";
import Credentials from "next-auth/providers/credentials";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import { assertProductionSecurity, dashboardAuthConfigured } from "@/lib/security-config";
import { emailAllowed, localAuthEnabled, normalizeEmail, safeAuthReturn, validOktaIssuer } from "@/lib/auth-policy";
import { createLocalAuthService, limitAuthRequest, resendAuthMailer } from "@/lib/local-auth";

assertProductionSecurity(process.env);
const authEnabled = dashboardAuthConfigured(process.env);
const providers: Provider[] = [];
const enabledProviders = new Set<string>();
if (process.env.AUTH_GITHUB_ID && process.env.AUTH_GITHUB_SECRET) {
  providers.push(GitHub({ clientId: process.env.AUTH_GITHUB_ID, clientSecret: process.env.AUTH_GITHUB_SECRET, authorization: { params: { scope: "read:user user:email repo" } } }));
  enabledProviders.add("github");
}
if (process.env.AUTH_GITLAB_ID && process.env.AUTH_GITLAB_SECRET) {
  providers.push(GitLab({ clientId: process.env.AUTH_GITLAB_ID, clientSecret: process.env.AUTH_GITLAB_SECRET, authorization: { params: { scope: "read_user read_repository api" } } }));
  enabledProviders.add("gitlab");
}
if (process.env.AUTH_GOOGLE_ID && process.env.AUTH_GOOGLE_SECRET) {
  providers.push(Google({
    clientId: process.env.AUTH_GOOGLE_ID, clientSecret: process.env.AUTH_GOOGLE_SECRET,
    authorization: { params: { scope: "openid email profile" } },
    checks: ["pkce", "state", "nonce"],
    allowDangerousEmailAccountLinking: false,
    profile(profile) { return { id: profile.sub, name: profile.name, email: normalizeEmail(profile.email), image: profile.picture }; },
  }));
  enabledProviders.add("google");
}
if (process.env.AUTH_OKTA_ID && process.env.AUTH_OKTA_SECRET && validOktaIssuer(process.env.AUTH_OKTA_ISSUER)) {
  providers.push(Okta({
    clientId: process.env.AUTH_OKTA_ID, clientSecret: process.env.AUTH_OKTA_SECRET, issuer: process.env.AUTH_OKTA_ISSUER,
    authorization: { params: { scope: "openid email profile" } },
    checks: ["pkce", "state", "nonce"], allowDangerousEmailAccountLinking: false,
    profile(profile) { return { id: profile.sub, name: profile.name, email: normalizeEmail(profile.email), image: null }; },
  }));
  enabledProviders.add("okta");
}
if (localAuthEnabled(process.env)) {
  providers.push(Credentials({
    credentials: { identifier: { label: "Username or email", type: "text" }, password: { label: "Password", type: "password" } },
    async authorize(credentials, request) {
      if (typeof credentials.identifier !== "string" || credentials.identifier.length > 254 || typeof credentials.password !== "string" || credentials.password.length > 128) return null;
      if (!await limitAuthRequest(prisma, process.env, request, "signin", credentials.identifier)) return null;
      const service = createLocalAuthService(prisma, process.env, resendAuthMailer(process.env));
      return service.authenticate(credentials.identifier, credentials.password);
    },
  }));
  enabledProviders.add("credentials");
}

const result = NextAuth({
  ...(authEnabled ? { adapter: PrismaAdapter(prisma) } : {}),
  providers,
  secret: process.env.AUTH_SECRET || "dev-secret-not-for-production",
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 },
  pages: { signIn: "/auth/signin", error: "/auth/signin" },
  callbacks: {
    async signIn({ user, account, profile }) {
      if (!emailAllowed(user.email, process.env)) return false;
      if (account?.provider === "google" || account?.provider === "okta") {
        if (profile?.email_verified !== true || normalizeEmail(profile.email) !== normalizeEmail(user.email)) return false;
      }
      if (user.id) {
        const stored = await prisma.user.findUnique({ where: { id: user.id }, select: { disabled: true } });
        if (stored?.disabled) return false;
      }
      return true;
    },
    async jwt({ token, user, account }) {
      if (user?.id) {
        const stored = await prisma.user.findUnique({ where: { id: user.id } });
        if (!stored || stored.disabled) return null;
        token.sub = stored.id; token.sessionVersion = stored.sessionVersion;
        token.authStartedAt = Date.now(); token.provider = account?.provider;
      }
      if (!token.sub || typeof token.authStartedAt !== "number" || Date.now() - token.authStartedAt > 8 * 3_600_000 || !enabledProviders.has(String(token.provider))) return null;
      const stored = await prisma.user.findUnique({ where: { id: token.sub }, select: { sessionVersion: true, disabled: true, email: true } });
      // Check durable state on every session read, including proxy authorization.
      if (!stored || stored.disabled || stored.sessionVersion !== token.sessionVersion || !emailAllowed(stored.email, process.env)) return null;
      return token;
    },
    session({ session, token }) {
      if (session.user && token?.sub) session.user.id = token.sub;
      return session;
    },
    redirect({ url, baseUrl }) {
      if (url.startsWith("/")) return baseUrl + safeAuthReturn(url);
      try { const parsed = new URL(url); return parsed.origin === new URL(baseUrl).origin ? baseUrl + safeAuthReturn(parsed.pathname + parsed.search) : baseUrl; }
      catch { return baseUrl; }
    },
  },
});
export const { handlers, auth, signIn, signOut } = result;
export { authEnabled };
