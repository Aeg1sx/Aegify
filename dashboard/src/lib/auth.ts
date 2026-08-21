import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import GitLab from "next-auth/providers/gitlab";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "@/lib/prisma";
import {
  assertProductionSecurity,
  dashboardAuthConfigured,
} from "@/lib/security-config";

assertProductionSecurity(process.env);
const authEnabled = dashboardAuthConfigured(process.env);

const providers = [];
if (process.env.AUTH_GITHUB_ID && process.env.AUTH_GITHUB_SECRET) {
  providers.push(
    GitHub({
      clientId: process.env.AUTH_GITHUB_ID,
      clientSecret: process.env.AUTH_GITHUB_SECRET,
      authorization: {
        params: { scope: "read:user user:email repo" },
      },
    }),
  );
}
if (process.env.AUTH_GITLAB_ID && process.env.AUTH_GITLAB_SECRET) {
  providers.push(
    GitLab({
      clientId: process.env.AUTH_GITLAB_ID,
      clientSecret: process.env.AUTH_GITLAB_SECRET,
      authorization: {
        params: { scope: "read_user read_repository api" },
      },
    }),
  );
}

const result = NextAuth({
  // Only use PrismaAdapter when auth is properly configured
  ...(authEnabled ? { adapter: PrismaAdapter(prisma) } : {}),
  providers,
  secret: process.env.AUTH_SECRET || "dev-secret-not-for-production",
  pages: {
    signIn: "/auth/signin",
  },
  callbacks: {
    session({ session, user, token }) {
      if (session.user && user) {
        session.user.id = user.id;
      } else if (session.user && token?.sub) {
        session.user.id = token.sub;
      }
      return session;
    },
  },
});

export const { handlers, auth, signIn, signOut } = result;
export { authEnabled };
