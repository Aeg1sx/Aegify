import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

function privateResponse() {
  const response = NextResponse.next();
  response.headers.set("Cache-Control", "private, no-store");
  return response;
}

export default auth((req) => {
  const { pathname } = req.nextUrl;

  // CI uploads use a dedicated bearer token. Let bearer requests reach the
  // route handler, which performs a timing-safe token verification.
  if (
    pathname === "/api/upload" &&
    (req.headers.has("authorization") || req.headers.has("x-aegify-token"))
  ) {
    return privateResponse();
  }

  // Allow auth routes, API auth routes, and static assets
  if (
    pathname === "/auth" || pathname.startsWith("/auth/") ||
    pathname === "/api/auth" || pathname.startsWith("/api/auth/") ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon")
  ) {
    return NextResponse.next();
  }

  // If AUTH_SECRET is not configured, skip auth (development mode)
  if (!process.env.AUTH_SECRET) {
    return privateResponse();
  }

  // If not authenticated, redirect to sign in
  if (!req.auth) {
    if (pathname.startsWith("/api/")) return NextResponse.json({ error: "Authentication required." }, { status: 401, headers: { "Cache-Control": "no-store" } });
    const signInUrl = new URL("/auth/signin", req.nextUrl.origin);
    signInUrl.searchParams.set("callbackUrl", pathname + req.nextUrl.search);
    return NextResponse.redirect(signInUrl);
  }

  return privateResponse();
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
