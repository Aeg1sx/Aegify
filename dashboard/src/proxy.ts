import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export default auth((req) => {
  const { pathname } = req.nextUrl;

  // CI uploads use a dedicated bearer token. Let bearer requests reach the
  // route handler, which performs a timing-safe token verification.
  if (
    pathname === "/api/upload" &&
    process.env.CODEGUARD_UPLOAD_TOKEN &&
    req.headers.get("authorization")?.startsWith("Bearer ")
  ) {
    return NextResponse.next();
  }

  // Allow auth routes, API auth routes, and static assets
  if (
    pathname.startsWith("/auth") ||
    pathname.startsWith("/api/auth") ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon")
  ) {
    return NextResponse.next();
  }

  // If AUTH_SECRET is not configured, skip auth (development mode)
  if (!process.env.AUTH_SECRET) {
    return NextResponse.next();
  }

  // If not authenticated, redirect to sign in
  if (!req.auth) {
    const signInUrl = new URL("/auth/signin", req.nextUrl.origin);
    signInUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(signInUrl);
  }

  return NextResponse.next();
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
