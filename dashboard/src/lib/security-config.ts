import { accessPolicyConfigured, authOrigin, localAuthEnabled, mailConfigured, validOktaIssuer } from "./auth-policy.ts";

type Environment = Record<string, string | undefined>;

function completePair(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right);
}

function validAuthOrigin(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      !url.username &&
      !url.password &&
      url.pathname === "/" &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

export function dashboardAuthConfigured(environment: Environment): boolean {
  const providerConfigured =
    completePair(environment.AUTH_GITHUB_ID, environment.AUTH_GITHUB_SECRET) ||
    completePair(environment.AUTH_GITLAB_ID, environment.AUTH_GITLAB_SECRET) ||
    completePair(environment.AUTH_GOOGLE_ID, environment.AUTH_GOOGLE_SECRET) ||
    (completePair(environment.AUTH_OKTA_ID, environment.AUTH_OKTA_SECRET) && validOktaIssuer(environment.AUTH_OKTA_ISSUER)) ||
    localAuthEnabled(environment);
  return Boolean(environment.AUTH_SECRET) && providerConfigured;
}

export function productionSecurityErrors(environment: Environment): string[] {
  if (environment.NODE_ENV !== "production") return [];

  const errors: string[] = [];
  if (!environment.AUTH_SECRET) errors.push("AUTH_SECRET is required");
  else if (environment.AUTH_SECRET.length < 32) errors.push("AUTH_SECRET must contain at least 32 characters");
  if (!environment.ENCRYPTION_SECRET) {
    errors.push("ENCRYPTION_SECRET is required");
  }
  if (!dashboardAuthConfigured(environment)) {
    errors.push("at least one complete authentication method is required");
  }
  if (!environment.AUTH_URL) {
    errors.push("AUTH_URL is required");
  } else if (!validAuthOrigin(environment.AUTH_URL)) {
    errors.push("AUTH_URL must be an HTTP(S) origin without credentials or a path");
  }
  if (environment.AUTH_URL && validAuthOrigin(environment.AUTH_URL) && !authOrigin(environment)) errors.push("AUTH_URL requires HTTPS except on loopback hosts");
  if (!accessPolicyConfigured(environment)) errors.push("AUTH_ALLOWED_EMAILS or AUTH_ALLOWED_DOMAINS is required");
  if (localAuthEnabled(environment) && !mailConfigured(environment)) errors.push("local authentication requires RESEND_API_KEY and AUTH_EMAIL_FROM for verification and recovery");
  return errors;
}

export function assertProductionSecurity(environment: Environment): void {
  const errors = productionSecurityErrors(environment);
  if (errors.length > 0) {
    throw new Error(`Refusing insecure production startup: ${errors.join("; ")}`);
  }
}

export function anonymousUploadAllowed(environment: Environment): boolean {
  return (
    environment.NODE_ENV !== "production" &&
    !environment.AUTH_SECRET &&
    !environment.AEGIFY_UPLOAD_TOKEN
  );
}
