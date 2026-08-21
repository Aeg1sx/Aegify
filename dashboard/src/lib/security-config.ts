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
    completePair(environment.AUTH_GITLAB_ID, environment.AUTH_GITLAB_SECRET);
  return Boolean(environment.AUTH_SECRET) && providerConfigured;
}

export function productionSecurityErrors(environment: Environment): string[] {
  if (environment.NODE_ENV !== "production") return [];

  const errors: string[] = [];
  if (!environment.AUTH_SECRET) errors.push("AUTH_SECRET is required");
  if (!environment.ENCRYPTION_SECRET) {
    errors.push("ENCRYPTION_SECRET is required");
  }
  if (!dashboardAuthConfigured(environment)) {
    errors.push("a complete GitHub or GitLab OAuth provider is required");
  }
  if (!environment.AUTH_URL) {
    errors.push("AUTH_URL is required");
  } else if (!validAuthOrigin(environment.AUTH_URL)) {
    errors.push("AUTH_URL must be an HTTP(S) origin without credentials or a path");
  }
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
