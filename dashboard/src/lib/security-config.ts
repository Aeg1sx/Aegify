type Environment = Record<string, string | undefined>;

function completePair(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right);
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
    !environment.CODEGUARD_UPLOAD_TOKEN
  );
}
