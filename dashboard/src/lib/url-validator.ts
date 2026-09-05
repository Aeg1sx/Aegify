/**
 * SSRF-safe URL validation for user-configured endpoints.
 * Blocks internal/private network addresses to prevent Server-Side Request Forgery.
 */

const BLOCKED_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
  "metadata.google.internal",
  "169.254.169.254", // AWS/GCP metadata
  "metadata.internal",
]);

// Private IP ranges (RFC 1918, RFC 6598, link-local, loopback)
const PRIVATE_RANGES = [
  { start: 0x0a000000, end: 0x0affffff }, // 10.0.0.0/8
  { start: 0xac100000, end: 0xac1fffff }, // 172.16.0.0/12
  { start: 0xc0a80000, end: 0xc0a8ffff }, // 192.168.0.0/16
  { start: 0x7f000000, end: 0x7fffffff }, // 127.0.0.0/8
  { start: 0xa9fe0000, end: 0xa9feffff }, // 169.254.0.0/16
  { start: 0x64400000, end: 0x647fffff }, // 100.64.0.0/10 (CGN)
  { start: 0x00000000, end: 0x00ffffff }, // 0.0.0.0/8
];

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

function isPrivateIP(ip: string): boolean {
  const num = ipToInt(ip);
  if (num === null) return false;
  return PRIVATE_RANGES.some((r) => num >= r.start && num <= r.end);
}

export interface UrlValidationResult {
  valid: boolean;
  error?: string;
}

export function validateEndpointUrl(url: string): UrlValidationResult {
  if (!url || !url.trim()) {
    return { valid: false, error: "URL is required" };
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // Must be HTTPS (allow HTTP only for localhost in dev, but we block localhost anyway)
  if (parsed.protocol !== "https:") {
    return { valid: false, error: "Only HTTPS URLs are allowed" };
  }

  // Block known internal hostnames
  const hostname = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(hostname)) {
    return { valid: false, error: "Internal/loopback addresses are not allowed" };
  }

  // Block private IPs
  if (isPrivateIP(hostname)) {
    return { valid: false, error: "Private network addresses are not allowed" };
  }

  // Block IPv6 private/link-local (fe80::, fc00::, fd00::)
  if (hostname.startsWith("[")) {
    const ipv6 = hostname.slice(1, -1).toLowerCase();
    if (
      ipv6.startsWith("fe80:") ||
      ipv6.startsWith("fc00:") ||
      ipv6.startsWith("fd00:") ||
      ipv6 === "::1"
    ) {
      return { valid: false, error: "Private IPv6 addresses are not allowed" };
    }
  }

  // Block hostnames that resolve to common internal patterns
  if (
    hostname.endsWith(".internal") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".localhost")
  ) {
    return { valid: false, error: "Internal domain names are not allowed" };
  }

  // Block credentials in URL
  if (parsed.username || parsed.password) {
    return { valid: false, error: "URLs with embedded credentials are not allowed" };
  }

  return { valid: true };
}

export function validateSlackWebhookUrl(url: string): UrlValidationResult {
  const common = validateEndpointUrl(url);
  if (!common.valid) return common;
  const parsed = new URL(url);
  if (parsed.hostname.toLowerCase() !== "hooks.slack.com") {
    return { valid: false, error: "Slack webhook host must be hooks.slack.com" };
  }
  if (!/^\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(parsed.pathname)) {
    return { valid: false, error: "Invalid Slack webhook path" };
  }
  if (parsed.search || parsed.hash) {
    return { valid: false, error: "Slack webhook URL cannot contain query or fragment" };
  }
  return { valid: true };
}

export function validateJiraBaseUrl(url: string): UrlValidationResult {
  const common = validateEndpointUrl(url);
  if (!common.valid) return common;
  const parsed = new URL(url);
  if (parsed.search || parsed.hash) {
    return { valid: false, error: "Jira base URL cannot contain query or fragment" };
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    return { valid: false, error: "Jira base URL must not include an API path" };
  }
  const hostname = parsed.hostname.toLowerCase();
  const configuredHosts = (process.env.AEGIFY_JIRA_ALLOWED_HOSTS || "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  if (!hostname.endsWith(".atlassian.net") && !configuredHosts.includes(hostname)) {
    return {
      valid: false,
      error: "Jira host must be Atlassian Cloud or listed in AEGIFY_JIRA_ALLOWED_HOSTS",
    };
  }
  return { valid: true };
}

/**
 * Validate custom headers - block dangerous headers that could
 * be used for request smuggling or abuse.
 */
const BLOCKED_HEADERS = new Set([
  "host",
  "transfer-encoding",
  "content-length",
  "connection",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "cookie",
  "set-cookie",
]);

export function validateCustomHeaders(
  headers: Record<string, string>
): UrlValidationResult {
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase().trim();

    if (!lowerKey) {
      return { valid: false, error: "Header name cannot be empty" };
    }

    if (BLOCKED_HEADERS.has(lowerKey)) {
      return {
        valid: false,
        error: `Header '${key}' is not allowed (security restriction)`,
      };
    }

    // Block header injection via newlines
    if (/[\r\n]/.test(key) || /[\r\n]/.test(value)) {
      return {
        valid: false,
        error: "Header names and values cannot contain newlines",
      };
    }

    // Reasonable length limits
    if (key.length > 256) {
      return { valid: false, error: `Header name '${key.slice(0, 50)}...' is too long` };
    }
    if (value.length > 8192) {
      return { valid: false, error: `Header value for '${key}' is too long` };
    }
  }

  return { valid: true };
}
