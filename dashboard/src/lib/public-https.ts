import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { validateEndpointUrl } from "./url-validator.ts";

const blocked = new BlockList();
for (const [network, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]] as const) blocked.addSubnet(network, prefix, "ipv4");
const globalV6 = new BlockList(); globalV6.addSubnet("2000::", 3, "ipv6");
for (const [network, prefix] of [["2001::", 32], ["2001:db8::", 32], ["2001:2::", 48], ["2002::", 16]] as const) blocked.addSubnet(network, prefix, "ipv6");
export function publicProviderAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !blocked.check(address, "ipv4");
  return family === 6 && globalV6.check(address, "ipv6") && !blocked.check(address, "ipv6");
}
export interface ProviderHttpRequest { url: string; headers: Record<string, string>; body: string; timeoutMs: number; method?: "GET" | "POST" }
export type ProviderTransport = (input: ProviderHttpRequest) => Promise<{ status: number; text: string }>;

/** DNS results are validated and pinned into this TLS connection; no redirect or retry. */
export const publicProviderRequest: ProviderTransport = async (input) => {
  const valid = validateEndpointUrl(input.url);
  if (!valid.valid) throw new Error(valid.error);
  const url = new URL(input.url);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const signal = AbortSignal.timeout(input.timeoutMs);
  const addresses = isIP(hostname) ? [{ address: hostname, family: isIP(hostname) }] : await new Promise<Array<{ address: string; family: number }>>((resolve, reject) => {
    const abort = () => reject(new Error("Provider DNS lookup timed out."));
    signal.addEventListener("abort", abort, { once: true });
    lookup(hostname, { all: true }).then(resolve, () => reject(new Error("Provider DNS lookup failed."))).finally(() => signal.removeEventListener("abort", abort));
  });
  if (signal.aborted) throw new Error("Provider request timed out.");
  if (!addresses.length || addresses.some((item) => !publicProviderAddress(item.address))) throw new Error("Provider endpoint must resolve only to public network addresses.");
  const pinned = addresses[0];
  const pinnedLookup: LookupFunction = (_host, options, callback) => options.all ? callback(null, [pinned]) : callback(null, pinned.address, pinned.family);
  return new Promise((resolve, reject) => {
    const req = request(url, { method: input.method || "POST", headers: { ...input.headers, "Accept-Encoding": "identity" }, signal, agent: false, lookup: pinnedLookup, rejectUnauthorized: true }, (response) => {
      let bytes = 0; const chunks: Buffer[] = [];
      if ((response.statusCode || 0) >= 300 && (response.statusCode || 0) < 400) { response.destroy(); reject(new Error("Provider redirects are blocked.")); return; }
      response.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) { response.destroy(new Error("Provider response exceeds 2 MiB.")); return; }
        chunks.push(chunk);
      });
      response.on("error", () => reject(new Error("Provider response was interrupted or exceeded the size limit.")));
      response.on("end", () => resolve({ status: response.statusCode || 502, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", () => reject(new Error(signal.aborted ? "Provider request timed out. No automatic retry was made." : "Provider HTTPS connection failed.")));
    req.end(input.body);
  });
};
