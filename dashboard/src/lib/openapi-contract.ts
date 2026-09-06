import { createHash } from "node:crypto";
import { JSON_SCHEMA, load } from "js-yaml";

export const SPEC_MAX_BYTES = 2 * 1024 * 1024;
export interface ContractParameter {
  name: string; location: string; required: boolean; schema: Record<string, unknown>;
}
export interface ContractOperation {
  pointer: string; method: string; path: string; resolvedPaths: string[];
  operationId: string; summary: string; tags: string[]; deprecated: boolean;
  security: { state: "required" | "optional" | "none" | "undeclared" | "unknown"; alternatives: Record<string, string[]>[] };
  parameters: ContractParameter[]; requestBody: Record<string, unknown>;
  responses: Record<string, unknown>; servers: string[];
}
export interface ApiContract {
  title: string; version: string; apiVersion: string; digest: string;
  operations: ContractOperation[]; securitySchemes: Record<string, unknown>; warnings: string[];
}
export function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
const text = (value: unknown, max = 300) => typeof value === "string" ? value.slice(0, max) : "";
const pointerPart = (value: string) => value.replace(/~/g, "~0").replace(/\//g, "~1");
const METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "trace", "query"]);

/** A bounded documentation extractor, not a complete OpenAPI/JSON Schema validator. */
export function parseApiContract(source: string): ApiContract {
  if (Buffer.byteLength(source) > SPEC_MAX_BYTES) throw new Error("Specification exceeds the 2 MiB limit.");
  if (/^\s*</.test(source)) throw new Error("This is HTML. Use the raw OpenAPI JSON/YAML URL, not the Swagger UI page.");
  let parsed: unknown;
  try { parsed = load(source, { schema: JSON_SCHEMA, json: false, maxDepth: 40, maxAliases: 0 }); }
  catch { throw new Error("Invalid JSON/YAML, duplicate keys, aliases, or excessive nesting. Upload a single bundled specification."); }
  const root = record(parsed);
  const version = text(root.openapi || root.swagger);
  if (version !== "2.0" && !/^3\.[012]\.\d+$/.test(version)) throw new Error("Supported versions: Swagger 2.0 and OpenAPI 3.0, 3.1, 3.2.");
  if (!Object.keys(record(root.info)).length || typeof record(root.info).title !== "string") throw new Error("Specification info.title is required.");
  if (!Object.hasOwn(root, "paths") || !root.paths || Array.isArray(root.paths) || typeof root.paths !== "object") throw new Error("A paths object is required. Webhook-only documents are not imported as server endpoints.");
  const warnings = new Set<string>();
  const warn = (message: string) => { if (warnings.size < 50) warnings.add(message); else warnings.add("Additional extraction warnings omitted."); };
  const resolve = (value: unknown, visited = new Set<string>()): Record<string, unknown> => {
    const item = record(value);
    if (!Object.hasOwn(item, "$ref")) return item;
    const ref = text(item.$ref, 2000);
    if (!ref.startsWith("#/")) { warn("External references were not fetched. Bundle external definitions before importing."); return {}; }
    if (visited.has(ref) || visited.size >= 12) { warn("Recursive/deep references were bounded; some schema details are incomplete."); return {}; }
    visited.add(ref);
    let target: unknown = root;
    try {
      for (const token of decodeURIComponent(ref.slice(2)).split("/")) {
        const key = token.replace(/~1/g, "/").replace(/~0/g, "~");
        if (!Object.hasOwn(record(target), key)) throw new Error();
        target = record(target)[key];
      }
    } catch { warn("Unresolved local reference: " + ref.slice(0, 150)); return {}; }
    if (Object.keys(item).some((key) => !["$ref", "summary", "description"].includes(key))) warn("Reference siblings are not merged; review the original document for schema constraints.");
    return resolve(target, visited);
  };
  let schemaNodes = 0;
  const schema = (value: unknown, depth = 0): Record<string, unknown> => {
    if (++schemaNodes > 20_000 || depth > 4) { warn("Schema previews were bounded; this is not full schema validation."); return { incomplete: true }; }
    if (typeof value === "boolean") return { allowed: value };
    const item = resolve(value);
    const result: Record<string, unknown> = {};
    for (const key of ["type", "format", "pattern"]) {
      if (typeof item[key] === "string") result[key] = text(item[key], 250);
      else if (key === "type" && Array.isArray(item.type)) result.type = item.type.filter((entry) => typeof entry === "string").slice(0, 8);
    }
    for (const key of ["minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "multipleOf", "exclusiveMinimum", "exclusiveMaximum", "nullable", "readOnly", "writeOnly"]) {
      if (typeof item[key] === "boolean" || (typeof item[key] === "number" && Number.isFinite(item[key]))) result[key] = item[key];
    }
    if (Array.isArray(item.enum)) result.enumCount = item.enum.length;
    if (Array.isArray(item.required)) result.required = item.required.filter((entry) => typeof entry === "string").slice(0, 50);
    if (item.properties) {
      const properties = Object.entries(record(item.properties));
      if (properties.length > 30) warn("Schema properties are limited to 30 per object.");
      result.properties = Object.fromEntries(properties.slice(0, 30).map(([name, value]) => [name.slice(0, 200), schema(value, depth + 1)]));
    }
    if (item.items !== undefined) result.items = schema(item.items, depth + 1);
    for (const key of ["allOf", "oneOf", "anyOf"]) if (Array.isArray(item[key])) {
      if (item[key].length > 5) warn("Schema composition previews are limited to five branches.");
      result[key] = item[key].slice(0, 5).map((entry) => schema(entry, depth + 1));
    }
    if (item.additionalProperties !== undefined) result.additionalProperties = schema(item.additionalProperties, depth + 1);
    return result;
  };
  const boundedList = (value: unknown, max: number, label: string): unknown[] => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) { warn(label + " is malformed."); return []; }
    if (value.length > max) warn(label + " was truncated to " + max + " records.");
    return value.slice(0, max);
  };
  const security = (value: unknown): ContractOperation["security"] => {
    if (value === undefined) return { state: "undeclared", alternatives: [] };
    if (!Array.isArray(value) || value.length > 20 || value.some((entry) => !entry || typeof entry !== "object" || Array.isArray(entry) || Object.values(entry).some((scopes) => !Array.isArray(scopes) || scopes.some((scope) => typeof scope !== "string")))) {
      warn("Invalid security declaration; authentication requirements could not be established."); return { state: "unknown", alternatives: [] };
    }
    const alternatives = value.map((entry) => Object.fromEntries(Object.entries(entry).map(([key, scopes]) => [key.slice(0, 200), (scopes as string[]).slice(0, 30).map((scope) => scope.slice(0, 200))])));
    return { state: !alternatives.length ? "none" : alternatives.some((entry) => !Object.keys(entry).length) ? "optional" : "required", alternatives };
  };
  const media = (value: unknown) => {
    const entries = Object.entries(record(value));
    if (entries.length > 10) warn("Media type previews are limited to ten entries.");
    return Object.fromEntries(entries.slice(0, 10).map(([type, item]) => [type.slice(0, 200), schema(record(item).schema)]));
  };
  const operations: ContractOperation[] = [];
  const seen = new Set<string>();
  for (const [path, rawPath] of Object.entries(record(root.paths))) {
    if (path.startsWith("x-")) continue;
    if (!path.startsWith("/") || path.length > 1500 || /[?#\x00-\x20]/.test(path)) { warn("An invalid or oversized path was skipped."); continue; }
    const pathItem = resolve(rawPath);
    const entries = Object.entries(pathItem).filter(([key]) => METHODS.has(key)).map(([key, value]) => [key.toUpperCase(), value, key] as const);
    if (pathItem.additionalOperations) {
      if (!version.startsWith("3.2.")) warn("additionalOperations requires OpenAPI 3.2; entries were ignored.");
      else for (const [method, value] of Object.entries(record(pathItem.additionalOperations))) {
        if (!/^[A-Z][A-Z0-9-]{0,30}$/.test(method) || METHODS.has(method.toLowerCase())) { warn("An invalid additional HTTP operation was ignored."); continue; }
        entries.push([method, value, "additionalOperations/" + pointerPart(method)]);
      }
    }
    for (const [method, rawOperation, pointer] of entries) {
      if (method === "QUERY" && !version.startsWith("3.2.")) { warn("QUERY requires OpenAPI 3.2; operation was ignored."); continue; }
      const operation = record(rawOperation);
      if (!Object.keys(operation).length) { warn("An empty/malformed operation was skipped."); continue; }
      if (operations.length >= 1000) throw new Error("Specification exceeds the 1,000 operation limit. Split it by service.");
      const key = method + ":" + path.replace(/\{[^/{}]+\}/g, "{}");
      if (seen.has(key)) throw new Error("Ambiguous duplicate operation paths: " + method + " " + path);
      seen.add(key);
      const parameterMap = new Map<string, ContractParameter>();
      for (const raw of [...boundedList(pathItem.parameters, 100, "Path parameters"), ...boundedList(operation.parameters, 100, "Operation parameters")]) {
        const parameter = resolve(raw);
        const name = text(parameter.name, 200); const location = text(parameter.in, 30);
        if (!name || !["path", "query", "querystring", "header", "cookie", "body", "formData"].includes(location)) { warn("A parameter could not be resolved or has an invalid name/location."); continue; }
        if (location === "header" && ["accept", "content-type", "authorization"].includes(name.toLowerCase())) continue;
        parameterMap.set(location + ":" + (location === "header" ? name.toLowerCase() : name), { name, location, required: parameter.required === true, schema: parameter.content ? { content: media(parameter.content) } : schema(parameter.schema ?? parameter) });
      }
      const servers: string[] = []; const bases: string[] = [];
      if (version === "2.0") {
        const base = text(root.basePath, 1500) || "/";
        if (!base.startsWith("/") || /[?#\x00-\x20]/.test(base)) throw new Error("Swagger basePath must be an absolute path.");
        bases.push(base.replace(/\/$/, ""));
      } else {
        const rawServers = operation.servers ?? pathItem.servers ?? root.servers;
        const values = boundedList(rawServers, 20, "Servers");
        if (rawServers === undefined || (Array.isArray(rawServers) && !rawServers.length)) bases.push("");
        for (const value of values) {
          const server = record(value);
          let url = text(server.url, 2000);
          url = url.replace(/\{([^{}]+)\}/g, (match, variable: string) => typeof record(record(server.variables)[variable]).default === "string" ? String(record(record(server.variables)[variable]).default) : match);
          if (!url || /[{}\x00-\x20]/.test(url) || (!url.startsWith("/") && !/^https?:\/\//.test(url)) || url.startsWith("//")) { warn("A relative/unresolved server URL was not used for endpoint matching."); continue; }
          try {
            const parsed = new URL(url, "https://spec.invalid");
            if (parsed.username || parsed.password || parsed.search || parsed.hash) { warn("A server URL containing credentials, query, or fragment was omitted."); continue; }
            servers.push(url); bases.push(parsed.pathname.replace(/\/$/, ""));
          } catch { warn("An invalid server URL was omitted."); }
        }
      }
      if (operation.callbacks || root.webhooks) warn("Callbacks and webhooks are not imported as callable server endpoints.");
      const body = resolve(operation.requestBody);
      const responseEntries = Object.entries(record(operation.responses));
      if (responseEntries.length > 20) warn("Response previews are limited to 20 statuses per operation.");
      operations.push({
        pointer: "#/paths/" + pointerPart(path) + "/" + pointer, method, path,
        resolvedPaths: [...new Set(bases.map((base) => base + path))], operationId: text(operation.operationId),
        summary: text(operation.summary), tags: boundedList(operation.tags, 20, "Tags").filter((tag) => typeof tag === "string").map((tag) => text(tag, 100)), deprecated: operation.deprecated === true,
        security: security(Object.hasOwn(operation, "security") ? operation.security : root.security),
        parameters: [...parameterMap.values()], requestBody: { required: body.required === true, content: media(body.content) },
        responses: Object.fromEntries(responseEntries.slice(0, 20).map(([status, value]) => {
          const response = resolve(value);
          return [status.slice(0, 10), version === "2.0" ? { schema: schema(response.schema) } : { content: media(response.content) }];
        })), servers,
      });
    }
  }
  const securitySchemes = Object.fromEntries(Object.entries(record(version === "2.0" ? root.securityDefinitions : record(root.components).securitySchemes)).slice(0, 40).map(([name, value]) => {
    const item = resolve(value); return [name.slice(0, 200), { type: text(item.type), scheme: text(item.scheme), in: text(item.in), name: text(item.name) }];
  }));
  const result: ApiContract = { title: text(record(root.info).title), apiVersion: text(record(root.info).version), version, digest: createHash("sha256").update(source).digest("hex"), operations, securitySchemes, warnings: [...warnings] };
  if (Buffer.byteLength(JSON.stringify(result)) > SPEC_MAX_BYTES) throw new Error("Expanded contract exceeds 2 MiB. Split it by service.");
  return result;
}

export interface ContractEndpoint { id: string; path: string; method: string; framework: string; filePath: string; lineStart: number; lineEnd: number; authRequired: boolean }
export function reconcileContract(contract: Pick<ApiContract, "operations">, endpoints: ContractEndpoint[]) {
  const source = endpoints.filter((endpoint) => endpoint.framework !== "OpenAPI" && endpoint.lineStart > 0 && endpoint.lineEnd >= endpoint.lineStart);
  const used = new Set<string>();
  const operations = contract.operations.map((operation) => {
    // Exact, case-sensitive paths only: no fuzzy operationId or template-name guesses.
    const matches = source.filter((endpoint) => endpoint.method === operation.method && operation.resolvedPaths.includes(endpoint.path));
    matches.forEach((endpoint) => used.add(endpoint.id));
    return { ...operation, matches, association: matches.length > 1 ? "ambiguous" : matches.length === 1 ? "exact_route" : "spec_only", reviewNotes: matches.some((endpoint) => operation.security.state === "required" && !endpoint.authRequired) ? ["The spec requires authentication, but the source detector recorded no auth signal. Inspect middleware and framework enforcement; this is not a confirmed vulnerability."] : [] };
  });
  return { operations, matched: operations.filter((operation) => operation.association === "exact_route").length, ambiguous: operations.filter((operation) => operation.association === "ambiguous").length, specOnly: operations.filter((operation) => operation.association === "spec_only").length, codeOnly: source.filter((endpoint) => !used.has(endpoint.id)) };
}
