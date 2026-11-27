export function isWranglerManifest(path: string): boolean {
  return /(?:^|[\\/])wrangler\.(?:jsonc?|toml)$/.test(path);
}

const scope = String.raw`(?:default|env\.[A-Za-z0-9_.-]{1,80}|environment at line [1-9]\d{0,8})`;
const location = String.raw`[1-9]\d{0,8}`;
const fields = {
  kv_namespaces: { label: "KV namespace", primary: "id", preview: "preview_id" },
  d1_databases: { label: "D1 database", primary: "database_id", preview: "preview_database_id" },
  r2_buckets: { label: "R2 bucket", primary: "bucket_name", preview: "preview_bucket_name" },
} as const;

const binding = new RegExp(`^${scope}(?:\\.previews)?\\.vars\\.[A-Za-z_][A-Za-z0-9_]{0,127} = \\[withheld\\]$`);
const routing = new RegExp(`^${scope}: workers_dev = false \\(line ${location}\\), preview_urls = true \\(line ${location}\\)$`);
const collection = Object.keys(fields).join("|");
const storage = new RegExp(
  `^(?<local>${scope})\\.(?<collection>${collection})\\[(?<localIndex>\\d{1,7})\\]\\.remote = true \\(line (?<remoteLine>${location})\\), ` +
  `(?<selector>[a-z_]{2,21}) \\(line (?<selectorLine>${location})\\) matches ` +
  `(?<peer>${scope})\\.\\k<collection>\\[(?<peerIndex>\\d{1,7})\\]\\.(?<primary>[a-z_]{2,12}) \\(line (?<peerLine>${location})\\)$`,
);

const previewFields = { ...fields, "queues.producers": { label: "Queue producer", primary: "queue" } } as const;
const previewCollections = Object.keys(previewFields).map((key) => key.replace(".", "\\.")).join("|");
const workerPreview = new RegExp(
  `^(?<declaration>${scope})\\.previews\\.(?<collection>${previewCollections})\\[(?<index>\\d{1,7})\\]\\.(?<primary>[a-z_]{2,12}) \\(line (?<line>${location})\\) matches ` +
  `(?<peer>${scope})\\.\\k<collection>\\[(?<peerIndex>\\d{1,7})\\]\\.\\k<primary> \\(line (?<peerLine>${location})\\)$`,
);

export type ConfigurationSetting =
  | { kind: "statement"; text: string }
  | {
    kind: "worker-preview"; text: string; label: string; collection: string; primary: string;
    declaration: string; index: string; line: string; peer: string; peerIndex: string; peerLine: string;
  }
  | {
    kind: "storage"; text: string; label: string; collection: string;
    local: string; localIndex: string; remoteLine: string; selector: string; selectorLine: string;
    peer: string; peerIndex: string; primary: string; peerLine: string;
  };

export const unavailableSettings = "Parsed settings are unavailable for this report.";

export function parseConfigurationSettings(value: unknown): ConfigurationSetting[] | null {
  if (typeof value !== "string" || !value || value.length > 20_000 || /[\r\n\u2028\u2029]/u.test(value)) return null;
  const parts = value.split(" · ");
  if (parts.length > 17) return null;
  const settings: ConfigurationSetting[] = [];
  for (const text of parts) {
    if (binding.test(text) || routing.test(text) || /^[1-9]\d{0,7} more at this line$/.test(text)) {
      settings.push({ kind: "statement", text });
      continue;
    }
    const preview = workerPreview.exec(text)?.groups;
    if (preview) {
      const { declaration, collection, index, primary, line, peer, peerIndex, peerLine } = preview;
      const field = previewFields[collection as keyof typeof previewFields];
      if (primary !== field.primary || (declaration !== "default" && declaration !== peer)) return null;
      settings.push({ kind: "worker-preview", text, label: field.label, collection, primary,
        declaration, index, line, peer, peerIndex, peerLine });
      continue;
    }
    const groups = storage.exec(text)?.groups;
    if (!groups) return null;
    const { collection, local, localIndex, remoteLine, selector, selectorLine, peer, peerIndex, primary, peerLine } = groups;
    const resource = fields[collection as keyof typeof fields];
    if (primary !== resource.primary || (selector !== resource.primary && selector !== resource.preview)) return null;
    settings.push({ kind: "storage", text, label: resource.label, collection, local, localIndex, remoteLine, selector, selectorLine, peer, peerIndex, primary, peerLine });
  }
  return settings;
}
