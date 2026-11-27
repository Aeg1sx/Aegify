import { lineRange } from "@/lib/code-evidence";
import { parseConfigurationSettings, unavailableSettings, type ConfigurationSetting } from "@/lib/configuration-evidence";

function PreviewComparison({ setting }: {
  setting: Extract<ConfigurationSetting, { kind: "worker-preview" }>;
}) {
  const rows = [
    { title: "Worker Preview", scope: setting.declaration + ".previews", index: setting.index, line: setting.line },
    { title: "Worker deployment", scope: setting.peer, index: setting.peerIndex, line: setting.peerLine },
  ];
  return <div className="@container">
    <p className="mb-2 font-semibold text-sm">{setting.label}</p>
    <dl className="divide-y divide-border border-y border-border">
      {rows.map((row) => <div key={row.title} className="grid grid-cols-[minmax(0,1fr)_auto] items-baseline gap-x-3 gap-y-1 py-2.5 @min-[29rem]:grid-cols-[8.5rem_minmax(0,1fr)_auto]">
        <dt className="col-span-2 font-medium text-sm @min-[29rem]:col-span-1">{row.title}</dt>
        <dd className="min-w-0">
          <code className="block text-xs leading-5 text-muted-foreground">{row.scope}</code>
          <code className="block text-xs leading-5">{setting.collection}[{row.index}].{setting.primary}</code>
        </dd>
        <dd className="whitespace-nowrap font-mono text-xs text-muted-foreground tabular-nums">Line {row.line}</dd>
      </div>)}
    </dl>
    {setting.declaration !== setting.peer && <p className="mt-2 text-xs leading-5 text-muted-foreground">
      <code>{setting.peer}</code> inherits the top-level <code>previews</code> block.
    </p>}
  </div>;
}

export function ConfigurationEvidence({ finding }: {
  finding: { filePath: string; lineStart: number; lineEnd: number; codeSnippet: string };
}) {
  const settings = parseConfigurationSettings(finding.codeSnippet);
  return <div className="overflow-hidden rounded-md border border-border">
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b bg-muted/40 px-4 py-3">
      <span className="break-all font-mono text-xs">{finding.filePath}</span>
      <span className="text-xs text-muted-foreground">Line {lineRange(finding.lineStart, finding.lineEnd)}</span>
    </div>
    {settings ? <ul className="divide-y divide-border" aria-label="Parsed settings">
      {settings.map((setting, index) =>
        <li key={index} className="min-w-0 px-4 py-3 [overflow-wrap:anywhere]">
          {setting.kind === "statement"
            ? <code className="text-sm">{setting.text}</code>
            : setting.kind === "worker-preview" ? <PreviewComparison setting={setting} />
            : <div className="@container py-1">
              <p className="mb-3 text-sm font-semibold">{setting.label}</p>
              <dl className="grid gap-4 @min-[32rem]:grid-cols-2">
                <div className="border-l-2 border-primary pl-3">
                  <dt className="text-xs font-medium text-muted-foreground">Local development</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold">{setting.local}</dd>
                  <dd className="mt-2 text-xs leading-5"><code>{setting.collection}[{setting.localIndex}].{setting.selector}</code> · line {setting.selectorLine}</dd>
                  <dd className="text-xs leading-5 text-muted-foreground"><code>remote = true</code> · line {setting.remoteLine}</dd>
                </div>
                <div className="border-l-2 border-input pl-3">
                  <dt className="text-xs font-medium text-muted-foreground">Matching deployment</dt>
                  <dd className="mt-1 font-mono text-sm font-semibold">{setting.peer}</dd>
                  <dd className="mt-2 text-xs leading-5"><code>{setting.collection}[{setting.peerIndex}].{setting.primary}</code> · line {setting.peerLine}</dd>
                </div>
              </dl>
            </div>}
        </li>)}
    </ul> : <p className="px-4 py-3 text-sm text-muted-foreground">{unavailableSettings}</p>}
  </div>;
}
