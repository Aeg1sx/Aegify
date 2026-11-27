import Link from "next/link";

const bands: Record<string, string> = {
  critical: "var(--severity-critical)",
  high: "var(--severity-high)",
  medium: "var(--severity-medium)",
  low: "var(--severity-low)",
};

interface SeverityChartProps {
  severities: Record<string, number>;
  projectId?: string;
  selectedLevel?: string;
  onSelect?: (level: string) => void;
}

export function SeverityChart({ severities, projectId, selectedLevel, onSelect }: SeverityChartProps) {
  const levels = [...new Set([...Object.keys(bands), ...Object.keys(severities)])];
  const total = Object.values(severities).reduce((sum, count) => sum + count, 0);
  return (
    <div className={onSelect ? "p-5" : undefined}>
      <div className="flex items-baseline gap-2">
        <strong className="font-mono text-3xl font-medium tabular-nums">{total.toLocaleString()}</strong>
        {!projectId && <span className="text-sm text-muted-foreground">
          {onSelect ? "in this scan" : "current findings"}
        </span>}
      </div>
      <div aria-hidden className="my-4 flex h-3 gap-0.5 overflow-hidden rounded-sm bg-muted">
        {levels
          .filter((level) => severities[level] > 0)
          .map((level) => (
            <span
              key={level}
              style={{ flex: severities[level], backgroundColor: bands[level] || "var(--muted-foreground)" }}
            />
          ))}
      </div>
      <ul className="divide-y">
        {levels.map((level) => {
          const count = severities[level] || 0;
          const contents = (
            <>
              <span className="inline-flex items-center gap-2.5 capitalize">
                <span
                  aria-hidden
                  className="size-2 rounded-sm"
                  style={{ backgroundColor: bands[level] || "var(--muted-foreground)" }}
                />
                {level}
              </span>
              <span className="font-mono tabular-nums">{count.toLocaleString()}</span>
            </>
          );
          const row = "flex min-h-11 w-full items-center justify-between gap-2 text-sm hover:text-primary";
          return (
            <li key={level}>
              {onSelect ? (
                <button
                  type="button"
                  aria-pressed={selectedLevel === level}
                  onClick={() => onSelect(selectedLevel === level ? "" : level)}
                  className={row + " aria-pressed:font-semibold aria-pressed:text-primary"}
                >
                  {contents}
                </button>
              ) : (
                <Link href={"/findings?severity=" + encodeURIComponent(level) + (projectId ? "&projectId=" + encodeURIComponent(projectId) : "")} className={row}>
                  {contents}
                </Link>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
