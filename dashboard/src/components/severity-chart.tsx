"use client";
import Link from "next/link";
import { SeverityBadge } from "@/components/severity-badge";

export function SeverityChart({ severities }: { severities: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low"];
  const maximum = Math.max(1, ...order.map((s) => severities[s] || 0));
  const total = Object.values(severities).reduce((sum, n) => sum + n, 0);
  return <div className="space-y-5" aria-label="Severity distribution">
    {order.map((severity) => {
      const count = severities[severity] || 0;
      return <Link key={severity} href={"/findings?severity=" + severity} className="group grid grid-cols-[70px_1fr_42px] items-center gap-3" aria-label={severity + ": " + count + " findings"}>
        <SeverityBadge severity={severity} /><span className="h-2 overflow-hidden rounded-sm bg-muted"><span className="block h-full rounded-sm transition-[width] group-hover:opacity-70" style={{ width: (count / maximum * 100) + "%", background: "var(--severity-" + severity + ")" }} /></span><span className="text-right font-mono text-sm tabular-nums">{count}</span>
      </Link>;
    })}
    <p className="border-t border-border pt-3 text-xs text-muted-foreground">{total.toLocaleString()} current occurrences · select a severity to investigate</p>
  </div>;
}
