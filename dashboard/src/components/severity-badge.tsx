import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: {
    color: "bg-[var(--severity-critical-bg)] text-[var(--severity-critical)] border-[var(--severity-critical)]/20",
    label: "Critical",
  },
  high: {
    color: "bg-[var(--severity-high-bg)] text-[var(--severity-high)] border-[var(--severity-high)]/20",
    label: "High",
  },
  medium: {
    color: "bg-[var(--severity-medium-bg)] text-[var(--severity-medium)] border-[var(--severity-medium)]/20",
    label: "Medium",
  },
  low: {
    color: "bg-[var(--severity-low-bg)] text-[var(--severity-low)] border-[var(--severity-low)]/20",
    label: "Low",
  },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const config = severityConfig[severity] || severityConfig.medium;
  return (
    <Badge variant="outline" className={cn("text-xs font-medium", config.color)}>
      {config.label}
    </Badge>
  );
}
